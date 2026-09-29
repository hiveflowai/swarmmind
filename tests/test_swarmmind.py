import json

import pytest

from swarmauth import AuditLog, KeyPair, RevocationList, RevocationSet, issue, verify_log
from swarmmind.envelope import EnvelopeError, open_envelope, seal
from swarmmind.flower import SwarmGrid, parse_prompt

NOW = 1_790_000_000


class FakeGrid:
    """Mimics Flower's RuntimeAgentGrid.call contract (function_call -> function_call_output)."""

    def __init__(self):
        self.outbox = []
        self.replies = []

    def call(self, item):
        args = item["arguments"]
        if item["name"] == "get_nodes":
            out = {"nodes": [{"id": "11", "name": "mission", "location": "37.76,-122.42"}], "num_available": 1}
        elif item["name"] == "push_messages":
            self.outbox.extend(args["messages"])
            out = {"results": [{"message_id": f"m{i}", "error": None} for i, _ in enumerate(args["messages"])]}
        elif item["name"] == "pull_messages":
            out = {"messages": self.replies, "pending_message_ids": []}
        elif item["name"] == "push_reply_message":
            self.outbox.append(args)
            out = {"message_id": "r1", "error": None}
        return {"type": "function_call_output", "call_id": item["call_id"], "output": json.dumps(out)}


@pytest.fixture
def setup():
    officer = KeyPair.from_seed("federation-officer")
    coord = KeyPair.from_seed("coordinator")
    m = issue(officer, coord.public.x, ["swarm:*"], ttl=3600, now=NOW)
    return officer, coord, m


def test_seal_and_open(setup):
    officer, coord, m = setup
    env = seal(coord, "assign", {"task": "evaluate offer"}, [m], ts=NOW)
    op = open_envelope(env.to_json(), {officer.kid}, now=NOW)
    assert op.grant.agent_kid == coord.kid and op.env.body["task"] == "evaluate offer"


@pytest.mark.parametrize("attack,code", [
    ("tamper", "BAD_SIGNATURE"), ("no_mandate", "EMPTY_CHAIN"), ("stolen_mandate", "NOT_HOLDER"),
    ("stale", "STALE"), ("replay", "REPLAY"), ("scope", "TYPE_NOT_IN_MANDATE"), ("revoked", "REVOKED"),
])
def test_rejections(setup, attack, code):
    officer, coord, m = setup
    imp = KeyPair.from_seed("impostor")
    trusted, kw = {officer.kid}, dict(now=NOW)
    env = seal(coord, "assign", {"task": "x"}, [m], ts=NOW)
    raw = env.to_json()
    if attack == "tamper":
        d = json.loads(raw); d["body"]["task"] = "pay 9000 to acct-666"; raw = json.dumps(d)
    elif attack == "no_mandate":
        raw = seal(imp, "assign", {"task": "x"}, [], ts=NOW).to_json()
    elif attack == "stolen_mandate":
        raw = seal(imp, "assign", {"task": "x"}, [m], ts=NOW).to_json()
    elif attack == "stale":
        kw["now"] = NOW + 3000
    elif attack == "replay":
        seen = set(); open_envelope(raw, trusted, seen=seen, **kw); kw["seen"] = seen
    elif attack == "scope":
        narrow = issue(officer, coord.public.x, ["swarm:status"], ttl=60, now=NOW)
        raw = seal(coord, "assign", {"task": "x"}, [narrow], ts=NOW).to_json()
    elif attack == "revoked":
        rl = RevocationList(issuer=officer.public.x); rl.revoke(officer, coord.kid, now=NOW)
        kw["is_revoked"] = RevocationSet([rl])
    with pytest.raises(EnvelopeError) as e:
        open_envelope(raw, trusted, **kw)
    assert e.value.code == code


def test_flower_adapter_roundtrip(tmp_path, setup, monkeypatch):
    officer, coord, m = setup
    node = KeyPair.from_seed("node-mission")
    node_m = issue(officer, node.public.x, ["swarm:propose", "swarm:status"], ttl=3600, now=NOW)
    import swarmmind.envelope as envmod
    monkeypatch.setattr(envmod.time, "time", lambda: NOW)

    grid = FakeGrid()
    link = SwarmGrid(grid, coord, AuditLog(tmp_path / "link.jsonl", coord), {officer.kid}, "coordinator")
    assert link.nodes()[0]["name"] == "mission"
    ids = link.send([("11", seal(coord, "assign", {"task": "t"}, [m], ts=NOW, round=1))])
    assert ids == ["m0"]

    # SuperNode side receives the prompt Flower builds and replies
    prompt = json.dumps({"message_id": "m0", "src_node_id": "1", "payload": grid.outbox[0]["payload"]})
    mid, src, payload = parse_prompt(prompt)
    sn = SwarmGrid(grid, node, AuditLog(tmp_path / "node.jsonl", node), {officer.kid}, "mission")
    inc = sn.verify(payload, mid, src)
    assert inc.opened and inc.opened.env.round == 1
    sn.reply(seal(node, "propose", {"answer": 42}, [node_m], ts=NOW, reply_to=inc.opened.env.id))

    grid.replies = [{"message_id": "r1", "reply_to_message_id": "m0", "src_node_id": "11",
                     "payload": grid.outbox[-1]["payload"], "error": None},
                    {"message_id": "r2", "reply_to_message_id": "m0", "src_node_id": "12",
                     "payload": seal(KeyPair.from_seed("x"), "propose", {}, [], ts=NOW).to_json(), "error": None}]
    replies, pending = link.collect(ids, timeout=1)
    assert replies[0].opened.env.body == {"answer": 42}
    assert replies[1].error.code == "EMPTY_CHAIN"
    assert verify_log(tmp_path / "link.jsonl").ok and verify_log(tmp_path / "node.jsonl").ok
