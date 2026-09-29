"""Flower adapter: SwarmMind envelopes over Flower Agent Grid tools.

Flower 1.39 AgentApps exchange plain string payloads through Grid tools
(``get_nodes``/``push_messages``/``pull_messages`` on the SuperLink,
``push_reply_message`` on SuperNodes). This adapter calls those tools from
code — not from the model — so every message is sealed, verified and audited
deterministically:

    outgoing:  seal(envelope)  -> push      -> audit "sent"
    incoming:  pull/prompt     -> open(...) -> audit "received" | "rejected"
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from swarmauth.audit import AuditLog
from swarmauth.keys import KeyPair

from .envelope import Envelope, EnvelopeError, Opened, open_envelope


def _call(grid: Any, name: str, **arguments: Any) -> dict[str, Any]:
    item = grid.call({"type": "function_call", "name": name,
                      "call_id": f"swarm-{uuid.uuid4().hex[:12]}", "arguments": arguments})
    return json.loads(item["output"])


@dataclass
class Incoming:
    message_id: Optional[str]
    src_node_id: Optional[str]
    opened: Optional[Opened] = None
    error: Optional[EnvelopeError] = None
    raw: Optional[str] = None


def parse_prompt(prompt: str) -> tuple[Optional[str], Optional[str], str]:
    """Split a SuperNode AgentApp prompt into (message_id, src_node_id, payload)."""
    try:
        d = json.loads(prompt)
        if isinstance(d, dict) and "payload" in d and "src_node_id" in d:
            return d.get("message_id"), d.get("src_node_id"), d["payload"]
    except ValueError:
        pass
    return None, None, prompt


class SwarmGrid:
    def __init__(
        self,
        grid: Any,
        key: KeyPair,
        audit: AuditLog,
        trusted_roots: Iterable[str],
        actor: str,
        is_revoked: Optional[Callable[[str], bool]] = None,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        self.grid = grid
        self.key = key
        self.audit = audit
        self.trusted_roots = set(trusted_roots)
        self.actor = actor
        self.is_revoked = is_revoked
        self.seen: set[str] = set()
        self.clock = clock or (lambda: int(time.time()))

    # -- SuperLink side ---------------------------------------------------------
    def nodes(self) -> list[dict[str, Any]]:
        return _call(self.grid, "get_nodes", sample_size=None)["nodes"]

    def send(self, messages: list[tuple[str, Envelope]]) -> list[Optional[str]]:
        """Push sealed envelopes; returns accepted Flower message ids (None if rejected)."""
        out = _call(self.grid, "push_messages", messages=[
            {"dst_node_id": dst, "payload": env.to_json(), "reply_to_message_id": None}
            for dst, env in messages
        ])["results"]
        for (dst, env), res in zip(messages, out):
            self.audit.append("sent", self.actor, {
                "env_id": env.id, "type": env.type, "dst_node": dst, "round": env.round,
                "flwr_message_id": res["message_id"], "error": res["error"]})
        return [r["message_id"] for r in out]

    def collect(self, message_ids: list[str], timeout: float) -> tuple[list[Incoming], list[str]]:
        """Pull replies and verify each one. Returns (replies, pending ids)."""
        ids = [m for m in message_ids if m]
        if not ids:
            return [], []
        out = _call(self.grid, "pull_messages", message_ids=ids, timeout=min(timeout, 300))
        replies = [self.verify(m.get("payload"), m["message_id"], m["src_node_id"], m.get("error"))
                   for m in out["messages"]]
        return replies, out["pending_message_ids"]

    # -- SuperNode side ------------------------------------------------------------
    def reply(self, env: Envelope) -> Optional[str]:
        res = _call(self.grid, "push_reply_message", payload=env.to_json())
        self.audit.append("sent", self.actor, {"env_id": env.id, "type": env.type,
                                               "round": env.round, "reply": True,
                                               "flwr_message_id": res["message_id"],
                                               "error": res["error"]})
        return res["message_id"]

    # -- both ----------------------------------------------------------------------
    def verify(self, payload: Optional[str], message_id: Optional[str] = None,
               src_node_id: Optional[str] = None, transport_error: Optional[str] = None) -> Incoming:
        if transport_error or payload is None:
            err = EnvelopeError("TRANSPORT", transport_error or "empty payload")
            self.audit.append("rejected", self.actor, {"src_node": src_node_id, "code": err.code})
            return Incoming(message_id, src_node_id, error=err)
        try:
            opened = open_envelope(payload, self.trusted_roots, now=self.clock(),
                                   is_revoked=self.is_revoked, seen=self.seen)
        except EnvelopeError as err:
            self.audit.append("rejected", self.actor, {"src_node": src_node_id, "code": err.code,
                                                       "detail": str(err)[:200]})
            return Incoming(message_id, src_node_id, error=err, raw=payload)
        self.audit.append("received", self.actor, {
            "env_id": opened.env.id, "type": opened.env.type, "src_node": src_node_id,
            "sender": opened.env.sender_kid, "root": opened.grant.root_kid,
            "round": opened.env.round})
        return Incoming(message_id, src_node_id, opened=opened)
