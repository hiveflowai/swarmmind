"""SwarmMind v0.1 envelope: signed messages between agents.

Every message carries who sent it (public key), the mandate chain that
authorises the sender, and a signature over the canonical envelope. The
receiver verifies all of it in code *before* any model sees the body.
See SPEC.md for the message semantics.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from swarmauth.canonical import canonical_bytes
from swarmauth.keys import KeyPair, kid_for, verify
from swarmauth.mandate import Grant, Mandate, MandateError, verify_chain

VERSION = "swarmmind/0.1"

TYPES = (
    "discover",      # who is out there and what can you do
    "assign",        # delegate a task (carries the sub-mandate for it)
    "propose",       # a candidate answer or action
    "object",        # disagree with a proposal, with a reason
    "evidence",      # support/refute a proposal (derived facts only, never raw data)
    "vote",          # accept/reject a proposal
    "commit",        # final, human-approved outcome
    "status",        # progress / heartbeat
    "pattern_share", # signed threat pattern ("vaccine")
    "revoke",        # signed revocation list update
)

# Scope a sender must hold to emit each message type.
REQUIRED_SCOPE = {
    "discover": "swarm:discover",
    "assign": "swarm:assign",
    "propose": "swarm:propose",
    "object": "swarm:propose",
    "evidence": "swarm:propose",
    "vote": "swarm:vote",
    "commit": "swarm:commit",
    "status": "swarm:status",
    "pattern_share": "swarm:share",
    "revoke": "swarm:revoke",
}


class EnvelopeError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class Envelope:
    type: str
    sender: str  # public key
    body: dict[str, Any]
    to: Optional[str] = None  # kid of the recipient, or None for broadcast
    round: int = 0
    reply_to: Optional[str] = None
    mandate: list[dict[str, Any]] = field(default_factory=list)  # root -> leaf
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: int = field(default_factory=lambda: int(time.time()))
    v: str = VERSION
    sig: Optional[str] = None

    def signed_part(self) -> dict[str, Any]:
        return {
            "v": self.v, "id": self.id, "type": self.type, "sender": self.sender, "to": self.to,
            "round": self.round, "reply_to": self.reply_to, "ts": self.ts, "body": self.body,
            "mandate": self.mandate,
        }

    def to_json(self) -> str:
        return json.dumps({**self.signed_part(), "sig": self.sig}, ensure_ascii=False,
                          separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "Envelope":
        try:
            d = json.loads(text)
            return cls(type=d["type"], sender=d["sender"], body=d["body"], to=d.get("to"),
                       round=d.get("round", 0), reply_to=d.get("reply_to"),
                       mandate=d.get("mandate") or [], id=d["id"], ts=d["ts"], v=d["v"],
                       sig=d.get("sig"))
        except (ValueError, KeyError, TypeError) as err:
            raise EnvelopeError("MALFORMED", str(err)) from err

    @property
    def sender_kid(self) -> str:
        return kid_for(self.sender)


def seal(signer: KeyPair, type: str, body: dict[str, Any], mandate: Iterable[Mandate | dict] = (),
         **kw: Any) -> Envelope:
    if type not in TYPES:
        raise EnvelopeError("UNKNOWN_TYPE", type)
    env = Envelope(type=type, sender=signer.public.x, body=body,
                   mandate=[m.to_dict() if isinstance(m, Mandate) else m for m in mandate], **kw)
    env.sig = signer.sign(canonical_bytes(env.signed_part()))
    return env


@dataclass
class Opened:
    env: Envelope
    grant: Grant


def open_envelope(
    raw: str | Envelope,
    trusted_roots: Iterable[str],
    now: Optional[int] = None,
    is_revoked: Optional[Callable[[str], bool]] = None,
    max_age: int = 600,
    seen: Optional[set[str]] = None,
) -> Opened:
    """Verify signature, freshness, replay, mandate chain and type scope."""
    env = raw if isinstance(raw, Envelope) else Envelope.from_json(raw)
    now = int(time.time()) if now is None else now
    if env.v != VERSION:
        raise EnvelopeError("BAD_VERSION", env.v)
    if env.type not in TYPES:
        raise EnvelopeError("UNKNOWN_TYPE", env.type)
    if not env.sig or not verify(env.sender, env.sig, canonical_bytes(env.signed_part())):
        raise EnvelopeError("BAD_SIGNATURE", "envelope signature invalid")
    if abs(now - env.ts) > max_age:
        raise EnvelopeError("STALE", f"envelope ts {env.ts} too far from {now}")
    if seen is not None:
        if env.id in seen:
            raise EnvelopeError("REPLAY", env.id)
        seen.add(env.id)
    try:
        grant = verify_chain(env.mandate, trusted_roots, now=now, is_revoked=is_revoked,
                             presenter=env.sender)
    except MandateError as err:
        raise EnvelopeError(err.code, str(err)) from err
    if not grant.allows(REQUIRED_SCOPE[env.type]):
        raise EnvelopeError("TYPE_NOT_IN_MANDATE", f"{env.type} needs {REQUIRED_SCOPE[env.type]}")
    return Opened(env, grant)
