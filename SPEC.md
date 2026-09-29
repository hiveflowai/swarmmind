# SwarmMind v0.1 + SwarmAuth v0.1 — Specification (draft)

Status: draft for the Flower Collaborative Agent Hackathon (Stanford, 2026-09-29).
License: CC BY 4.0 (this document). Reference code: Apache-2.0.

**SwarmMind** is the *context* layer: how agents that belong to different
people and institutions exchange tasks, proposals and evidence.
**SwarmAuth** is the *access + control* layer: who an agent is, on whose
behalf it acts, what it may do, when a human must approve, and a record that
proves it afterwards.

Design rules:

1. **Verification is code, not a model.** Signatures, mandates, scopes and
   policy are checked deterministically before any LLM sees a message and
   before any action runs. Models *propose*; code *decides*.
2. **Delegation only narrows.** Each hop can reduce — never widen — scopes,
   limits, payees, purpose and lifetime.
3. **Data stays home.** Messages carry judgements and derived facts, never
   raw records. Threat knowledge is shared as *patterns*, not data.
4. **Humans commit.** Anything that commits a principal (a write, a payment,
   a policy change) requires a signed human decision.
5. **Everything is replayable.** Each node keeps a hash-chained, signed log.

## 1. Primitives

| Primitive | Encoding |
|---|---|
| Key | Ed25519. Public key as base64url (no padding) of the 32 raw bytes |
| `kid` | RFC 7638 JWK thumbprint of `{"crv":"Ed25519","kty":"OKP","x":<pub>}`, base64url SHA-256 |
| Canonical JSON | Sorted keys, no whitespace, UTF-8. Only objects, arrays, strings, integers (|n| < 2^53), booleans, null. **No floats** — amounts are integer minor units |
| Signature | Ed25519 over the canonical bytes of the object without its `sig` field |

## 2. SwarmAuth

### 2.1 Mandate

```json
{
  "v": "swarmauth/0.1",
  "id": "<hex>",
  "iss": "<delegator public key>",
  "sub": "<delegate public key>",
  "scopes": ["offers:read", "offers:reply", "payments.transfer:write"],
  "constraints": {"max_amount": 50000, "payees": ["bank-sf"], "approval_over": 10000},
  "purpose": "personal-finance",
  "nbf": 1790000000,
  "exp": 1790003600,
  "parent": null,
  "sig": "<Ed25519 by iss>"
}
```

**Scopes** are `resource:action`. `resource` is dot-separated; `*` or a
trailing `.*` are the only wildcards. `action` is a token or `*`.
`payments.*:write` covers `payments.transfer:write`; the reverse is false.

**Chain.** A holder presents `[root, …, leaf]`. A verifier checks, for each
mandate: signature; not revoked (id, iss kid or sub kid); `nbf - skew ≤ now <
exp + skew` (skew 30 s); the root `iss` is a principal the verifier trusts and
has `parent = null`; each next mandate has `parent = prev.id`, `iss = prev.sub`,
`exp ≤ prev.exp`, and narrows:

| Constraint | Child vs parent |
|---|---|
| `scopes` | every child scope covered by a parent scope |
| `max_amount`, `approval_over`, `max_calls` | integer, `≤` |
| `payees`, `regions`, `data_fields` | subset |
| `purpose` and any other key | equal; cannot be dropped |

The presenter of a message must be the leaf `sub`.

Error codes (stable): `EMPTY_CHAIN`, `BAD_VERSION`, `BAD_SIGNATURE`,
`REVOKED`, `NOT_YET_VALID`, `EXPIRED`, `UNTRUSTED_ROOT`, `BROKEN_CHAIN`,
`EXPIRY_ESCALATION`, `SCOPE_ESCALATION`, `CONSTRAINT_ESCALATION`,
`CONSTRAINT_DROPPED`, `CONSTRAINT_CHANGED`, `PURPOSE_CHANGED`, `NOT_HOLDER`.

### 2.2 Revocation list

`{issuer, entries: {<mandate id | kid>: revoked_at}, seq, sig}` signed by the
issuer. A node keeps the highest valid `seq` per issuer. Distributed with the
SwarmMind `revoke` message.

### 2.3 Policy decision

Input: verified grant + proposed `Action {scope, amount, payee, purpose, text,
sender}`. Output: `{verdict: allow|deny|ask, rule, reason, decided_by}`.
Reference evaluation order: `NO_MANDATE` → `OUT_OF_MANDATE` → `PURPOSE` →
`MAX_AMOUNT` → `PAYEE_NOT_ALLOWED` → `PATTERN:<id>` → `APPROVAL_OVER` →
`WRITE_NEEDS_HUMAN` → `WITHIN_MANDATE`. `ask` means the action is suspended
until an approval decision arrives; timeout = deny.

### 2.4 Human approval

Request `{id, agent, action, reason, mandate_id, created}`. Decision
`{request_id, approved, approver, request, note, ts, sig}` signed by the
human. Valid iff: approver kid is trusted for that principal, `approver ≠
agent` (no self-approval), and `request` equals the original request exactly.

### 2.5 Pattern ("vaccine")

`{id, kind: payee|phrase|sender, indicators[], description, origin, created,
sig}` signed by the node that detected the attack. Contains **indicators only**
— never the conversation, the person or the account data. A receiving node
adopts a pattern only with a signed approval from one of *its own* trusted
humans for the request `{type: "adopt_pattern", pattern_id}`.

### 2.6 Audit log

JSONL, one entry per line:
`{seq, ts, type, actor, data, prev, signer, hash, sig}` where `hash =
SHA-256(canonical(entry − hash − sig))`, `prev` is the previous hash (genesis
`0`×64) and `sig` is Ed25519 by `signer` over the ASCII hash. Verification
detects edits, deletions, insertions and reordering.

## 3. SwarmMind

### 3.1 Envelope

```json
{
  "v": "swarmmind/0.1", "id": "<hex>", "type": "assign",
  "sender": "<public key>", "to": "<kid|null>", "round": 3,
  "reply_to": "<envelope id|null>", "ts": 1790000000,
  "body": {…}, "mandate": [<root>, …, <leaf>], "sig": "<Ed25519 by sender>"
}
```

A receiver MUST reject before any model call when: the signature fails, `|now
− ts| > 600 s`, the `id` was already seen (replay), the mandate chain fails, or
the leaf grant lacks the scope required for the type.

### 3.2 Message types

| Type | Required scope | Meaning |
|---|---|---|
| `discover` | `swarm:discover` | capabilities query |
| `assign` | `swarm:assign` | delegate a task; body may carry a narrowed sub-mandate |
| `propose` | `swarm:propose` | candidate answer or action |
| `object` | `swarm:propose` | disagreement with a proposal + reason |
| `evidence` | `swarm:propose` | derived facts for/against a proposal (never raw data) |
| `vote` | `swarm:vote` | accept / reject a proposal |
| `commit` | `swarm:commit` | final outcome; for writes MUST reference a human approval decision |
| `status` | `swarm:status` | progress, heartbeat |
| `pattern_share` | `swarm:share` | signed Pattern |
| `revoke` | `swarm:revoke` | signed revocation list |

### 3.3 Rounds

Work is organised in short rounds so every Flower task stays well under the
5-minute SuperGrid limit: a coordinator `assign`s, collects `propose` /
`object` / `evidence` with a pull timeout ≤ 90 s, applies policy, raises
approval requests, and `commit`s. State between rounds lives in the audit log.

## 4. Transport binding: Flower Agent Grid (1.39)

The envelope JSON is the Grid message `payload` string. The coordinator runs
as an AgentApp on the SuperLink (`get_nodes`, `push_messages`,
`pull_messages`); participants run as AgentApps on SuperNodes and answer with
`push_reply_message`. Grid tools are invoked by code through the adapter, so
sealing, verification and auditing cannot be skipped by the model.

## 5. Out of scope for v0.1

Consensus at scale and partition handling, hosted revocation/status service,
tamper-proof retention of audit logs, enterprise policy language, key
custody (HSM), identity proofing of humans.
