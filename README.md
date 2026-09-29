# SwarmMind

**The context layer for collaborating agents.** A signed envelope and ten message types that carry *authority*,
not just text. Specification (CC BY 4.0) + reference code (Apache-2.0).

- **`SPEC.md`** — SwarmMind v0.1 and SwarmAuth v0.1: envelope, message types, rounds, mandates, approvals, patterns, audit.
- **`swarmmind/envelope.py`** — `seal()` / `open_envelope()`: signature, freshness, replay, mandate chain and
  per-type scope are verified **before any model sees the body**.
- **`swarmmind/flower.py`** — transport binding for Flower Agent Grid tools (`get_nodes`, `push_messages`,
  `pull_messages`, `push_reply_message`), called from code so sealing, verification and auditing can't be skipped.

| Type | Meaning |
|---|---|
| `discover` · `assign` · `propose` · `object` · `evidence` · `vote` · `commit` · `status` | coordination |
| `pattern_share` | a signed threat pattern ("vaccine"): indicators only, never data |
| `revoke` | a signed revocation list |

Identity and mandates come from [SwarmAuth](https://github.com/hiveflowai/swarmauth). See it running on Flower in
[Hiveflow Swarm](https://github.com/hiveflowai/hiveflow-swarm).

```bash
uv sync && uv run pytest
```

© 2026 Hiveflow, Inc. · code Apache-2.0 · SPEC.md CC BY 4.0
