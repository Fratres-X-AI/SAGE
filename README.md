# SAGE — Agent Incident Forensics

**Fail-closed security tool** for portable agent incident evidence: redactable, hash-chained, third-party verifiable.

SAGE is **not** a chat UI, not an RCA leaderboard, and not “observability SaaS.” Trace products already exist. The gap is a **backend-neutral forensic artifact** you can seal, ship, and re-verify without trusting the producer.

**Current release: v2.1.1** — OSS-ready custody toolkit: quarantine unpack, **pinned** Ed25519 signatures, auditor policy/kit, release gate, threat-matrix. Formats remain on the 2.0 freeze. See [`COMPATIBILITY.md`](COMPATIBILITY.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), [`SECURITY.md`](SECURITY.md), [`RELEASE.md`](RELEASE.md), [`CHANGELOG.md`](CHANGELOG.md).

## Security loop (production)

```bash
pip install -e ".[dev]"          # includes cryptography for Ed25519 tests
# optional: pip install -e ".[sign]"  # Ed25519 only, without full dev set

# record → pack v2 → strict policy → handoff kit
export SAGE_PACK_KEY="replace-me"
python examples/security_verify_loop.py

sage doctor
sage verify evidence.sage.tar.gz \
  --policy policies/strict.json \
  --witness \
  --hmac-key "$SAGE_PACK_KEY" \
  --receipt verify.receipt.json

sage verify-receipt verify.receipt.json --verify-key "$SAGE_PACK_KEY"
sage version
```

Optional asymmetric custody (**pinned** public key required to verify):

```bash
sage keygen --out ~/.sage/ed25519.json   # keep private; do not commit
export SAGE_SIGN_PRIVATE_KEY=...         # from keygen JSON
export SAGE_SIGN_PUBLIC_KEY=...          # auditors pin this
sage pack incident.sage.json --out evidence.sage.tar.gz --hmac-key "$SAGE_PACK_KEY" --sign
sage verify evidence.sage.tar.gz \
  --policy policies/auditor.json \
  --hmac-key "$SAGE_PACK_KEY" \
  --require-signature \
  --public-key "$SAGE_SIGN_PUBLIC_KEY"
python examples/auditor_kit.py
```

Auditor offline path: [`docs/VERIFY_RUNBOOK.md`](docs/VERIFY_RUNBOOK.md) · pinned-signature kit: [`docs/AUDITOR_KIT.md`](docs/AUDITOR_KIT.md).

## What v2 freezes

| Surface | Format / API |
|---------|----------------|
| Journal | `sage.journal.v1` |
| Pack | `sage.pack.v2` (custody-bound HMAC) |
| Policy / receipt / keys | `sage.verify.policy.v1` / `receipt.v1` / `keys.v1` |
| Bundle schema | `1.0` |
| Python API | `sage.version.STABLE_PUBLIC_API` |

Breaking these requires **3.0**. Migration: [`MIGRATION_v2.md`](MIGRATION_v2.md).

## Core capabilities

| Pillar | Mechanism |
|--------|-----------|
| Recorder | `SageRecorder` — sanitize-on-close, redact-before-hash, CAS |
| Journal | Live WAL + sealed `manifest_seal` + `merkle_root` |
| Verify | `sage verify` + policies + CAS inventory + witness |
| Pack / handoff | Pack v2 + `sage handoff` offline kit |
| Custody | `witness.jsonl` + HMAC receipts |
| Adapters | LangChain callback, CrewAI/AutoGen run wrappers, OTel tap/export |
| Heal | Sealed `HealCapability` boundaries |
| Research | `sage research *` (explicitly non-forensic) |

```python
from sage import SageRecorder

with SageRecorder(trace_id="user-123") as recorder:
    agent.run(task)
recorder.export("incident.sage.json")
```

## Install

```bash
pip install -e ".[dev]"    # core (stdlib) + tests + cryptography
pip install -e ".[sign]"   # optional Ed25519 only
pip install -e ".[tui]"    # optional Textual inspect TUI
pip install -e ".[attr]"   # optional research helpers
```

## Tests

```bash
pytest                     # forensics suite (attribution research ignored by default)
python scripts/release_check.py
python scripts/ci_smoke.py
python examples/security_verify_loop.py
python examples/auditor_kit.py
sage doctor
```

CI matrix: Ubuntu / Windows / macOS × Python 3.10 / 3.12.

## Explicit non-claims

- SAGE does **not** prove the agent/LLM/tools told the truth.
- Synthetic attribution benches are a **research harness**, not production RCA.
- HMAC custody ≠ hardware-backed identity. See the threat model.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
