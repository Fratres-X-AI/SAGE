<p align="center">
  <img src="docs/assets/sage-linkedin-hero.png" alt="SAGE — Agent Incident Forensics" width="100%" />
</p>

<h1 align="center">SAGE</h1>
<p align="center"><strong>Agent Incident Forensics</strong></p>
<p align="center">
  Portable, redactable, hash-chained evidence for agent runs.<br/>
  Seal it. Ship it. Re-verify it — without trusting the producer’s UI.
</p>

<p align="center">
  <a href="https://github.com/Fratres-X-AI/SAGE/actions/workflows/ci.yml"><img src="https://github.com/Fratres-X-AI/SAGE/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-red.svg" alt="License" /></a>
  <a href="https://github.com/Fratres-X-AI/SAGE/releases/tag/v2.2.0"><img src="https://img.shields.io/badge/release-v2.2.0-informational.svg" alt="Release" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python" /></a>
</p>

---

## Why SAGE exists

Traces show you a story in a dashboard.  
**SAGE gives you an artifact another team can fail-closed verify offline.**

Observability products already exist. The gap is a **backend-neutral forensic pack**: redacted before hash, content-addressed blobs, custody MAC, optional pinned Ed25519, third-party `sage verify`.

SAGE is a **security tool**, not a chat UI, not an RCA leaderboard, and not “AI observability SaaS.”

## 60-second loop

```bash
pip install -e ".[dev]"
export SAGE_PACK_KEY="replace-me"

python examples/security_verify_loop.py

sage verify evidence.sage.tar.gz \
  --policy policies/strict.json \
  --witness \
  --hmac-key "$SAGE_PACK_KEY" \
  --receipt verify.receipt.json
```

Auditor posture (pinned signature):

```bash
python examples/auditor_kit.py
# docs: docs/AUDITOR_KIT.md · docs/VERIFY_RUNBOOK.md
```

```python
from sage import SageRecorder

with SageRecorder(trace_id="incident-42") as rec:
    agent.run(task)
rec.export("incident.sage.json")
```

## What you get

| Capability | Detail |
|------------|--------|
| **Recorder** | Sanitize-on-close, redact-before-hash, CAS offload |
| **Journal** | Crash-safe live WAL → sealed manifest + merkle |
| **Pack v2** | Portable `.sage.tar.gz` with custody-bound HMAC |
| **Verify** | Policies, blob inventory, witness, receipts |
| **Signatures** | Optional Ed25519 — **pinned key required** (TOFU refused) |
| **Handoff** | Offline auditor kit (`sage handoff`) |
| **Adapters** | LangChain callback, CrewAI/AutoGen wrappers, OTel tap |

Formats are frozen under the [2.x compatibility covenant](COMPATIBILITY.md).

## Explicit non-claims

- Does **not** prove the agent / LLM / tools told the truth  
- Research (`sage research *`) is **not** forensic custody  
- Software HMAC/Ed25519 ≠ HSM identity — see [THREAT_MODEL.md](THREAT_MODEL.md)

## Install

```bash
pip install -e ".[dev]"     # core + tests + cryptography
pip install -e ".[sign]"    # Ed25519 only
pip install -e ".[tui]"     # optional inspect TUI
```

Core recorder / CAS / verify / CLI remain **stdlib-only**.

## Prove it locally

```bash
python scripts/release_check.py
pytest -q
python examples/auditor_kit.py
sage doctor
```

CI: Ubuntu · Windows · macOS × Python 3.10 / 3.12.

## Docs

| Doc | Purpose |
|-----|---------|
| [VERIFY_RUNBOOK.md](docs/VERIFY_RUNBOOK.md) | Record → ship → auditor re-verify |
| [AUDITOR_KIT.md](docs/AUDITOR_KIT.md) | Pinned-signature verify posture |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, adversaries, non-goals |
| [SECURITY.md](SECURITY.md) | Supported versions / reporting |
| [RELEASE.md](RELEASE.md) | Tag / publish checklist |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR bar for a security tool |

## Design partners

If you run agents in production and want sealed incident packs on **one** real path — open an issue or reach out. We want brutal feedback, not vanity stars.

## License

**[FSL-1.1-ALv2](LICENSE)** — Functional Source License (Fair Source).

- ✅ Internal use, education, research, self-host for your company  
- ❌ Competing commercial product/SaaS without a commercial license  
- ⏱ Converts to Apache-2.0 **2 years** after each version’s availability  

Commercial terms: [COMMERCIAL.md](COMMERCIAL.md) · License FAQ: [fsl.software](https://fsl.software/)
