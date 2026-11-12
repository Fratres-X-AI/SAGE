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

Current release: **v2.2.0**. Release candidate on this branch: **2.3.0rc1** (not published).

## Five-minute pilot demonstration

A synthetic client-support workflow recorded through real LangChain (`langchain-core==1.8.0`), with a
deterministic test model, a tool failure, a sealed and signed pack, and a recipient-verifiable kit:

```bash
pip install -e ".[langchain,sign]"
python examples/consultancy_demo.py --scenario tool-error --mode sync --out demo-runs/run-01
```

`demo-runs/run-01/handoff/` is the shareable kit and `demo-runs/run-01/keys/` stays with the producer.
`INCIDENT_SUMMARY.md` reports three separate results: workflow outcome, capture completeness, and
evidence verification. Scenarios: `success`, `tool-error`, `tool-timeout`; modes: `sync`, `async`.

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

## Instrumenting your code

`SageRecorder` records only the spans you open or that an adapter opens for you. Wrapping a call in the
recorder does not trace it by itself.

Manual spans:

```python
from sage import SageRecorder

with SageRecorder(trace_id="incident-42") as rec:
    with rec.tool_call("lookup", inputs={"account": account_id}) as span:
        span.set_output(result=lookup(account_id))
rec.export("incident.sage.json")
```

LangChain (automatic for the runnables, chat models, and tools invoked with the callback):

```python
from sage import SageRecorder
from sage.adapters.langchain_callback import SageLangChainCallback

with SageRecorder(trace_id="incident-42", framework="langchain") as rec:
    handler = SageLangChainCallback(rec)
    chain.invoke(inputs, config={"callbacks": [handler]})   # AsyncSageLangChainCallback for ainvoke
    handler.assert_complete()                               # raises if capture was incomplete
rec.export("incident.sage.json")
```

Tested LangChain scope: `langchain-core==1.8.0` on Python 3.12, sequential chains, chat models, and
tools, sync and async, one callback instance per workflow run. Parallel branches inside one run,
token streaming, LangGraph, and other framework versions are not validated. Callback errors surface
to the caller (`raise_error=True`), so start in development or staging.

## What you get

| Capability | Detail |
|------------|--------|
| **Recorder** | Sanitize-on-close, redact-before-hash, CAS offload |
| **Journal** | Crash-safe live WAL → sealed manifest + merkle |
| **Pack v2** | Portable `.sage.tar.gz` with custody-bound HMAC |
| **Verify** | Policies, blob inventory, witness, receipts |
| **Signatures** | Optional Ed25519 — **pinned key required** (TOFU refused) |
| **Handoff** | Offline auditor kit (`sage handoff`) |
| **Adapters** | LangChain callback (tested against real `langchain-core`); CrewAI/AutoGen wrappers and OTel tap are unit-tested only |

Formats are frozen under the [2.x compatibility covenant](COMPATIBILITY.md).

## Explicit non-claims

- Does **not** prove the agent / LLM / tools told the truth  
- Does **not** guarantee complete capture of arbitrary applications; only instrumented work is recorded  
- Does **not** diagnose root cause automatically  
- Redaction applies configured key and pattern rules; it does **not** detect every kind of sensitive data  
- Software HMAC/Ed25519 ≠ HSM identity — see [THREAT_MODEL.md](THREAT_MODEL.md)  
- Not a legal-admissibility or regulatory-compliance claim  
- Research (`sage research *`) is **not** forensic custody

## Install

SAGE is not published on PyPI. Install from a checkout or from a wheel you were given:

```bash
pip install -e ".[dev]"            # checkout: core + tests + cryptography
pip install -e ".[langchain]"      # pinned langchain-core for the callback adapter
pip install -e ".[sign]"           # Ed25519 only
pip install -e ".[tui]"            # optional inspect TUI

python -m pip install sage_incident_bundles-<version>-py3-none-any.whl   # recipient: verify only
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
