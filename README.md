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

Latest published release: **v2.2.0** (the badge above). A source checkout of this branch is the
**2.3.0rc1** release candidate, which is not published; the instructions below use the checkout.

## Five-minute pilot demonstration

A synthetic client-support workflow recorded through real LangChain (`langchain-core==1.8.0`), with a
deterministic test model, a tool failure, a sealed and signed pack, and a recipient-verifiable kit.
From the repository root (tested with Python 3.10 and 3.12):

```bash
python -m venv .venv                    # Windows: py -3.12 -m venv .venv
. .venv/bin/activate                    # PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[langchain,sign]"
python examples/consultancy_demo.py --scenario tool-error --mode sync --out demo-runs/run-01
```

`demo-runs/run-01/handoff/` is the shareable kit and `demo-runs/run-01/keys/` stays with the producer.
`INCIDENT_SUMMARY.md` reports three separate results: workflow outcome, capture completeness, and
evidence verification. Scenarios: `success`, `tool-error`, `tool-timeout`; modes: `sync`, `async`.
The output directory must not already exist (or must be empty).

Verify the kit as a recipient would. In the demo the keys are in `../keys` relative to the kit:

```bash
sage handoff verify demo-runs/run-01/handoff --hmac-key-file demo-runs/run-01/keys/hmac.key --public-key-file demo-runs/run-01/keys/ed25519.public.txt
sage key fingerprint demo-runs/run-01/keys/ed25519.public.txt    # same value as pinned_key_fingerprint above
```

The same commands work in PowerShell (`\` or `/` in paths). Exit `0` means the evidence, policy, and
receipt all verified. On failure, `error_type` names what failed (`SignatureMismatchError`,
`ReceiptMismatchError`, `PolicyViolationError`, `ChainIntegrityError`).

A real recipient has no checkout: they get the kit, the wheel, and the two key files separately, and
follow `HANDOFF.md`. A recipient who cannot install packages can use the single-file verifier from
the release, `sage-verify-<version>.pyz`, which needs only Python 3.10 or newer:
`python sage-verify-<version>.pyz <kit> --hmac-key-file <file> --public-key-file <file>`.

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

The same handler works for LangGraph: pass it in the graph's `config` (`pip install ".[langgraph]"`).

Tested scope: `langchain-core==1.8.0` (also 1.6.13 and 1.7.7) and `langgraph==1.2.21` on Python 3.12.
That covers chains, chat models, tools, retrievers, streaming, batch, `RunnableParallel`, and LangGraph
graphs with conditional edges, tool nodes, parallel branches, subgraphs, and interrupt/resume, sync and
async, one callback instance per workflow. `COMPATIBILITY.md` lists exactly what is and is not
validated. Callback errors surface to the caller (`raise_error=True`), so start in development or staging.

OpenAI Agents SDK (`pip install -e ".[openai-agents]"`, tested with `openai-agents==0.24.0`):

```python
from agents import Runner, set_trace_processors
from sage.adapters.openai_agents import SageOpenAIAgentsProcessor

processor = SageOpenAIAgentsProcessor(trace_id="incident-42", journal_dir="run.journal")
set_trace_processors([processor])          # add_trace_processor(...) keeps the OpenAI exporter too
with processor:
    Runner.run_sync(agent, "Where is order 42?")
processor.assert_complete()
processor.export("incident.sage.json")
```

Agents, model calls, tool calls, handoffs, guardrails, and the SDK's task/turn spans become SAGE spans
nested as the SDK nested them.

PydanticAI (`pip install -e ".[pydantic-ai]"`, tested with `pydantic-ai-slim==2.68.0`):

```python
from sage.adapters.pydantic_ai import SagePydanticAI

sage = SagePydanticAI(trace_id="incident-42", journal_dir="run.journal")
agent = sage.instrument(agent)             # or sage.instrument_all()
with sage:
    agent.run_sync("Where is order 42?")
sage.assert_complete()
sage.export("incident.sage.json")
```

It reads PydanticAI's OpenTelemetry spans (`invoke_agent`, `chat`, `execute_tool`) through a private
tracer provider; nothing is sent to an external exporter.

Existing OpenTelemetry traces (OTLP JSON, JSON Lines, or protobuf with `pip install -e ".[otlp]"`):

```bash
sage import traces.pb --format otlp --out incident.sage.json
sage verify incident.sage.json
```

OpenInference (`llm.*`, `tool.*`, `retrieval.documents.*`) and GenAI (`gen_ai.*`) attributes become
typed span data. Tested against exports from `opentelemetry-sdk==1.45.2`. See `COMPATIBILITY.md` for
what each adapter covers and what is not validated.

## Live journal durability

Pass `journal_dir=` to write a crash-recoverable journal while the run is in progress. Closed spans
are redacted, offloaded, hash-chained, and appended to `spans.jsonl` / `chain.jsonl`.
`journal_durability=` selects when they reach the disk:

| Mode | When a closed span is on disk | What a crash can lose |
|------|-------------------------------|-----------------------|
| `"span"` | Before `end_span` returns (four fsyncs per span) | Nothing that was closed |
| `"batch"` (default) | A background thread group-commits with fsync when the oldest waiting span is 50 ms old or 256 spans wait, whichever comes first | Spans closed inside that window, plus the commit under way |
| `"close"` | Same background writes, but no fsync until `flush_journal()` or the seal | Process crash: as `"batch"`. Operating-system crash or power loss: anything since the last `flush_journal()` |

```python
with SageRecorder(trace_id="incident-42", journal_dir="run.journal", journal_durability="batch") as rec:
    ...
    rec.flush_journal()   # optional checkpoint: returns once everything closed so far is fsynced
```

- The window is tunable: `journal_batch_interval_ms=` and `journal_batch_max_spans=`. It is also
  bounded: once 4 × `journal_batch_max_spans` spans (1,024 by default) are uncommitted, `end_span`
  waits for the disk. When the disk is slow, the window stretches in time but not past that count.
- `SAGE_JOURNAL_DURABILITY=span|batch|close` sets the mode when the argument is not given. The
  adapters (`SageLangChainCallback`, `SageOpenAIAgentsProcessor`, `SagePydanticAI`, `wrap_agent_run`,
  `attach_otel_tap`, `instrument`, `wrap_run`)
  accept `journal_durability=` too.
- Sealing (leaving the `with` block, `finalize()`, `export()`) always flushes, fsyncs, and stops the
  writer thread. A write failure on the writer thread is raised as `JournalWriteError` from the next
  `end_span`, `flush_journal()`, or the seal. It is never dropped.
- In `"batch"` and `"close"` mode, read the live files only after `flush_journal()`; `end_span`
  returning no longer means the span is on disk. Use `"span"` if you need that guarantee.
- After a crash, `sage audit <journal>` (or `sage.journal.recover_journal`) returns the intact
  prefix. A journal killed in the middle of a commit can fail `sage verify-journal` until recovered.
- Offloaded blobs follow the same schedule: in `"batch"` and `"close"` mode they are fsynced in
  groups before the journal lines that refer to them are committed (and always before the seal). A
  blob never gets its content-address name before it has been fsynced; until then only the
  recording process can read it.
- The mode changes timing only. Record formats and every hash are identical in all three modes, and
  journals written by earlier releases verify unchanged.

Measure it on your own hardware: `python scripts/measure_overhead.py --mode journal --durability all`
prints per-span medians by mode and payload size as JSON. CI runs the same script on Linux and keeps
the result as the `journal-benchmark` artifact. [docs/perf.md](docs/perf.md) has reference numbers
for Linux and Windows. These are measurements, not a service-level commitment.

## What you get

| Capability | Detail |
|------------|--------|
| **Recorder** | Sanitize-on-close, redact-before-hash, CAS offload |
| **Journal** | Crash-safe live WAL (durability `span` / `batch` / `close`) → sealed manifest + merkle |
| **Pack v2** | Portable `.sage.tar.gz` with custody-bound HMAC |
| **Verify** | Policies, blob inventory, witness, receipts |
| **Signatures** | Optional Ed25519 — **pinned key required** (TOFU refused) |
| **Handoff** | Offline auditor kit (`sage handoff`) |
| **Adapters** | LangChain callback, OpenAI Agents SDK processor, PydanticAI (tested against the pinned real packages); OTLP / OpenInference import; CrewAI/AutoGen wrappers are unit-tested only |

Formats are frozen under the [2.x compatibility covenant](COMPATIBILITY.md).

## Explicit non-claims

- Does **not** prove the agent / LLM / tools told the truth  
- Does **not** guarantee complete capture of arbitrary applications; only instrumented work is recorded  
- Does **not** diagnose root cause automatically  
- Redaction applies configured key and pattern rules (plus opt-in shape detectors), and `sage scan` checks a pack before you share it; neither detects every kind of sensitive data. See [docs/REDACTION.md](docs/REDACTION.md)  
- Software HMAC/Ed25519 ≠ HSM identity — see [THREAT_MODEL.md](THREAT_MODEL.md)  
- Not a legal-admissibility or regulatory-compliance claim  
- Research (`sage research *`) is **not** forensic custody

## Install

SAGE is not published on PyPI. Install from a checkout or from a wheel you were given:

```bash
pip install -e ".[dev]"            # checkout: core + tests + cryptography
pip install -e ".[langchain]"      # pinned langchain-core for the callback adapter
pip install -e ".[openai-agents]"  # pinned openai-agents for the tracing processor
pip install -e ".[pydantic-ai]"    # pinned pydantic-ai-slim + opentelemetry-sdk
pip install -e ".[otlp]"           # pinned opentelemetry-proto for binary OTLP import
pip install -e ".[sign]"           # Ed25519 only
pip install -e ".[tui]"            # optional inspect TUI

python -m pip install "sage_incident_bundles-<version>-py3-none-any.whl[sign]"   # recipient; drop [sign] for unsigned kits
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
| [REDACTION.md](docs/REDACTION.md) | Redaction rules, opt-in detectors, `sage scan` pre-share check |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, adversaries, non-goals |
| [FORMAT.md](docs/spec/FORMAT.md) | Normative artifact spec; conformance vectors in `tests/vectors/` |
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
