# Compatibility Covenant (SAGE 2.x)

## Semver

- **MAJOR** — breaking change to stable public API **or** frozen forensic formats that invalidate prior verify.
- **MINOR** — backward-compatible features / adapters / docs (e.g. 2.1 quarantine + optional Ed25519).
- **PATCH** — bugfixes that preserve verify outcomes for honest artifacts.

Research surfaces (`sage research *`, attribution training) are **not** under the freeze.

## 2.1 notes (non-breaking)

- Unpack defaults to **quarantine** (staging verify then promote). Use `quarantine=False` / `--no-quarantine` for the prior in-place extract path.
- Ed25519 pack signatures are optional; HMAC-only packs remain valid unless `require_signature` / `SAGE_REQUIRE_PACK_SIGNATURE` is set.

## 2.1.1 notes

- `--require-signature` now **refuses TOFU** (embedded pack public key alone). Supply a pinned key via `--public-key`, `SAGE_SIGN_PUBLIC_KEY`, or key ring. Escape hatch: `--allow-tofu-signature`.
- Deprecated top-level `sage attribute|train|bench|synth` aliases removed; use `sage research …`.

## 2.3 notes (release candidate 2.3.0rc1, non-breaking)

- No frozen format changed. Artifacts sealed by 2.2.0 verify unchanged (`tests/fixtures/compat_v2_2_0`).
- Newly recorded spans redact error message and stack, failure context, events, and span name. Old
  artifacts are verified as sealed; verification never rewrites them.
- Exceptions now record their class name as `error.type` (previously the generic `Error`) plus a
  bounded traceback.
- `create_handoff()` raises `HandoffSetupError` instead of weakening an explicit policy when keys are
  missing, and refuses to overwrite a non-empty destination unless `overwrite=True`.
- `verify_handoff.py` now requires `verify.receipt.json` and checks it against the verified pack.

### Tested adapter compatibility

| Adapter | Tested against | Scope |
|---------|----------------|-------|
| `sage.adapters.langchain_callback` | `langchain-core==1.8.0` (pinned), also 1.6.13 and 1.7.7; Python 3.12 (CI: Ubuntu) | Chains, chat models, LLMs, tools, retrievers; `invoke`/`ainvoke`, `stream`/`astream`, `batch`/`abatch`, `RunnableParallel`; one handler per workflow |
| Same handler on LangGraph | `langgraph==1.2.21` with the langchain-core versions above | `StateGraph` nodes, conditional edges, `ToolNode`, fan-out/fan-in, subgraphs, `interrupt` and `Command(resume=...)`, `ainvoke`, `stream(stream_mode="updates")` |
| CrewAI / AutoGen wrappers, OTel tap | Stand-in objects only | Not validated against the real frameworks |

The core (recorder, journal, pack, verify, CLI) is tested on Ubuntu, Windows, and macOS with
Python 3.10 and 3.12. That matrix does not extend to the adapters. The full resolved dependency sets
are in `constraints/langchain.txt` and `constraints/langgraph.txt`; the 1.6.13 and 1.7.7 lanes resolve
freely and print what they tested.

LangChain behavior to know:

- Use one handler instance per workflow run. Call `assert_complete()` before handing off an artifact.
- Callback failures surface and stop the workflow (`raise_error=True`). Keep pilots to development or
  staging until production failure handling is agreed.
- langchain-core gates tool callbacks on `ignore_agent`; the handler keeps it `False`.
- When an async handler runs under a sync `invoke`, LangChain logs and drops handler exceptions even
  with `raise_error=True`; `assert_complete()` still reports those capture errors.
- Streaming records one model span. Chunks are counted in `data["stream"]["chunks"]`; the final text
  is in the span outputs. A streamed chain's inputs are filled in when the run ends.
- Batch and parallel runs share one handler safely; each run becomes its own span (batch items are
  separate root spans).

LangGraph behavior to know:

- Node spans carry `langgraph.node` and `langgraph.step` attributes; root spans carry
  `langgraph.thread_id` when a checkpointer thread is configured. Parent links follow LangGraph run ids.
- An `interrupt()` is recorded on the node span as status `cancelled` with
  `data["langgraph"] = {"interrupted": true, "interrupts": [...]}`. It is not an error, so the bundle
  stays `completed`. Interrupt payloads pass through redaction like any other span data.
- The resumed run (`Command(resume=...)`) is a new root span in the same bundle when the same handler
  is passed. A `ParentCommand` handoff ends the node span `ok` with `data["langgraph"]["control"]`.

Not validated, and not claimed: `astream_events`, agent action/finish events, retry and custom events,
real provider SDKs, LangGraph Platform / remote graphs, and versions other than those listed above.

Live-journal durability (`journal_durability="span" | "batch" | "close"`, default `"batch"` since
2.3.0) changes when records are fsynced, not what is written. `sage.journal.v1` is unchanged; a live
journal holds the same lines and the same hashes in every mode.

## Frozen formats (2.0)

| Format ID | Meaning |
|-----------|---------|
| `sage.journal.v1` | Live/sealed journal layout |
| `sage.pack.v2` | Default portable pack + custody MAC |
| `sage.pack.v1` | Legacy pack MAC (content_digest only); still verifiable |
| `sage.verify.policy.v1` | Verify policy document |
| `sage.verify.receipt.v1` | Verification receipt |
| `sage.keys.v1` | Key ring |
| Schema `1.0` | Bundle/span content model |

Breaking these requires SAGE **3.0** and a migration guide.

## Stable Python API

See `sage.version.STABLE_PUBLIC_API`. Importing from private modules (`sage.*` internals not listed) is unsupported.

## Hash binding rule

Verification is defined on **compact** (redacted, CAS-referenced) form. Rehydrated bundles are for inspection/replay, not for re-sealing without an explicit new finalize.
