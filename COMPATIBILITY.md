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

## 2.3 notes (2.3.0, non-breaking)

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
| `sage.importers.otlp` / `sage import --format otlp` | OTLP JSON: no extra packages. Protobuf: `opentelemetry-proto==1.45.2` (pinned `[otlp]`). Fixtures and live spans from `opentelemetry-sdk==1.45.2`; Python 3.12 (CI: Ubuntu) | `MessageToDict` JSON (base64 ids, enum names, int64 strings), spec / Collector-style JSON and JSON Lines (hex ids, integer enums), binary `ExportTraceServiceRequest`, SDK `to_json()` dicts; OpenInference and GenAI attributes mapped into typed span data |
| `sage.adapters.openai_agents` | `openai-agents==0.24.0` (pinned `[openai-agents]`); Python 3.12 (CI: Ubuntu) | `Runner.run` / `Runner.run_sync` with an offline `Model`: tool call, handoff between two agents, input guardrail tripwire, tool exception, model exception, task/turn spans, nesting |
| `sage.adapters.pydantic_ai` | `pydantic-ai-slim==2.68.0` + `opentelemetry-sdk==1.45.2` (pinned `[pydantic-ai]`); Python 3.12 (CI: Ubuntu) | `run_sync` / `run` with `TestModel` and `FunctionModel`: tool call, structured output, `ModelRetry` retry, output-validation retry, tool exception, `include_content=False`, `instrument_all`, an existing `TracerProvider` |
| OTel tap (`attach_otel_tap`) | The OTLP fixtures above | `ingest_payload` of real SDK exports; `on_span` per span dict |
| CrewAI / AutoGen wrappers | Stand-in objects only | Not validated against the real frameworks |

The core (recorder, journal, pack, verify, CLI) is tested on Ubuntu, Windows, and macOS with
Python 3.10 and 3.12. That matrix does not extend to the adapters. The full resolved dependency sets
are in `constraints/langchain.txt`, `constraints/langgraph.txt` and `constraints/otel-agents.txt`; the
1.6.13 and 1.7.7 lanes resolve freely and print what they tested. `constraints/otel-agents.txt` cannot
be combined with `constraints/langgraph.txt`: openai-agents 0.24.0 requires `websockets<17`.

OTLP import behavior to know:

- Span types come from `openinference.span.kind`, then `gen_ai.operation.name`. Spans with neither
  (plain HTTP or database spans) become `chain`. The OTLP span kind (INTERNAL, CLIENT, ...) is kept as
  `otel.span_kind`; the OTel trace id as `otel.trace_id` and in `bundle.metadata["otel_trace_ids"]`.
- Span ids are stored as 16-digit lowercase hex whether the input used hex or base64.
- Token counts are copied to `data["usage"]` as `prompt_tokens` / `completion_tokens` / `total_tokens`
  (OpenInference) or `input_tokens` / `output_tokens` (GenAI). The raw `llm.token_count.*` attributes
  are kept too while their values are numbers (before 2.3.0 they were replaced by `[REDACTED]`).
- An `exception` event becomes the span error (type, message, stack with directory names cut).
- Not supported: compressed exports (gzip/zstd files), OTLP logs and metrics, span links, resource
  attributes such as `service.name` (the instrumentation scope is kept per span). Duplicate span
  ids keep the first copy.

OpenAI Agents behavior to know:

- Register with `set_trace_processors([processor])` to record only into SAGE, or
  `add_trace_processor(processor)` to keep the OpenAI exporter. Call `assert_complete()`; the SDK swallows
  processor exceptions, so capture errors are only reported there.
- Each SDK trace is a `chain` root span. Mapping: `agent` → agent, `generation` / `response` → llm,
  `function` → tool, `handoff` → handoff, `guardrail` → guardrail, `task` / `turn` → chain,
  `custom` / `mcp_tools` → custom, `transcription` / `speech` → llm, `speech_group` → chain.
- A triggered guardrail is an `error` span (`GuardrailTripwireTriggered`, `data["triggered"] = true`); the
  SDK puts its own "Guardrail tripwire triggered" error on the enclosing turn span.
- openai-agents 0.24.0 replaces a tool's exception text with "Tool execution failed. Error details are
  redacted." before processors see it; SAGE records what the SDK reports.
- Model inputs and outputs are only present when the model implementation records them on the
  generation span and `trace_include_sensitive_data` is true. Tests use an offline model that records
  them the way the SDK's chat-completions model does. Not validated: the real OpenAI models, the
  `response` span with a live Responses API, streaming (`run_streamed`), MCP, realtime and voice.

PydanticAI behavior to know:

- `SagePydanticAI.instrument(agent)` installs `InstrumentationSettings` with a private
  `TracerProvider`, so spans do not reach a global exporter. Use `sage.span_processor` on an existing
  provider (for example Logfire) instead.
- Mapping: `invoke_agent` → agent, `chat` → llm, `execute_tool` → tool, anything else → chain.
- A tool that raises `ModelRetry` is an `error` span with `data["retry"]`, because PydanticAI marks it
  ERROR. The bundle is then `failed` even if the run recovered.
- Tool results arrive as strings (OTel attribute values). With `include_content=False` the message
  structure is kept without text.
- Not validated: streaming (`run_stream`), real provider models, MCP toolsets, durable execution.

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
