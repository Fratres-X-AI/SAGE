# Changelog

## 2.3.0rc1 — 2026-11-12 (release candidate, not published)

Frozen formats are unchanged; artifacts sealed by 2.2.0 still verify (`tests/fixtures/compat_v2_2_0`).

### Assurance

- `docs/spec/FORMAT.md` is the normative spec for bundles, journals, packs, witness logs, policies,
  and receipts: encodings, hash inputs, verification order, and exit codes.
- `tests/vectors/` holds 53 conformance vectors (accept and reject, each tied to a spec section).
  `run_vectors.py` checks an implementation against them. `reference_check.py` recomputes every
  hash, MAC, and signature in the valid vectors from the spec alone, with the standard library.
- Property tests (Hypothesis) and atheris fuzz harnesses (`fuzz/`, weekly in `fuzz.yml`, a short run
  on every PR) check that hostile input is rejected with a typed error. They found these
  verifier gaps, now fixed:
  - Deleting `pack.json` let a pack pass as an unattested journal when no policy was given. It is
    now refused when a key or signature is required.
  - Span members the hashes do not cover were accepted. Stored spans and bundles must now be in
    normal form.
  - `bundle_hash`, `merkle_root`, and `witness_tip` in `pack.json` were not checked against the
    journal. They are now.
  - Policy `min_redaction_count` read an unauthenticated count from `pack.json`. It now reads the
    hash-bound bundle.
  - A corrupt complete line in a journal was reported as a recoverable torn tail (exit 2). Only the
    unterminated last line counts as torn now; other bad lines exit 1.
  - A required pin with no pinned key raised `ChainIntegrityError`; it is now
    `SignatureMismatchError` (a subclass, so existing handlers still catch it).
  - Malformed tar, gzip, JSON, receipt, and policy input could escape as raw Python exceptions. They
    are now `ChainIntegrityError` or `ReceiptMismatchError`.
- On Windows, a process reading a live journal's manifest could make the recorder's manifest update
  fail (`PermissionError` from `os.replace`), which stopped the background writer. Journal, bundle,
  and blob writes now retry the replace for up to 5 seconds while a reader has the file open, and
  SAGE's own manifest reads retry while a replace is under way.

### OpenTelemetry import and new framework adapters

- New `sage.importers.otlp` (`load_otlp_file`, `import_otlp`) and `sage import <file> --format otlp`.
  It reads OTLP JSON in both encodings seen in practice (spec / Collector style with hex ids and integer
  enums, and protobuf `MessageToDict` output with base64 ids, enum names and int64 strings), JSON Lines,
  and binary `ExportTraceServiceRequest` protobuf. Protobuf needs the new `[otlp]` extra
  (`opentelemetry-proto==1.45.2`). Imported bundles are sealed and pass `sage verify`.
- The OpenInference importer now fills typed span data from OpenInference attributes
  (`llm.model_name`, `llm.invocation_parameters`, flattened `llm.input_messages.*` /
  `llm.output_messages.*`, `llm.token_count.*`, `tool.name`, `retrieval.documents.*`) and from GenAI
  attributes (`gen_ai.request.model`, `gen_ai.input.messages`, `gen_ai.usage.*`, `gen_ai.tool.*`,
  `gen_ai.agent.name`). `exception` events become span errors.
- Fixed: importing an OTLP span without `openinference.span.kind` raised `ValueError`, because the OTel
  span kind (`1`, `SPAN_KIND_INTERNAL`) was read as a SAGE span type. Unknown OpenInference kinds now
  map to `custom` instead of failing.
- New `sage.adapters.openai_agents.SageOpenAIAgentsProcessor`, an OpenAI Agents SDK tracing processor
  (`[openai-agents]` extra, `openai-agents==0.24.0`). Tested with real `Runner.run` / `run_sync` runs and
  an offline model: tool calls, a handoff between two agents, a guardrail tripwire, tool and model
  exceptions, and span nesting.
- New `sage.adapters.pydantic_ai.SagePydanticAI` (`[pydantic-ai]` extra, `pydantic-ai-slim==2.68.0`
  with `opentelemetry-sdk==1.45.2`). It records PydanticAI's OpenTelemetry spans through a private
  tracer provider. Tested with `TestModel` and `FunctionModel`: tool calls, structured output, tool
  retries, output-validation retries, and a tool exception.
- Both adapters import without their extras and raise an install hint when constructed.
- `constraints/otel-agents.txt` and a CI job (`otel-agents-integration`). `release_check.py` checks the
  new exact pins.

### Redaction detectors and pre-share leak check

See `docs/REDACTION.md`.

- New opt-in detectors, all off by default: `openai_key`, `anthropic_key`, `aws_access_key_id`,
  `github_token`, `slack_token`, `google_api_key`, `stripe_key`, `private_key_pem`, `jwt`,
  `bearer_token`, `email`, `card_number` (issuer prefix and Luhn check), `high_entropy`, and
  `local_path`. Turn them on with `redaction_policy={"detectors": [...]}` or `["all"]`. They run before
  hashing, like the existing rules. With no detectors, output and bundle hashes are byte-identical to
  2.2 (pinned by a test).
- New `sage scan <pack|bundle|journal>` (`--json`, `--rule`, `--blob-root`). It reports possible leaks
  by rule id and location (file member, line, span id, JSON path), including `pack.json`, journal
  metadata, blobs, and dict keys. It never prints a value, only its length and a SHA-256 prefix. Exit
  codes: 0 no findings, 1 findings, 2 setup or usage error.
- `sage handoff` scans the pack it builds and warns on stderr when there are findings.
  `--fail-on-findings` refuses to build the kit. New `--blob-root` on `sage pack` and `sage handoff`.
- **Behaviour change (token counts):** new recordings keep token counts. Before, any key containing
  `token` was redacted unless it was on a short allowlist or ended in `_tokens`, so
  `llm.token_count.*` and `*_tokens_details` became `[REDACTED]`. Now a usage-count key keeps its
  value when the value is a number, `None`, or a dict or list of those. Strings under usage-count keys
  are now redacted (before, `input_tokens: "..."` or any `*_tokens` string was kept). Credential keys
  (`token`, `access_token`, `refresh_token`, `id_token`, `session_token`, `x-auth-token`, ...) stay
  redacted whatever the value.
- **Fixed:** sealing wrote the absolute blob store path into `metadata.blob_store`, leaking the
  producer's user name and directory layout into shared evidence. It is now relative to the working
  directory, or left out when the store is outside it. Blobs are still found in the same process; in
  a new process, pass `--blob-root` for a store outside the working directory. Bundles sealed by 2.2
  keep their path and still verify. Default recordings now hash differently from 2.2 because of this
  metadata change.


### Recipient experience

- New error types `SignatureMismatchError`, `ReceiptMismatchError`, and `PolicyViolationError`. They
  subclass `ChainIntegrityError`, so existing handlers keep working. The handoff helper reports
  them in `error_type`.
- The handoff helper takes `--hmac-key-file` and `--public-key-file`, so recipients no longer read key
  files with shell syntax. `HANDOFF.md`, the README, and the auditor kit guide use them.
- New `sage handoff verify <kit>` (same checks and exit codes as the kit's `verify_handoff.py`) and
  `sage key fingerprint <file>`. `sage handoff <path> --out-dir ...` still builds kits.
- Releases include `sage-verify-<version>.pyz`, a reproducible single-file verifier that needs only
  Python 3.10+. Without `cryptography` it verifies Ed25519 signatures with a bundled pure-Python,
  verification-only implementation checked against RFC 8032 and `cryptography`.
- The missing-`cryptography` message names the installed SAGE version and the exact install command.
- The kit helper is now generated from `sage/handoff_verify.py`, one source for the kit, the CLI, and
  the single-file verifier.

### LangGraph and wider LangChain coverage

- New optional `[langgraph]` extra (pinned `langgraph==1.2.21`) and `constraints/langgraph.txt`.
- The LangChain handler now records LangGraph runs: node and step attributes, subgraph parent links,
  fan-out/fan-in, `ToolNode`, and `interrupt` / `Command(resume=...)`. Interrupted nodes are `cancelled`
  (not errors) with the interrupt payload in `data["langgraph"]`.
- Streaming (`stream`/`astream`) keeps one model span and counts chunks in `data["stream"]`; streamed
  chain inputs are recorded when the run ends.
- `batch`/`abatch` and `RunnableParallel` are supported under one handler.
- Retriever runs are recorded as `retrieval` spans with their documents (redacted like other fields).
- CI runs the integration tests against langchain-core 1.6.13, 1.7.7, and the pinned 1.8.0.

### Release supply chain

- Every GitHub Action is pinned to a commit SHA; workflows default to read-only tokens.
- Tagged releases are built reproducibly (`scripts/repro_check.py`, also run in CI), signed with Sigstore,
  carry SLSA build provenance, and land as a **draft** GitHub release. PyPI publishing uses trusted
  publishing and stays off until the `SAGE_PYPI_ENABLED` repository variable is set.
- New `scripts/verify_release.py` checks a downloaded release: checksums, Sigstore signatures, and
  provenance. Missing tools exit 2 instead of skipping.
- OpenSSF Scorecard and dependency-review workflows; `SECURITY.md` now states response targets.
- `release_check.py` fails when a document title carries a stale `(vX.Y)` stamp.
- `THREAT_MODEL.md` adds receipt substitution, policy downgrade, and release tampering.

### Journal durability modes and faster recording

- New `SageRecorder(journal_durability=...)`: `"span"` (fsync per closed span, the previous behaviour),
  `"batch"` (group commit from a background writer thread; **new default**), `"close"` (fsync only at
  `flush_journal()` or the seal). `SAGE_JOURNAL_DURABILITY` sets the mode when the argument is omitted.
- Loss window on a crash. `span`: nothing that was closed. `batch`: spans closed in the last 50 ms or
  the last 256 spans (`journal_batch_interval_ms`, `journal_batch_max_spans`), plus the commit under way;
  never more than 1,024 uncommitted spans, because `end_span` then waits for the disk. `close`: as
  `batch` for a process crash; anything since the last flush for an operating-system crash or power loss.
- **Behaviour change:** with the default mode, a span is no longer on disk when `end_span` returns.
  Call `rec.flush_journal()` before reading a live journal, or pass `journal_durability="span"`.
- Sealing always flushes, fsyncs, and joins the writer thread. A writer-thread failure is raised as
  `sage.errors.JournalWriteError` from the next `end_span`, `flush_journal()`, or the seal.
- New `SageRecorder.flush_journal()` and `close_journal()`. The adapters and `sage.sdk` helpers accept
  `journal_durability=`.
- The live manifest is replaced once per commit instead of once per span, and its WAL gets one record
  per commit. Record formats are byte-compatible; hashes are identical in every mode
  (`tests/test_recording_hash_stability.py` pins them against the previous recorder).
- Offloaded blobs are fsynced in groups in `batch` / `close` mode, before the journal lines that name
  them. A blob gets its content-address name only after its fsync.
- Recording fast path: redaction patterns are compiled once, sensitive-key checks are cached, spans are
  serialized once for the content hash and the journal line, sanitizing no longer deep-copies the span,
  duplicate payloads within a span are stored once, the blob store no longer resolves real paths on
  every access, and span lookup is by id instead of a scan.
- `scripts/measure_overhead.py`: `--durability {span,batch,close,all}` and `--mode journal`, a per-span
  benchmark swept over payload sizes, JSON output. CI runs it on Linux (`journal-benchmark` artifact).
  The numbers are measurements, not an SLA.


### Redaction coverage

- The redaction policy now applies to every span field that can carry captured text: error message,
  error stack, failure context, events, and span name, in addition to inputs, outputs, attributes, and data.
  Bundle title, root-cause hint, and live-journal manifest metadata are covered too.
- Live-journal sanitization and final sealing share one implementation (`sage.audit.redact_span`).
- Exceptions record their class name (for example `PermissionError`) and a bounded traceback whose frame
  paths are trimmed to the last two components.

### LangChain integration (optional `[langchain]` extra, pinned `langchain-core==1.8.0`)

- `SageLangChainCallback` subclasses LangChain's `BaseCallbackHandler` when installed and handles chat
  models, LLMs, chains, and tools, with explicit `run_id` / `parent_run_id` mapping and per-instance state.
- New `AsyncSageLangChainCallback` for `ainvoke`.
- New `assert_complete()` raises `CaptureIncompleteError` when runs were left open or capture failed.
- Tests run the real LangChain callback manager (`tests/integration_langchain`).

### Handoff kits

- `HANDOFF.md` gives exact recipient steps: venv, the `[sign]` extra for signed kits, key setup for
  bash and PowerShell, and the fingerprint check. `verify_handoff.py` prints `pinned_key_fingerprint`.
- A signed kit verified without `cryptography` now exits `2` (setup) with an install hint that works
  without a checkout, instead of `1` (integrity failure).
- Receipts and verify reports record the running SAGE version from `sage.version` instead of
  installed package metadata (which can be stale in an editable install).
- `create_handoff()` / `sage handoff` enforce an explicit policy exactly as given; missing key material is a
  setup error instead of a silently weaker policy. New `public_key`, `sign`, and `overwrite` options.
- Kits are built in a staging directory and promoted only after verification and receipt generation.
  An existing kit is not overwritten by default, and a failed rebuild leaves it unchanged.
- `verify_handoff.py` binds the receipt to the freshly verified pack (`expect_fingerprint`, bundle hash,
  bundle id, policy digest), requires the receipt, supports `--public-key`, and uses exit codes
  0 (verified), 1 (integrity or policy failure), 2 (setup problem).

### Demonstration and packaging

- `examples/consultancy_demo.py`: synthetic client-support workflow through real LangChain with
  `--scenario success|tool-error|tool-timeout --mode sync|async --out DIR`; persistent kit, separate keys.
- `scripts/recipient_check.py`: installs the built wheel into a fresh environment outside the checkout and
  verifies a kit with no network access.
- CI adds a pinned LangChain integration job and an installed-wheel recipient job.

## 2.2.0 — 2026-07-26

### License

- Relicensed from Apache-2.0 to **FSL-1.1-ALv2** (Functional Source License — same family Sentry uses)
- Competing commercial products/services require a commercial license (see `COMMERCIAL.md`)
- Each version converts to Apache-2.0 two years after availability
- Prior git snapshots that shipped under Apache-2.0 remain Apache for those commits only

## 2.1.1 — 2026-07-26

### OSS launch polish (no outside services)

- **Pinned Ed25519 required** when `--require-signature` / policy `require_pack_signature` (TOFU refused; `--allow-tofu-signature` escape hatch)
- Key ring supports `public_key` / `public_key_env` for Ed25519 pins
- `policies/auditor.json` — strict + signature pin posture
- `examples/auditor_kit.py` + `docs/AUDITOR_KIT.md`
- `scripts/release_check.py` version/docs/policy gate
- Research top-level CLI aliases removed (use `sage research *` only)
- Attribution tests ignored by default pytest (research extra)
- SECURITY / RELEASE / doctor ed25519 pin checks updated

## 2.1.0 — 2026-07-26

### Custody / operator layer

- **Quarantine unpack** (default): extract + verify in staging, then promote; failed verify leaves `out_dir` untouched (`--no-quarantine` escape hatch)
- **Optional Ed25519** pack signatures via `pip install -e '.[sign]'` (`--sign`, `--require-signature`, `SAGE_SIGN_*` / `SAGE_REQUIRE_PACK_SIGNATURE`)
- **`sage doctor`** — environment + mini verify/handoff self-check
- **`sage keygen`** — write local Ed25519 keypair JSON
- Executable **threat-matrix** tests mapped to `THREAT_MODEL.md` adversaries

Core remains stdlib-only; cryptography is an optional extra.

## 2.0.1 — 2026-07-26

### Hardening (fail-closed gaps)

- Live journals recompute content/link hashes (not tip/length only)
- Heal capabilities bind `source_bundle_hash` (+ optional `SAGE_HEAL_KEY` MAC)
- Heal cascade cannot mutate spans outside sealed capability
- CAS digests reject path traversal / non-hex addresses
- Pack extract: no unsafe `extractall` fallback; size/member budgets; streaming blob restore
- Receipts refuse unsigned by default (`--allow-unsigned` escape hatch)
- Policy load rejects unknown fields / wrong format
- CLI `diff`/`replay` verify both sides by default
- Witness tip binds `chain_tip` to artifact
- Journal recovery validates/rebuilds forged chain prefixes
- Span `events` redact + CAS offload before hash

## 2.0.0 — 2026-07-26

### Security-tool freeze

- Stability covenant: frozen formats + stable public API (`COMPATIBILITY.md`)
- Threat model, security policy, verify/handoff runbook
- Multi-OS CI (Ubuntu / Windows / macOS) + release SBOM workflow
- Strict policy profile (`policies/strict.json`)
- Golden framework adapter tests (LangChain-shaped, CrewAI/AutoGen wrappers)
- `sage version` reports package + format IDs
- Apache-2.0 `LICENSE` in tree

### Breaking (semver major)

- Pack default attestation is **v2** (custody-bound). Use `--pack-version 1` for legacy.
- Stable API list is now normative; undocumented imports are unsupported.

## 1.1.0

- Verify policies, receipts, pack v2 custody MAC, key rings, `sage handoff`

## 1.0.0

- Unified `sage verify`, CAS inventory, pack provenance, witness custody

## 0.9.0

- Sanitize-on-close, manifest WAL, `verify-journal`, GHA CI

## 0.8.0 – 0.7.0

- Merkle, pack HMAC, FakeClock, LangChain callback, live journal redact+chain
