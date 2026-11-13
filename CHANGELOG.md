# Changelog

## 2.3.0rc1 — 2026-11-12 (release candidate, not published)

Frozen formats are unchanged; artifacts sealed by 2.2.0 still verify (`tests/fixtures/compat_v2_2_0`).

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
