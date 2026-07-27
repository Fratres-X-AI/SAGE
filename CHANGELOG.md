# Changelog

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
