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
