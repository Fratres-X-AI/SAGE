# Security Policy

SAGE is developed as a **fail-closed forensic / security tool**.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.1.x | Yes (current) |
| 2.0.x | Security fixes; upgrade to 2.1.x |
| 1.x | Security fixes only until 2026-12-31; migrate to 2.x |
| < 1.0 | No |

## Reporting a vulnerability

Email or open a private advisory with:

1. SAGE version (`sage version`)
2. Minimal reproducer (artifact + command)
3. Impact (integrity bypass, secret leak, DoS in verify, etc.)

Do **not** open a public issue for key-material or bypass reports until a fix is released.

## Security invariants (regression bar)

- Compact verify before rehydrate (hash binding).
- Redaction / sanitize before hashing or journal append.
- Pack v2 MAC covers content digest **and** custody anchors.
- `--require-signature` requires a **pinned** public key (TOFU refused).
- Missing/wrong HMAC or policy violation → non-zero exit.
- Torn journals refuse `verify`; recovery is explicit.
- Quarantine unpack: failed verify leaves destination untouched.
- Research commands (`sage research *`) are **not** custody claims.

See `THREAT_MODEL.md`, `docs/VERIFY_RUNBOOK.md`, and `docs/AUDITOR_KIT.md`.
