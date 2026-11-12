# Security Policy

SAGE is developed as a **fail-closed forensic / security tool**.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.3.x (candidate `2.3.0rc1`) | Release candidate: test it; report issues against it |
| 2.2.x | Yes (current release) |
| 2.1.x | Security fixes; upgrade to 2.2.x |
| 2.0.x | No; upgrade to 2.2.x |
| 1.x | Security fixes only until 2026-12-31; migrate to 2.x |
| < 1.0 | No |

## Reporting a vulnerability

Open a private security advisory on GitHub (Security tab, "Report a vulnerability") with:

1. SAGE version (`sage version`)
2. Minimal reproducer (artifact + command), using synthetic data
3. Impact (integrity bypass, secret leak, DoS in verify, etc.)

Do **not** open a public issue for key-material, redaction, or bypass reports until a fix is released.

## Security invariants (regression bar)

- Compact verify before rehydrate (hash binding).
- Redaction / sanitize before hashing or journal append, across every text-bearing span field
  (inputs, outputs, attributes, data, events, error message and stack, failure context, name).
- Pack v2 MAC covers content digest **and** custody anchors.
- `--require-signature` requires a **pinned** public key (TOFU refused).
- Missing/wrong HMAC or policy violation → non-zero exit.
- An explicit verification policy is never weakened to fit missing key material.
- Handoff receipts are checked against the freshly verified pack and policy.
- Torn journals refuse `verify`; recovery is explicit.
- Quarantine unpack: failed verify leaves destination untouched.
- Research commands (`sage research *`) are **not** custody claims.

Redaction applies the configured key and value-pattern rules. It does not detect every kind of
sensitive data, and it does not erase values from process memory outside SAGE's own records.

See `THREAT_MODEL.md`, `docs/VERIFY_RUNBOOK.md`, and `docs/AUDITOR_KIT.md`.
