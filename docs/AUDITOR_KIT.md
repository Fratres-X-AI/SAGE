# Auditor kit (offline verify)

Strongest in-repo custody posture for a third party who does **not** trust the producer UI.

## What you need

1. Evidence pack (`.sage.tar.gz`)
2. HMAC key (or key ring entry) agreed out-of-band
3. **Pinned** Ed25519 public key (never trust only the key embedded in the pack)
4. Policy: `policies/auditor.json` (or `strict.json` without signature requirement)

## Commands

```bash
pip install -e ".[dev]"

export SAGE_PACK_KEY="..."
export SAGE_SIGN_PUBLIC_KEY="..."   # pinned; required with --require-signature

sage doctor
sage verify evidence.sage.tar.gz \
  --policy policies/auditor.json \
  --hmac-key "$SAGE_PACK_KEY" \
  --witness \
  --require-signature \
  --public-key "$SAGE_SIGN_PUBLIC_KEY" \
  --receipt verify.receipt.json

sage verify-receipt verify.receipt.json --verify-key "$SAGE_PACK_KEY"
```

## Demo (local)

```bash
python examples/auditor_kit.py
```

## Explicit non-claims

- Pinning proves the pack matches a known verifier key — not that the agent told the truth.
- HMAC/Ed25519 without HSM/KMS is software custody. See `THREAT_MODEL.md`.
