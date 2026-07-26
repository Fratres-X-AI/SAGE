# Verify & Handoff Runbook (v2.1)

## Record → seal → ship

```bash
# In your agent process
python -c "from sage import SageRecorder; ..."

# Or CLI after export
sage verify incident.sage.json --skip-blobs   # if no CAS refs
sage pack incident.sage.json --out ship.sage.tar.gz --hmac-key "$SAGE_PACK_KEY"
# Optional: also Ed25519-sign (pip install -e '.[sign]')
# export SAGE_SIGN_PRIVATE_KEY=...
# sage pack incident.sage.json --out ship.sage.tar.gz --hmac-key "$SAGE_PACK_KEY" --sign
sage handoff ship.sage.tar.gz --out-dir ./evidence-kit --hmac-key "$SAGE_PACK_KEY"
```

## Auditor re-verify (offline)

HMAC-only (strict):

```bash
cd evidence-kit
export SAGE_PACK_KEY=...          # shared out-of-band
export SAGE_VERIFY_KEY=...        # optional distinct receipt key
python verify_handoff.py
# or
sage verify evidence.sage.tar.gz \
  --policy policies/strict.json \
  --witness \
  --hmac-key "$SAGE_PACK_KEY"
sage verify-receipt verify.receipt.json --verify-key "$SAGE_VERIFY_KEY"
```

Pinned Ed25519 (auditor):

```bash
export SAGE_PACK_KEY=...
export SAGE_SIGN_PUBLIC_KEY=...   # pin — do not trust pack-embedded TOFU key alone
sage verify evidence.sage.tar.gz \
  --policy policies/auditor.json \
  --hmac-key "$SAGE_PACK_KEY" \
  --witness \
  --require-signature \
  --public-key "$SAGE_SIGN_PUBLIC_KEY" \
  --receipt verify.receipt.json
```

See also [`AUDITOR_KIT.md`](AUDITOR_KIT.md) and `python examples/auditor_kit.py`.

## Strict CI gate

Use `policies/strict.json` (HMAC/witness) or `policies/auditor.json` (+ signature pin):

```bash
sage verify "$ARTIFACT" --policy policies/strict.json --hmac-key "$SAGE_PACK_KEY" --witness --receipt "receipts/${CI_COMMIT_SHA}.json"
```

## Do not

- Rehydrate before verify (breaks hash binding).
- Treat live journals as sealed evidence.
- Commit HMAC keys or key rings with inline `material` / private keys.
- Accept `--require-signature` without a pinned public key (TOFU is not authenticity).
- Equate pack HMAC/signature success with “the agent was correct.”
- Run `sage research` results as forensic conclusions.

## Incident response if verify fails

1. Capture the JSON error (`ok: false`).
2. If exit `2`, try `sage audit` / journal recovery — then re-seal.
3. If exit `1`, treat artifact as untrusted; request re-handoff from producer.
4. Preserve the failed bytes + receipt attempt for chain of custody notes.
