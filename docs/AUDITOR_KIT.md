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
  --witness \
  --require-signature \
  --public-key="$SAGE_SIGN_PUBLIC_KEY" \
  --receipt verify.receipt.json

sage verify-receipt verify.receipt.json --verify-key "$SAGE_PACK_KEY"
```

## Demo (local)

```bash
python examples/auditor_kit.py                # quick in-memory loop (temporary output)
python examples/consultancy_demo.py --scenario tool-error --out demo-runs/run-01   # persistent kit
```

## Handoff kits

`sage handoff` (or `create_handoff()`) builds a directory with the pack, `policy.json`,
`verify.receipt.json`, `verify_handoff.py`, and `HANDOFF.md`:

```bash
sage handoff incident.journal --out-dir kit --policy policies/auditor.json \
  --hmac-key-file keys/hmac.key --sign --public-key="$SAGE_SIGN_PUBLIC_KEY"
```

- The policy you pass is enforced as given. Missing HMAC key or signature pin is a setup error
  (exit 2), never a weaker policy.
- The kit is built in staging and promoted only after verification; an existing kit is not replaced
  unless you pass `--overwrite`.

The recipient installs the SAGE wheel (no checkout, no LangChain needed; add `[sign]` when the
policy requires signatures, which installs `cryptography`), then runs the helper from the kit
directory, pointing it at the key files (`<keys>`: where the separately received key files are; the
same commands work in bash and PowerShell):

```bash
python -m pip install "sage_incident_bundles-<version>-py3-none-any.whl[sign]"
cd kit
python verify_handoff.py --hmac-key-file <keys>/hmac.key --public-key-file <keys>/ed25519.public.txt
```

`sage handoff verify <kit> --hmac-key-file ... --public-key-file ...` does the same from any
directory. The output includes `pinned_key_fingerprint` (SHA-256 of the urlsafe-base64-decoded key);
compare it with the fingerprint received out of band, which `sage key fingerprint <file>` also
prints. A signed kit verified without `cryptography` installed exits `2` (setup), not `1`, and the
message names the installed SAGE version and the exact install command.

**No install at all.** Each release includes `sage-verify-<version>.pyz`, a single file with the SAGE
verification code inside. It needs only Python 3.10 or newer and no packages; without `cryptography`
it checks Ed25519 signatures with a bundled pure-Python verifier (RFC 8032, verification only,
non-canonical signatures rejected):

```bash
python sage-verify-<version>.pyz <kit> --hmac-key-file <keys>/hmac.key --public-key-file <keys>/ed25519.public.txt
```

Check the file with `scripts/verify_release.py` (or its `SHA256SUMS.json` entry) before using it.

On failure, `error_type` names what failed: `SignatureMismatchError`, `ReceiptMismatchError`,
`PolicyViolationError`, or `ChainIntegrityError` / `BlobIntegrityError` for altered evidence. All
four subclass `ChainIntegrityError`, so existing `except ChainIntegrityError` code keeps working.

`verify_handoff.py` verifies the pack under `policy.json`, then checks that the receipt's MAC is
valid **and** that its fingerprint, bundle hash, bundle id, and policy digest match the fresh
verification. Exit codes: `0` verified, `1` integrity/policy/receipt failure, `2` setup problem.

Provision key material outside the kit: the HMAC key and the producer's public key (confirm its
SHA-256 fingerprint out of band). Signing private keys never leave the producer. HMAC proves that a
holder of the shared key produced the MAC; only the signature ties the pack to the private-key holder.

## Explicit non-claims

- Pinning proves the pack matches a known verifier key — not that the agent told the truth.
- HMAC/Ed25519 without HSM/KMS is software custody. See `THREAT_MODEL.md`.
