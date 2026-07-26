# SAGE Threat Model (v2.0)

SAGE is an **agent incident forensics** toolkit: portable, redactable, hash-chained evidence you can verify without trusting the producer’s UI.

This is a security tool. Claims are scoped to **integrity and custody of recorded artifacts**, not to solving root-cause analysis.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Compact span content (redacted + CAS refs) | What `bundle_hash` / chain links bind |
| CAS blobs under content digests | Large payloads without stuffing the chain |
| Journal (`spans.jsonl` + `chain.jsonl` + sealed manifest) | Crash-safe recording surface |
| Pack (`.sage.tar.gz` + `pack.json`) | Portable handoff unit |
| Witness log (`witness.jsonl`) | Append-only custody actions |
| Verify receipts | Proof a specific artifact was verified under a policy |
| HMAC keys (`SAGE_PACK_KEY` / `SAGE_WITNESS_KEY` / `SAGE_VERIFY_KEY`) | Attestation secrets |

## Trust boundaries

1. **Recorder host** — process that saw plaintext before sanitize-on-close / redact.
2. **Blob store** — disk/object store holding CAS bytes.
3. **Verifier host** — auditor machine with keys + policy.
4. **Transport** — email, ticket, S3, etc. carrying packs/handoffs.

Hashes and HMACs prove **artifact integrity under a key/policy**, not honesty of the original agent or model.

## Adversaries

| Adversary | Goal | SAGE control |
|-----------|------|----------------|
| Tamperer with pack bytes | Alter spans/blobs unnoticed | `content_digest`, pack HMAC v2, CAS verify |
| Journal forger | Rewrite tip/merkle/seal | `manifest_seal`, merkle, `require_verified` |
| Witness stripper | Remove custody trail but keep pack MAC | Pack v2 binds `witness_tip` |
| Key thief | Forge new attestations | Key rotation via `key_id` / key ring; treat as full compromise |
| TOFU signer | Ship self-signed pack that verifies against embedded pubkey | `--require-signature` demands pinned `SAGE_SIGN_PUBLIC_KEY` / key ring |
| Live-carcass presenter | Pass CI on unsealed journal | `--require-sealed` / policy `forbid_live_journal` |
| Secret leaker via export | Ship API keys in evidence | Redact-before-hash + sanitize-on-close |
| Split-brain writer | Two owners same `trace_id` | Trace registry + file locks |

## Explicit non-goals (what SAGE does **not** prove)

- That the agent’s tools/LLM told the truth at runtime.
- That attribution/`sage research` found the true root cause.
- Confidentiality against an attacker who holds HMAC keys.
- Availability (this is not a SIEM).
- Non-repudiation against a compromised signing host (HMAC ≠ hardware-backed identity).

## Verify posture (production default)

```text
sage verify ARTIFACT \
  --require-sealed \
  --witness \
  --policy policies/strict.json \
  --hmac-key "$SAGE_PACK_KEY" \
  --receipt verify.receipt.json
```

Fail-closed exit codes: `0` ok · `1` integrity/policy · `2` recoverable fault.

## Residual risks

- Secrets exist in memory until span close (sanitize-on-close mitigates after end).
- Unpack rewrites local `blob_store` metadata → local seal hash may differ; custody uses pack `bundle_hash`.
- Torn JSONL requires recovery, not verify.
- Multi-tenant deployments must isolate key rings; never commit key material.
