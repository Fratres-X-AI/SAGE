# SAGE Threat Model (v2.3)

SAGE is an **agent incident forensics** toolkit: portable, redactable, hash-chained evidence you can verify without trusting the producer’s UI.

This is a security tool. Claims are scoped to **integrity and custody of recorded artifacts**, not to solving root-cause analysis.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Compact span content (redacted + CAS refs) | What `bundle_hash` / chain links bind |
| CAS blobs under content digests | Large payloads without stuffing the chain |
| Journal (`spans.jsonl` + `chain.jsonl` + sealed manifest) | Crash-recoverable recording surface; the durability mode sets how many closed spans a crash can lose |
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
| Careless sharer | Hand over evidence that still holds a key, personal data, or a local path the redaction policy missed | `sage scan` pre-share check (also run by `sage handoff`; `--fail-on-findings` blocks the kit). Opt-in detectors redact provider keys, JWTs, emails, card numbers, and high-entropy strings before hashing. The scan reports locations and rule ids, never values. It is pattern-based: a secret with no known shape can pass |
| Split-brain writer | Two owners same `trace_id` | Trace registry + file locks |
| Receipt substituter | Pass off a receipt from a different pack, key, or policy | Receipt binding: bundle hash and id, policy digest, and `expect_fingerprint` are checked against the freshly verified pack |
| Policy downgrader | Verify under a weaker policy than the one requested | An explicit policy is never weakened to fit missing key material; missing material raises `HandoffSetupError` (exit 2) |
| Release tamperer | Ship a modified wheel as an official release | Reproducible builds, `SHA256SUMS.json`, Sigstore signatures, and SLSA provenance; check with `scripts/verify_release.py` |
| Attestation stripper | Delete `pack.json` (MAC and signature) so a pack verifies as an unattested journal | A pack without `pack.json` is refused when a key or signature is required (`SignatureMismatchError` if a signature is required); vector `pack/pack-json-missing` |
| Unbound-field forger | Add or change fields the hashes do not cover (unknown span members, a non-normal span) | Stored spans and bundles must equal their normal form byte for byte (`docs/spec/FORMAT.md` section 3.3) |
| Anchor splicer | Pair a valid `pack.json` with another journal, or edit its anchors | `bundle_hash`, `merkle_root`, and `witness_tip` in `pack.json` are checked against the journal and witness log; `redaction_count` is read from the hash-bound bundle only |
| Malformed-input crasher | Crash or hang the verifier with hostile bytes | Every rejection is a typed `SageError` (exit 1 or 2); property tests, 53 conformance vectors, and scheduled atheris fuzzing (`fuzz/`) hold that contract |

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
  That rewrite is an absolute path on the receiver's machine; re-packing an unpacked journal carries
  it forward (`sage scan` reports it as `local_path`).
- Bundles sealed by SAGE 2.2 and earlier hold the producer's absolute blob store path in
  `metadata.blob_store`. It cannot be removed without breaking their hashes.
- Torn JSONL requires recovery, not verify.
- Under the default `journal_durability="batch"`, a crash loses spans closed in the last group-commit
  window (50 ms or 256 spans by default) plus any commit under way. If the writer falls behind,
  recording blocks once 1024 spans wait, so that is the upper bound. Under `"close"`, an operating-system crash or power loss
  loses everything since the last `flush_journal()`. Recovery returns the intact prefix; it never
  invents or reorders spans. Use `"span"` when every closed span must survive a crash.
- Multi-tenant deployments must isolate key rings; never commit key material.
