# SAGE evidence format, version 2.3

Status: normative for SAGE 2.3. This document defines the bytes SAGE writes and the checks a verifier
performs. An independent implementation that follows it produces and accepts the same artifacts as
the reference implementation (`src/sage`).

The key words MUST, MUST NOT, SHOULD, and MAY are used as described in RFC 2119.

Conformance is tested: `tests/vectors/` holds frozen artifacts with expected results, and
`tests/vectors/reference_check.py` recomputes every hash and MAC in this document using only the
Python standard library, without importing SAGE. See [Conformance](#11-conformance).

## 1. Overview

SAGE records an agent run as a list of **spans**. Sealing a recording produces:

- a **bundle**: the spans plus run metadata, a hash chain over the spans (the **audit chain**), and a
  **bundle hash** over everything;
- stored either as one JSON file (`*.sage.json`) or as a **journal** directory;
- optionally transported as a **pack** (`*.sage.tar.gz`): a journal, its offloaded payloads
  (**blobs**), a **witness log**, and `pack.json`, which carries an HMAC attestation and/or an Ed25519
  signature;
- optionally accompanied by a **verification receipt** that binds a verification result to one pack
  and one policy.

Integrity without a key only detects accidental corruption: anyone can recompute plain SHA-256
hashes. Tamper resistance comes from the HMAC key (shared secret) or the Ed25519 signature checked
against a public key the verifier obtained out of band.

## 2. Encodings

### 2.1 Hashes and identifiers

- All hashes are SHA-256, written as 64 lowercase hexadecimal characters ("hex digest").
- `ZERO` is 64 `0` characters.
- HMACs are HMAC-SHA-256, written as a hex digest. An HMAC key given as text is used as its UTF-8
  bytes. A key read from a file is the file's text with leading and trailing whitespace removed.

### 2.2 Canonical JSON

Two canonical encodings are used. Both are the output of Python's
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=...)` and are defined here so
other languages can reproduce them.

- **CJ-U** (`ensure_ascii=False`), then encoded as UTF-8. Used for span content hashes, audit chain
  links, the bundle hash, the manifest seal, and JSON blob payloads.
- **CJ-A** (`ensure_ascii=True`), which is pure ASCII. Used for HMAC and signature inputs, the witness
  log, receipts, the policy digest, and the pack content-digest list.

Both encodings follow these rules:

1. No whitespace outside strings. Members are separated by `,`, and keys from values by `:`.
2. Object members are sorted by key, comparing keys as sequences of Unicode code points. This is not
   RFC 8785 (JCS), which sorts by UTF-16 code units; the two differ only for keys containing
   characters above U+FFFF.
3. Strings: `"` and `\` are escaped as `\"` and `\\`. U+0008, U+0009, U+000A, U+000C, and U+000D are
   written as `\b`, `\t`, `\n`, `\f`, and `\r`. Other characters below U+0020 are written as `\u00XX`
   with lowercase hex. `/` is not escaped.
   - In CJ-U, every other character is written as itself.
   - In CJ-A, every character above U+007E, including U+007F, is written as `\uXXXX` with lowercase
     hex. Characters above U+FFFF are written as a UTF-16 surrogate pair, for example `\ud83d\ude00`.
4. `true`, `false`, and `null` are written literally.
5. Integers are written in decimal with no leading zeros or `+`.
6. Floats are written as Python's `repr(float)`: the shortest text that reads back as the same double.
   Exponents are written as `e-05` or `e+16`. A float that holds an integer value keeps a `.0` (`100.0`).
   A float and an integer with equal value are different values (`1.0` is not `1`).
7. Producers MUST NOT emit NaN or infinities. A verifier MAY reject them.

`H_U(v)` means SHA-256 over the CJ-U bytes of `v`, and `H_A(v)` means the same over the CJ-A bytes.

### 2.3 Files

- JSON files are UTF-8 without a byte-order mark.
- JSON Lines files (`*.jsonl`) hold one JSON object per line, ending with LF. Writers MAY end lines
  with CRLF, and readers MUST accept both. Each line is the CJ-A encoding of the object.
- Pretty-printed files (`manifest.sage.json`, `pack.json`, `verify.receipt.json`, `*.sage.json`) are
  `json.dumps(value, indent=2, sort_keys=True)`. Their whitespace carries no meaning: only the parsed
  value is hashed, never the file bytes. The exception is the pack content digest
  ([section 7.3](#73-content-digest)).

## 3. Spans

### 3.1 Normal form

A span is a JSON object with exactly these 19 members:

| Member | Type |
| --- | --- |
| `span_id` | non-empty string, unique in the bundle |
| `parent_id` | string or `null` |
| `trace_id` | non-empty string |
| `type` | one of `agent`, `chain`, `embedding`, `evaluator`, `guardrail`, `human`, `llm`, `policy`, `prompt`, `reranker`, `retrieval`, `tool`, `handoff`, `custom` |
| `kind` | the upper-case mirror of `type` (`retrieval` → `RETRIEVER`, otherwise `type` upper-cased) |
| `name` | non-empty string |
| `start_time` | string (RFC 3339 UTC with microseconds and `Z`, for example `2026-01-01T00:00:00.000000Z`) |
| `end_time` | string or `null` |
| `status` | one of `ok`, `error`, `cancelled`, `timeout` |
| `error` | `null` or `{"type": string, "message": string}`, plus `"stack": string` when a stack exists |
| `agent_id`, `agent_role` | string or `null` |
| `attributes`, `data`, `inputs`, `outputs` | objects |
| `events` | array |
| `is_suspected_root_cause` | boolean |
| `contribution_score` | number or `null` |
| `failure_context` | string or `null` |

`data` carries type-specific members, which MUST be present:

| `type` | Required members of `data` |
| --- | --- |
| `llm` | `model`, `input`, `output`, `parameters`, `usage` (plus `finish_reason`) |
| `tool` | `tool_name`, `input`, `output`, `success`, `side_effects` (plus `latency_ms`) |
| `retrieval` | `query`, `documents`, `source` |
| `policy` | `policy_name`, `rule_id`, `decision`, `reason`, `checked_input` |
| `handoff` | `from_agent`, `to_agent`, `context_passed`, `goal`, `plan_step`, `next_action`, `state_hash` |
| `agent` | `goal`, `plan_step`, `next_action`, `state_hash` |
| others | `input`, `output` |

The reference implementation fills these members, with defaults, when a span is created. The
defaults are defined by `sage.schema.ensure_typed_data`.

**Normal form rule.** A stored span MUST be in normal form: reading it with the reference reader and
writing it back produces the same CJ-U bytes. A verifier MUST reject a span that is not in normal
form, for example one with an unknown member, a missing member, or a value of the wrong JSON type.
Without this rule, stored content outside the normalized fields would not be bound by any hash.

### 3.2 Span content hash

`content_hash(span) = H_U(span)`, computed over the normal-form object.

### 3.3 Order

Spans in a bundle are ordered by `(start_time, span_id)`, comparing the strings by code point.

### 3.4 Sequence stamps

Spans recorded by SAGE carry `attributes["sage.seq"]` (a non-negative integer, unique in the bundle)
and `attributes["sage.mono_ns"]` (an integer). When stamps are present, a verifier MUST check three
things:

- every `parent_id` names a span in the bundle;
- the parent's `sage.seq` is lower than the child's;
- the parent's `sage.mono_ns` is not greater than the child's.

Spans without stamps (bundles from older importers) skip these checks.

## 4. Blobs

A payload whose UTF-8 size is at least the offload threshold (1024 bytes by default) is replaced by
a **blob reference**:

```json
{"$sage_blob": "<hex digest>", "size": 2048}
```

- A string payload's blob is the string's UTF-8 bytes.
- An object or array payload's blob is the CJ-U bytes of the value.
- The digest is the SHA-256 of the blob bytes. `size` is their length.
- Containers whose keys start with `$` are never offloaded.

The blob reference, not the payload, is what the span hashes cover. A verifier MUST check that every
referenced blob is present and that its bytes hash to its digest. When reading a payload back, the
reader parses the blob as JSON and uses the text unchanged if parsing fails.

Known limitation: a string payload that is itself valid JSON text (for example `"123"`) reads back
as the parsed value. Integrity is unaffected, because the reference is what is hashed.

A local blob store MAY gzip blobs of 64 KiB or more on disk. The digest is always over the
uncompressed bytes. Blobs inside a pack are never compressed.

## 5. Audit chain and bundle hash

### 5.1 Chain links

For spans `s[0] … s[n-1]` in order, link `i` is:

```json
{
  "index": i,
  "span_id": s[i].span_id,
  "span_type": s[i].type,
  "span_name": s[i].name,
  "timestamp": s[i].end_time or s[i].start_time or "",
  "prev_hash": ZERO if i == 0 else link[i-1].hash,
  "span_hash": content_hash(s[i]),
  "content_hash": content_hash(s[i]),
  "parent_id": s[i].parent_id,
  "parent_content_hash": content_hash(parent) if s[i].parent_id names a span in the bundle else null,
  "hash": H_U(link without "hash")
}
```

`span_hash` and `content_hash` are always equal; both are kept for older readers. The **chain tip**
is `link[n-1].hash`, or `ZERO` for an empty chain.

### 5.2 Merkle root

`merkle(leaves)` over a list of hex digests:

- an empty list gives `ZERO`;
- otherwise, while more than one node remains, the last node is duplicated if the count is odd, and
  each pair is replaced by `SHA-256(ASCII(left_hex + right_hex))` as a hex digest;
- a single leaf is its own root.

The chain merkle root is `merkle([link.hash for each link])`. The duplication rule means a list and
the same list with its last leaf repeated give the same root. The merkle root never stands alone: the
chain links and the blob inventory are always checked in full.

### 5.3 Bundle object

```json
{
  "schema_version": "1.0",
  "bundle_id": string,
  "title": string,
  "created_at": string,
  "source": {"framework": string, "run_id": string, "environment": string},
  "status": "completed" | "failed" | "partial",
  "root_cause_hint": string | array | null,
  "metadata": object,
  "spans": [span, ...],
  "redactions": [{"path": string, "reason": string}, ...],
  "redaction_policy": object,
  "audit": {"chain": [link, ...], "bundle_hash": hex},
  "run_id": source.run_id,
  "audit_chain": audit.chain
}
```

`run_id` and `audit_chain` are mirrors for older readers. A `*.sage.json` file MUST be in normal form
as a whole, by the same rule as spans ([section 3.1](#31-normal-form)). A bundle with
`schema_version` `sage.bundle.v1` is migrated first and is exempt from the normal-form rule.

### 5.4 Bundle hash

`bundle_hash = H_U(B)`, where `B` is the bundle object with three changes:

- `audit.bundle_hash` is replaced by `""`;
- `audit_chain` is removed;
- `run_id` is kept.

### 5.5 Redaction

Redaction runs before any hash is computed, so the hashes cover redacted content. The rules applied
are recorded in `redaction_policy`. `redactions` lists each redacted path and the rule that matched;
it never lists the value. The rules themselves are outside the scope of this format, and verifiers
do not re-run them.

## 6. Journal directory

A sealed journal is a directory with these files:

| File | Content |
| --- | --- |
| `spans.jsonl` | one span per line, in order |
| `chain.jsonl` | one chain link per line, same order |
| `manifest.sage.json` | the manifest |
| `witness.jsonl` | optional, the witness log ([section 8](#8-witness-log)) |

### 6.1 Manifest

The manifest holds every bundle member except `spans`, `run_id`, and `audit_chain`. Its `audit`
member is `{"chain": [...], "bundle_hash": hex}`. It also holds:

| Member | Value |
| --- | --- |
| `span_count` | number of spans |
| `span_ids` | span ids in order |
| `chain_tip` | the chain tip |
| `merkle_root` | the chain merkle root |
| `chain_file`, `spans_file` | `"chain.jsonl"`, `"spans.jsonl"` |
| `manifest_seal` | `H_U(manifest without "manifest_seal")` |

`metadata` of a sealed journal contains `"storage": "sage.journal.v1"`, `"spans_file"`, and
`"chain_file"`, and does not contain `live_recording`.

### 6.2 Verifying a sealed journal

A verifier MUST reject the journal unless all of these hold:

1. Every line of `spans.jsonl` and `chain.jsonl` is complete and parses. A torn last line is a
   recoverable fault (exit code 2), not an accepted journal.
2. `manifest_seal` matches.
3. `chain_tip` equals the last line of `chain.jsonl`, and `merkle_root` equals the chain merkle root.
4. The two files have the same number of lines.
5. Every span is in normal form and valid ([section 3.1](#31-normal-form)), and span ids are unique.
6. The chain recomputed from the spans ([section 5.1](#51-chain-links)) equals `chain.jsonl`, and
   the bundle hash recomputed from the manifest and the spans equals `audit.bundle_hash`.
7. Parent and sequence checks pass ([section 3.4](#34-sequence-stamps)).

### 6.3 Live journals

While a recording runs, the manifest carries `"live_recording": true` and `"status": "partial"`.
`manifest.wal.jsonl` holds successive manifest snapshots, each with an extra `wal_ts` member.

A live journal has no bundle hash. A verifier checks it only on request:

- each chain link must equal the link recomputed from the spans written so far;
- `chain_tip` must match;
- spans must be in normal form.

Policies forbid live journals by default. After a crash, recovery keeps the longest prefix in which
spans, chain links, and the manifest agree. Recovery never reorders spans and never creates them.

## 7. Pack

### 7.1 Layout

A pack is a gzip-compressed tar archive with one top-level directory:

```text
sage_artifact/
  pack.json
  journal/spans.jsonl
  journal/chain.jsonl
  journal/manifest.sage.json
  journal/witness.jsonl
  blobs/<hex digest>        one file per referenced blob, uncompressed
```

A verifier MUST extract safely and reject the archive if:

- any member path is absolute or contains `..`;
- a member is a link, device, or FIFO;
- a member would land outside the extraction directory;
- there are more than 10,000 members;
- a member is larger than 256 MiB;
- the total size is larger than 512 MiB.

A verifier MUST also read the whole gzip stream and check its CRC-32 and length trailer before it
extracts, and reject a damaged archive as an integrity failure. The integrity checks in
[section 7.6](#76-verifying-a-pack) cover the extracted members only. The archive bytes themselves
are not bound: gzip header fields (for example the mtime) and tar metadata can change without
failing verification. To pin the exact file, compare its SHA-256 with a value from the producer.

### 7.2 `pack.json`

| Member | Value | Bound by HMAC and signature |
| --- | --- | --- |
| `format` | `"sage.pack.v2"` (`"sage.pack.v1"` for legacy packs) | |
| `bundle_hash` | bundle hash of the packed journal | yes |
| `merkle_root` | chain merkle root of the packed journal | yes |
| `blob_digests` | sorted list of blob digests | through `blob_merkle` |
| `blob_merkle` | `merkle(blob_digests)` | yes |
| `blob_count` | `len(blob_digests)` | |
| `content_digest` | [section 7.3](#73-content-digest) | yes |
| `witness_tip` | `record_hash` of the last witness record, or `"no_witness"` | yes |
| `attestation` | [section 7.4](#74-hmac-attestation) | |
| `signature` | [section 7.5](#75-signature) | |
| `bundle_id`, `schema_version`, `sage_version`, `python_version`, `redaction_summary` | informational | no |

Informational members are not authenticated. A verifier MUST NOT use them for a decision or report
them as verified. In particular, the redaction count a verifier reports and checks against a policy
comes from the bundle's `redactions`, which the bundle hash covers.

A v2 `pack.json` MUST contain `format`, `bundle_hash`, `blob_digests`, `blob_merkle`,
`content_digest`, `merkle_root`, and `witness_tip`, and a verifier MUST reject it otherwise. A pack
without `pack.json` MUST be rejected.

### 7.3 Content digest

1. List every regular file under `sage_artifact/` except `pack.json`. Use paths relative to
   `sage_artifact/`, with `/` separators.
2. Sort the paths by their `/`-separated components, compared component by component as code point
   strings. For the file names SAGE writes, this is the same as a plain string sort.
3. Build the array `[[path, sha256_hex(file bytes)], ...]`.
4. `content_digest` is the SHA-256 of that array encoded as CJ-A, keeping the array's order (sorting
   applies to object keys only).

The content digest covers the exact bytes of every file, including whitespace.

### 7.4 HMAC attestation

The custody payload is:

```json
{
  "blob_merkle": ...,
  "bundle_hash": ...,
  "content_digest": ...,
  "merkle_root": ...,
  "witness_tip": ...
}
```

Its values are taken from `pack.json`, with `""` for a missing member, except `content_digest`,
which is the value the verifier recomputed.

```json
"attestation": {"alg": "hmac-sha256", "version": 2, "mac": HMAC(key, CJ-A(custody payload)),
                "witness_tip": ..., "key_id": optional}
```

Version 1 (legacy) computes `mac = HMAC(key, ASCII(content_digest))`.

### 7.5 Signature

```json
"signature": {"alg": "ed25519", "sig": b64u(Ed25519-sign(CJ-A(custody payload))),
              "public_key": b64u(32-byte public key), "key_id": optional}
```

- `b64u` is URL-safe base64 without padding. Readers MUST accept input with or without padding.
- The signature is RFC 8032 Ed25519 over the CJ-A bytes of the same custody payload as section 7.4.
- The public key fingerprint is `sha256_hex(32-byte public key)`.

The `public_key` inside the signature block is a hint, not a trust anchor. When the verifier requires
a signature, it MUST verify against a public key it obtained out of band (a pinned key). It MUST
reject a pack that carries no signature, and it MUST NOT fall back to the embedded key unless the
operator explicitly allowed trust-on-first-use. When a pack carries a signature that is not required,
the verifier MUST still verify it.

### 7.6 Verifying a pack

A verifier MUST reject the pack unless, in this order:

1. Safe extraction succeeds ([section 7.1](#71-layout)) and `pack.json` exists and is an object with
   the required members.
2. The recomputed content digest equals `content_digest`, and `merkle(blob_digests)` equals
   `blob_merkle`.
3. With an HMAC key: `attestation` exists, has `alg` `hmac-sha256`, and its `mac` matches. Comparison
   MUST be constant-time.
4. The signature check passes ([section 7.5](#75-signature)).
5. Every file in `blobs/` is named by a hex digest equal to the SHA-256 of its bytes, and the set of
   names equals `blob_digests`.
6. The journal verifies as sealed ([section 6.2](#62-verifying-a-sealed-journal)).
7. `bundle_hash`, `merkle_root`, and `witness_tip` in `pack.json` equal the packed journal's bundle
   hash, chain merkle root, and the `record_hash` of the last line of `journal/witness.jsonl`.
8. Every blob the spans reference is present and matches its digest.
9. If witness verification is requested, the witness log verifies ([section 8](#8-witness-log)).

## 8. Witness log

`witness.jsonl` is an append-only custody log. Each record is:

```json
{"ts": string, "action": string, "bundle_hash": hex, "chain_tip": hex, "actor": string,
 "prev_hash": ZERO or the previous record's record_hash, "extra": optional object,
 "attestation": optional {"alg": "hmac-sha256", "mac": HMAC(key, CJ-A(record without attestation and record_hash)), "key_id": optional},
 "record_hash": H_A(record without record_hash)}
```

Note that `record_hash` covers `attestation`, while the MAC does not. A verifier MUST reject the log
in any of these cases:

- it is empty or has a torn line;
- any `record_hash` or `prev_hash` link fails;
- an HMAC is required and any record lacks a matching MAC;
- the last record's `bundle_hash` or `chain_tip` differs from the expected value.

Unpacking appends an `unpack` record, so a local copy's log is one record longer than the packed
one.

## 9. Verification policy

A policy is a JSON object with `"format": "sage.verify.policy.v1"` and these optional members:

| Member | Type |
| --- | --- |
| `policy_id` | string |
| `require_sealed`, `forbid_live_journal`, `require_witness`, `require_witness_hmac`, `require_pack_hmac`, `require_pack_v2`, `require_pack_signature`, `require_blob_inventory` | booleans |
| `min_redaction_count`, `min_span_count` | integers |
| `allowed_kinds` | array of `bundle`, `journal`, `pack` |

Unknown members, a wrong format, or wrong types MUST be rejected.

`policy_digest = H_A(policy with every member present, defaults filled)`. The defaults are those of
`sage.policy.VerifyPolicy`. A policy violation is reported as `PolicyViolationError`.

## 10. Verification receipt

A receipt is a pretty-printed JSON object:

```json
{"format": "sage.verify.receipt.v1", "artifact_fingerprint": content_digest (packs) or bundle_hash,
 "kind": ..., "path_basename": ..., "bundle_id": ..., "bundle_hash": ..., "blob_merkle": ...,
 "witness_tip": ..., "pack_format": ..., "policy_id": ..., "policy_digest": ..., "sage_version": ...,
 "verified_at": ..., "ok": true,
 "attestation": {"alg": "hmac-sha256", "mac": HMAC(key, CJ-A(receipt without attestation)), "key_id": optional}}
```

A verifier MUST reject a receipt in any of these cases:

- it is unsigned, unless the policy requires no HMAC;
- its MAC does not match;
- `ok` is not `true`;
- `artifact_fingerprint` differs from the freshly verified pack's `content_digest`;
- `bundle_hash`, `bundle_id`, or `policy_digest` differ from the fresh verification's values.

Each of these is reported as `ReceiptMismatchError`.

## 11. Conformance

### 11.1 Errors and exit codes

Every rejection is a `SageError`. The CLI and the handoff helper map results to exit codes and
`error_type` values:

| Exit | Meaning | `error_type` |
| --- | --- | --- |
| 0 | evidence, policy, and receipt verified | |
| 1 | integrity failure: the evidence does not match | `ChainIntegrityError`, `BlobIntegrityError`, `SignatureMismatchError`, `ReceiptMismatchError`, `PolicyViolationError` |
| 2 | setup problem or recoverable fault: a missing key, missing `cryptography`, an unreadable file, a torn journal tail | `FaultRecoveryError` and setup errors |

Malformed input, such as invalid UTF-8, invalid JSON, wrong JSON types, or a corrupt archive, is an
integrity failure (`ChainIntegrityError`, exit code 1), never an unhandled exception.

### 11.2 Test vectors

`tests/vectors/manifest.json` lists every vector: a directory holding an artifact, the keys and
policy to verify it with, and the expected outcome (`accept`, or `reject` with an `error_type`). The
vectors cover:

- the hash primitives of [section 2](#2-encodings) and [section 5](#5-audit-chain-and-bundle-hash);
- one valid bundle, one valid journal, and one valid signed pack;
- one targeted corruption per rule in sections 6 to 10.

Two runners check them:

- `python tests/vectors/run_vectors.py` checks the reference implementation against every expected
  outcome.
- `python tests/vectors/reference_check.py` recomputes every hash, merkle root, content digest, MAC,
  and witness link of the valid vectors from this document alone, using only the standard library,
  and compares them with the stored values. An implementation in another language can port that
  file.

The vectors use only public test keys: an HMAC key `sage-conformance-hmac-key`, and the RFC 8032
section 7.1 TEST 1 Ed25519 key pair. Never use either for real evidence.

## 12. Versioning

A change to any byte defined here changes the format version. Readers MUST keep accepting earlier
2.x artifacts: `tests/fixtures/compat_v2_2_0` must verify unchanged.
