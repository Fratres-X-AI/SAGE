# Redaction and the pre-share leak check

SAGE removes secrets from captured data before anything is hashed or written. This page covers
what the default rules remove, the extra detectors you can turn on, and `sage scan`, which checks a
finished pack, bundle, or journal before you share it.

## Default rules (always on)

- **Keys.** A dict value is replaced by `[REDACTED]` when its key contains `api_key`,
  `authorization`, `cookie`, `credential`, `password`, `secret`, or `token`.
- **Token counts are kept.** A key that names a usage count (`input_tokens`, `cached_tokens`,
  `max_tokens`, `llm.token_count.prompt`, `input_tokens_details`, `token_usage`, ...) keeps its
  value, but only while the value is a number, `None`, or a dict or list of those. Any string under
  such a key is still redacted. Keys that name a credential stay redacted even when the value is a
  number: `token`, `access_token`, `refresh_token`, `id_token`, `session_token`, `x-auth-token`,
  `bearer token`, and any key that also contains a credential word such as `access`, `refresh`,
  `auth`, `session`, `secret`, `api_key`, `csrf`, `oauth`, `jwt`, `private`, or `cookie`.
- **Values.** Text matching `sk-` followed by 8 or more key characters, or `Bearer <credential>`, is
  replaced wherever it appears.
- You can replace the key list and value patterns per recorder with
  `redaction_policy={"key_fragments": [...], "value_patterns": [...]}`.

## Detectors (off by default)

Turn detectors on per recorder. Matches become `[REDACTED]` before hashing, like the default rules,
and each one is logged in `bundle.redactions` as `detector:<rule id>` with its JSON path (never the
value).

```python
SageRecorder(title="run", redaction_policy={"detectors": ["aws_access_key_id", "jwt", "email"]})
SageRecorder(title="run", redaction_policy={"detectors": ["all"]})
```

An unknown rule id raises `ValueError` the first time redaction runs. With no detectors, redaction
output and bundle hashes are byte-identical to SAGE 2.2 (`tests/test_redaction_detectors.py` pins
this).

| Rule id | Catches | Does not flag |
| --- | --- | --- |
| `openai_key` | `sk-`, `sk-proj-`, `sk-svcacct-`, `sk-admin-` keys (20+ characters after the prefix) | `sk-ant-` (see below), short `sk-` strings |
| `anthropic_key` | `sk-ant-` keys | |
| `aws_access_key_id` | `AKIA` and `ASIA` followed by 16 uppercase letters or digits | the secret access key itself (it has no prefix; `high_entropy` may catch it) |
| `github_token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens, `github_pat_` tokens | |
| `slack_token` | `xoxa-`, `xoxb-`, `xoxp-`, `xoxo-`, `xoxs-`, `xoxr-` tokens | |
| `google_api_key` | `AIza` followed by 35 characters | |
| `stripe_key` | `sk_live_`, `rk_live_`, `sk_test_`, `rk_test_` | publishable `pk_` keys |
| `private_key_pem` | `-----BEGIN ... PRIVATE KEY-----` through the matching END line | public keys, certificates |
| `jwt` | three base64url parts whose header and payload start with `eyJ` | |
| `bearer_token` | `Bearer <credential>` (also a default rule) | |
| `email` | email addresses | file names such as `logo@2x.png`, `pkg@1.2.3` versions |
| `card_number` | 13 to 19 digit card numbers with a known issuer prefix (Visa, Mastercard, Amex, Discover, JCB, Diners) that pass the Luhn check, as text or as integers | nanosecond or millisecond timestamps, order numbers, numbers that fail Luhn |
| `high_entropy` | random-looking tokens: 24+ characters, at least 2 uppercase, 2 lowercase and 2 digits, Shannon entropy of 4.0 bits per character or more | hex digests, UUIDs, padded base64 of 16/20/32/48/64-byte digests and ids, kebab or snake identifiers made of words, any value under a key ending in `id`, `hash`, `digest`, `sha256`, `checksum`, `fingerprint`, `sig`, `signature`, `public_key`, `nonce` |
| `local_path` | absolute paths that name a user or machine: `C:\...` (any drive), `/home/...`, `/Users/...`, `/root/...` | relative paths, URLs such as `https://host/Users/1` |

False positives: the guards above are tested against token counts, sha256 / sha1 / md5 hex digests,
UUIDs, span and trace ids (hex and base64), blob digests, version strings, timestamps, and model
names (`tests/_redaction_corpus.py`). `high_entropy` is the noisiest rule: it can redact a random
id stored under a key that does not say `id`, and it misses short or low-entropy secrets. Turn on
the provider rules you need first and add `high_entropy` when over-redaction is acceptable.

Redaction does not scan dict keys. A secret used as a key stays in the bundle; `sage scan` reports it.

## `sage scan`: check before you share

```bash
sage scan evidence.sage.tar.gz
sage scan bundle.sage.json --blob-root .sage/blobs
sage scan ./journal --json
sage scan evidence.sage.tar.gz --rule aws_access_key_id --rule email
```

The scan reads everything a recipient gets: journal files, `pack.json`, the witness log, the sealed
metadata, and every content-addressed blob. For a bundle or journal it also reads the blobs it
references, from `--blob-root` or the store it was sealed with. It runs every detector above (on by
default here, whatever the recording used), the default value patterns (`value_pattern`), and
`sensitive_key` (a credential-named key that still holds text, for example in a bundle sealed with
`redact=False`). Dict keys are checked too.

Each finding gives the rule id and the location: file member, line (for `.jsonl` files), span id,
and JSON path. **The scan never prints a value or any part of one.** It prints only the length and
the first 8 hex characters of the value's SHA-256, so you can tell whether two findings are the same
value. A key that matched a rule shows as `<key #N>` in paths.

Exit codes: `0` no findings, `1` findings, `2` setup or usage error (path missing, not a SAGE
artifact, unreadable pack, unknown rule).

Findings in a sealed artifact cannot be removed by editing it: the hashes would no longer verify.
Record again with the right redaction policy, then pack again.

`sage handoff` runs the same scan on the pack it builds. Findings print a warning on stderr (counts
and rule ids only) and the kit is still built. Pass `--fail-on-findings` to refuse to build it
(exit 1). The Python API raises `HandoffLeakError` with `fail_on_findings=True` and otherwise emits
a `HandoffLeakWarning`, or calls `on_scan_findings` if you pass one.

## Local paths in sealed metadata

SAGE 2.2 and earlier wrote the absolute blob store path into `metadata.blob_store`, which put the
producer's user name and directory layout in shared evidence. From 2.3.0rc1, `blob_store` is
written relative to the working directory, or left out when the store is outside it. Reading still
works: SAGE first uses the store the bundle was sealed with in the same process, then
`metadata.blob_store`, then the default `.sage/blobs`. For a store outside the working directory,
pass `--blob-root` to `sage pack`, `sage handoff`, `sage verify`, or `sage scan` in a new process.
Old bundles keep their absolute path (changing it would break their hashes); `sage scan` reports it
as `local_path`.
