"""Shared canary corpus for the redaction detector and scan tests.

Provider-shaped canaries are assembled at import time so no complete key-shaped literal sits in
the repository (secret scanners on push would otherwise flag these test strings).
"""

from __future__ import annotations

from typing import Any

from sage.schema import SCHEMA_VERSION, IncidentBundle

# 20 to 40 random-looking characters, reused as key bodies.
_BODY = "Qm7rT2vX9kLp4ZsW8nBc3HdF6gJy1"
_BODY36 = "Qm7rT2vX9kLp4ZsW8nBc3HdF6gJy1aE5uN0o"

OPENAI_KEY = "sk-" + "proj-" + _BODY
ANTHROPIC_KEY = "sk-" + "ant-" + "api03-" + _BODY
AWS_ACCESS_KEY_ID = "AK" + "IA" + "Q7RT2VX9KLP4ZSW8"
AWS_SESSION_KEY_ID = "AS" + "IA" + "Q7RT2VX9KLP4ZSW8"
GITHUB_TOKEN = "gh" + "p_" + _BODY36
GITHUB_PAT = "github" + "_pat_" + "11ABCDEFG0" + _BODY
SLACK_TOKEN = "xo" + "xb-" + "1234567890-0987654321-" + _BODY[:24]
GOOGLE_API_KEY = "AI" + "za" + "Sy" + _BODY + "Ab1C"
STRIPE_KEY = "sk" + "_live_" + _BODY
STRIPE_RESTRICTED = "rk" + "_live_" + _BODY
PEM_PRIVATE_KEY = (
    "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + _BODY + "\n-----END " + "RSA PRIVATE KEY-----"
)
JWT = (
    "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkNhbmFyeSJ9"
    + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
EMAIL = "pat.canary@" + "example.org"
CARD_NUMBER = "4111 1111 " + "1111 1111"  # Visa test number, Luhn-valid
HIGH_ENTROPY = "Zq8" + "Lw3Nv7XbR2mKt9PcJ4hYd6Fs"  # 27 chars, mixed case and digits
LOCAL_PATH_WINDOWS = "C:\\" + "Users\\pat\\proj\\.sage\\blobs"
LOCAL_PATH_POSIX = "/" + "home/pat/proj/.sage/blobs"

# Strings that look structured but are not secrets. No detector may flag them.
FALSE_POSITIVE_GUARDS: dict[str, Any] = {
    "sha256_hex": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "sha1_hex": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    "md5_hex": "098f6bcd4621d373cade4e832627b4f6",
    "uuid": "123e4567-e89b-12d3-a456-426614174000",
    "span_id": "span_3f9a1c2b7d4e5f60",
    "trace_id_hex": "0af7651916cd43dd8448eb211c80319c",
    "otel_span_id_b64": "AAECAwQFBgc=",
    "otel_trace_id_b64": "AAECAwQFBgcICQoLDA0ODw==",
    "blob_digest_b64": "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
    "blob_ref": {"$sage_blob": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
    "version": "2.3.0rc1",
    "pkg_version": "openai-agents@0.24.0",
    "timestamp_iso": "2026-11-13T16:43:37.057020Z",
    "timestamp_ns": "1763052217057020000",
    "timestamp_ns_int": 1763052217057020000,
    "epoch_ms": 1763052217057,
    "model": "gpt-4o-mini-2024-07-18",
    "model_2": "claude-3-5-sonnet-20241022",
    "model_3": "Qwen2.5-72B-Instruct-AWQ",
    "image_name": "logo@2x.png",
    "url": "https://api.example.com/v1/Users/123/orders",
    "relative_path": "tests/fixtures/otlp/openinference.otlp.json",
    "phone_like": "+1 415 555 0100",
    "order_number": "4111-2026-0042",
    "camel_identifier": "SageOpenAIAgentsProcessor",
    "redacted": "[REDACTED]",
    "usage": {"input_tokens": 12, "output_tokens": 30, "total_tokens": 42},
    "usage_details": {"input_tokens_details": {"cached_tokens": 4}, "output_tokens_details": {"reasoning_tokens": 7}},
    "token_counts_flat": {"llm.token_count.prompt": 12, "llm.token_count.completion": 30},
}


def golden_bundle() -> IncidentBundle:
    """Deterministic bundle with every canary and guard, for byte-identity checks."""
    # Not under a key like "secrets": the default key rule would redact the whole dict.
    samples = {
        "openai": f"key {OPENAI_KEY}",
        "anthropic": ANTHROPIC_KEY,
        "aws": AWS_ACCESS_KEY_ID,
        "github": GITHUB_TOKEN,
        "slack": SLACK_TOKEN,
        "google": GOOGLE_API_KEY,
        "stripe": STRIPE_KEY,
        "pem": PEM_PRIVATE_KEY,
        "jwt": JWT,
        "email": f"contact {EMAIL}",
        "card": f"card {CARD_NUMBER}",
        "entropy": HIGH_ENTROPY,
        "path": LOCAL_PATH_WINDOWS,
        "password": "hunter2-canary",
        "auth": "Bearer CANARYbearer0123456789",
    }
    # Usage-count keys the token-key fix (2.3.0) now keeps are left out: their output changed on purpose.
    guards = {k: v for k, v in FALSE_POSITIVE_GUARDS.items() if k not in ("token_counts_flat", "usage_details")}
    return IncidentBundle.from_dict(
        {
            "bundle_id": "bundle_golden_0001",
            "schema_version": SCHEMA_VERSION,
            "created_at": "2026-11-13T12:00:00Z",
            "title": f"golden {EMAIL}",
            "status": "failed",
            "source": {"framework": "custom", "run_id": "golden-run", "environment": "test"},
            "metadata": {"owner": EMAIL, "build": "2.3.0rc1"},
            "spans": [
                {
                    "span_id": "span_golden_root",
                    "type": "chain",
                    "name": "root",
                    "trace_id": "golden-trace",
                    "start_time": "2026-11-13T12:00:00Z",
                    "end_time": "2026-11-13T12:00:03Z",
                    "inputs": {"question": "where is order 42?", "samples": samples},
                    "outputs": {"answer": "shipped"},
                },
                {
                    "span_id": "span_golden_llm",
                    "parent_id": "span_golden_root",
                    "type": "llm",
                    "name": "chat",
                    "trace_id": "golden-trace",
                    "start_time": "2026-11-13T12:00:01Z",
                    "end_time": "2026-11-13T12:00:02Z",
                    "status": "error",
                    "error": {"type": "AuthError", "message": f"rejected {OPENAI_KEY} for {EMAIL}"},
                    "attributes": dict(guards),
                    "data": {"model": "gpt-4o-mini-2024-07-18", "usage": {"input_tokens": 12, "total_tokens": 42}},
                    "events": [{"name": "note", "text": f"card {CARD_NUMBER}"}],
                },
            ],
        }
    )
