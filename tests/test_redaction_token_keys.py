"""The "token" key rule: usage counts stay readable, credentials named *token* stay redacted."""

from __future__ import annotations

import pytest

from sage import redact_bundle
from sage.audit import redact_value
from sage.schema import IncidentBundle, SageSpan

SECRET = "opaque-credential-value-31337"

KEPT_USAGE = [
    ("llm.token_count.prompt", 12),
    ("llm.token_count.completion", 30),
    ("llm.token_count.total", 42),
    ("input_tokens", 12),
    ("cached_tokens", 0),
    ("reasoning_tokens", 7),
    ("max_tokens", 1024),
    ("tokens", 5),
    ("token_count", 3.0),
    ("total_tokens", None),
    ("gen_ai.usage.input_tokens", 12),
    ("inputTokens", 12),
    ("promptTokenCount", 9),
    ("input_tokens_details", {"cached_tokens": 4, "audio_tokens": 0}),
    ("output_tokens_details", {"reasoning_tokens": 7, "accepted_prediction_tokens": None}),
    ("token_usage", {"prompt": 3, "completion": 4, "per_turn": [1, 2]}),
]

ALWAYS_REDACTED_KEYS = [
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "x-auth-token",
    "X-Auth-Token",
    "session_token",
    "bearer token",
    "auth_token",
    "csrf_token",
    "oauth_token",
    "api_token",
    "github_token",
    "slack_bot_token",
    "token_secret",
    "tokenizer_secret",
]


@pytest.mark.parametrize("key,value", KEPT_USAGE)
def test_usage_count_keys_keep_numeric_values(key: str, value: object) -> None:
    redactions: list[dict[str, str]] = []
    assert redact_value({key: value}) == {key: value}
    assert redact_value({key: value}, redacted_paths=redactions) == {key: value}
    assert redactions == []


@pytest.mark.parametrize("key", ALWAYS_REDACTED_KEYS)
@pytest.mark.parametrize("value", [SECRET, 12345, {"value": SECRET}, [SECRET]])
def test_credential_token_keys_stay_redacted(key: str, value: object) -> None:
    assert redact_value({key: value}) == {key: "[REDACTED]"}


@pytest.mark.parametrize("key", [k for k, _v in KEPT_USAGE])
@pytest.mark.parametrize("value", [SECRET, "12", True, {"n": SECRET}, [3, SECRET]])
def test_usage_count_keys_redact_non_numeric_values(key: str, value: object) -> None:
    out = redact_value({key: value})
    assert out == {key: "[REDACTED]"}


def test_other_fragments_still_win_over_usage_shape() -> None:
    assert redact_value({"secret_tokens": 5}) == {"secret_tokens": "[REDACTED]"}
    assert redact_value({"password_tokens": 5}) == {"password_tokens": "[REDACTED]"}
    assert redact_value({"access_tokens": 5}) == {"access_tokens": "[REDACTED]"}


def test_flattened_openinference_counts_survive_the_seal() -> None:
    span = SageSpan(
        type="llm",
        name="chat",
        trace_id="t",
        end_time="2026-01-01T00:00:01Z",
        attributes={
            "llm.token_count.prompt": 12,
            "llm.token_count.completion": 30,
            "http.request.header.x-auth-token": SECRET,
        },
        data={"usage": {"input_tokens": 12, "input_tokens_details": {"cached_tokens": 4}}},
    )
    red = redact_bundle(IncidentBundle(title="t", spans=[span]))
    attrs = red.spans[0].attributes
    assert attrs["llm.token_count.prompt"] == 12 and attrs["llm.token_count.completion"] == 30
    assert attrs["http.request.header.x-auth-token"] == "[REDACTED]"
    assert red.spans[0].data["usage"]["input_tokens_details"] == {"cached_tokens": 4}
    assert [r["path"] for r in red.redactions] == ["spans.0.attributes.http.request.header.x-auth-token"]
