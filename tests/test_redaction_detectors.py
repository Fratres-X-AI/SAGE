"""Opt-in shape and entropy detectors: canaries, false-positive guards, and byte-identity when off."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

import _redaction_corpus as corpus
from sage import SageRecorder, redact_bundle
from sage.audit import finalize_bundle, redact_value, sha256_digest
from sage.bundle_io import load_bundle
from sage.detectors import ALL_DETECTORS, DETECTORS, apply_detectors, find_spans, luhn_valid, resolve_detector_ids
from sage.schema import IncidentBundle, SageSpan

# Hashes produced by SAGE before the detectors existed (commit a4a1ae0), detectors off.
GOLDEN_REDACT_BUNDLE = "f56a5ceb83f18cf12f704883e88d0df47d2faa5aa04b268172e78a310c43504b"
GOLDEN_FINALIZE = "36e55fb8a70293ad2969f5d5be9b8c0064303e86d7579138f468dc31d06c26d6"
GOLDEN_FINALIZE_NO_REDACT = "fea9c8c979fe0c09e91f566ed4eb015814b11b36ec6d8ba6b99151b60a0ace2c"

POSITIVE: dict[str, list[str]] = {
    "openai_key": [corpus.OPENAI_KEY, "sk-" + corpus._BODY],
    "anthropic_key": [corpus.ANTHROPIC_KEY],
    "aws_access_key_id": [corpus.AWS_ACCESS_KEY_ID, corpus.AWS_SESSION_KEY_ID],
    "github_token": [corpus.GITHUB_TOKEN, corpus.GITHUB_PAT],
    "slack_token": [corpus.SLACK_TOKEN],
    "google_api_key": [corpus.GOOGLE_API_KEY],
    "stripe_key": [corpus.STRIPE_KEY, corpus.STRIPE_RESTRICTED],
    "private_key_pem": [corpus.PEM_PRIVATE_KEY],
    "jwt": [corpus.JWT],
    "bearer_token": ["Bearer CANARYbearer0123456789"],
    "email": [corpus.EMAIL],
    "card_number": [corpus.CARD_NUMBER, "5555-5555-5555-4444", "378282246310005"],
    "high_entropy": [corpus.HIGH_ENTROPY],
    "local_path": [corpus.LOCAL_PATH_WINDOWS, corpus.LOCAL_PATH_POSIX, "/" + "Users/pat/proj"],
}


def _guard_strings(value: Any = None) -> list[tuple[str, str]]:
    """(key, string) pairs from the false-positive corpus, including nested values."""
    value = corpus.FALSE_POSITIVE_GUARDS if value is None else value
    out: list[tuple[str, str]] = []
    for key, child in value.items():
        if isinstance(child, dict):
            out.extend(_guard_strings(child))
        else:
            out.append((key, str(child)))
    return out


def test_every_detector_has_a_positive_canary() -> None:
    assert set(POSITIVE) == set(ALL_DETECTORS)


@pytest.mark.parametrize("rule", ALL_DETECTORS)
def test_detector_positive_canary(rule: str) -> None:
    for canary in POSITIVE[rule]:
        text = f"before {canary} after"
        out, fired = apply_detectors(text, (rule,))
        assert canary not in out, f"{rule} missed its canary"
        assert out.startswith("before ") and out.endswith(" after")
        assert fired == [rule]


@pytest.mark.parametrize("rule", ALL_DETECTORS)
def test_detector_false_positive_guards(rule: str) -> None:
    flagged = [key for key, text in _guard_strings() if find_spans(text, (rule,), key=key)]
    assert flagged == [], f"{rule} flagged non-secret values: {flagged}"


@pytest.mark.parametrize(
    "rule,near_miss",
    [
        ("openai_key", "sk-short"),
        ("anthropic_key", "sk-ant-short"),
        ("aws_access_key_id", "AKIA" + "lowercase0123456"),
        ("github_token", "ghp_" + "tooShort123"),
        ("slack_token", "xoxz-" + "1234567890-abc"),
        ("google_api_key", "AIza" + "short"),
        ("stripe_key", "pk_live_" + corpus._BODY),
        ("private_key_pem", "-----BEGIN PUBLIC KEY-----"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.notjson.sig"),
        ("bearer_token", "Bearer x"),
        ("email", "release@2x.png"),
        ("card_number", "4111 1111 1111 1112"),
        ("high_entropy", "Order-History-For-Acme-Corp-2026-11-13"),
        ("local_path", "https://example.com/home/pat/index.html"),
    ],
)
def test_detector_near_misses(rule: str, near_miss: str) -> None:
    assert find_spans(near_miss, (rule,)) == []


def test_luhn() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_entropy_skips_digest_keys() -> None:
    assert find_spans(corpus.HIGH_ENTROPY, ("high_entropy",), key="content_hash") == []
    assert find_spans(corpus.HIGH_ENTROPY, ("high_entropy",), key="span_id") == []
    assert find_spans(corpus.HIGH_ENTROPY, ("high_entropy",), key="note")


def test_resolve_detector_ids() -> None:
    assert resolve_detector_ids(None) == ()
    assert resolve_detector_ids(["all"]) == ALL_DETECTORS
    assert resolve_detector_ids(["email", "jwt", "email"]) == ("jwt", "email")  # catalog order
    with pytest.raises(ValueError, match="unknown redaction detector"):
        resolve_detector_ids(["nope"])


# --- byte identity when detectors are off ---------------------------------------------------------


def test_detectors_off_redaction_is_byte_identical_to_before() -> None:
    assert sha256_digest(redact_bundle(corpus.golden_bundle()).to_dict()) == GOLDEN_REDACT_BUNDLE
    assert finalize_bundle(corpus.golden_bundle(), offload_blobs=False).audit.bundle_hash == GOLDEN_FINALIZE
    sealed = finalize_bundle(corpus.golden_bundle(), redact=False, offload_blobs=False)
    assert sealed.audit.bundle_hash == GOLDEN_FINALIZE_NO_REDACT


def test_detectors_off_leaves_policy_record_unchanged() -> None:
    red = redact_bundle(corpus.golden_bundle())
    assert "detectors" not in red.redaction_policy
    assert not any(r["reason"].startswith("detector:") for r in red.redactions)
    # Detector-shaped values the default rules do not cover stay as recorded.
    blob = json.dumps(red.to_dict())
    assert corpus.AWS_ACCESS_KEY_ID in blob and corpus.EMAIL in blob


# --- detectors on ---------------------------------------------------------------------------------


def _detector_bundle() -> IncidentBundle:
    bundle = corpus.golden_bundle()
    bundle.redaction_policy = {"detectors": ["all"]}
    return bundle


def test_all_detectors_scrub_every_canary_and_keep_guards() -> None:
    red = redact_bundle(_detector_bundle())
    blob = json.dumps(red.to_dict())
    for rule, canaries in POSITIVE.items():
        for canary in canaries:
            if canary in json.dumps(corpus.golden_bundle().to_dict()):
                assert canary not in blob, f"{rule} canary survived redaction"
    for key, text in _guard_strings():
        if key not in ("token_counts_flat", "usage_details"):
            assert text in blob or text == "[REDACTED]", f"guard {key} was redacted"
    assert red.redaction_policy["detectors"] == list(ALL_DETECTORS)
    reasons = {r["reason"] for r in red.redactions}
    assert {"detector:aws_access_key_id", "detector:email", "detector:card_number", "detector:jwt"} <= reasons
    assert red.title == "golden [REDACTED]"
    assert red.spans[1].error is not None and corpus.EMAIL not in red.spans[1].error.message


def test_tracked_and_untracked_redaction_agree() -> None:
    from sage.audit import resolve_redaction_rules

    fragments, patterns = resolve_redaction_rules({"detectors": ["all"]})
    value = corpus.golden_bundle().to_dict()["spans"]
    tracked = redact_value(value, path="spans", redacted_paths=[], key_fragments=fragments, value_patterns=patterns)
    untracked = redact_value(value, path="spans", key_fragments=fragments, value_patterns=patterns)
    assert tracked == untracked


def test_card_number_stored_as_integer() -> None:
    from sage.audit import resolve_redaction_rules

    fragments, patterns = resolve_redaction_rules({"detectors": ["card_number"]})
    value = {"card": 4111111111111111, "ts": 1763052217057020000, "count": 12}
    out = redact_value(value, key_fragments=fragments, value_patterns=patterns)
    assert out == {"card": "[REDACTED]", "ts": 1763052217057020000, "count": 12}


def test_unknown_detector_in_policy_fails_loudly() -> None:
    bundle = corpus.golden_bundle()
    bundle.redaction_policy = {"detectors": ["aws"]}
    with pytest.raises(ValueError, match="unknown redaction detector"):
        redact_bundle(bundle)


def _tar_text(path: Path) -> str:
    import gzip

    texts = []
    with tarfile.open(fileobj=io.BytesIO(path.read_bytes()), mode="r:*") as tar:
        for member in tar.getmembers():
            if member.isfile():
                raw = tar.extractfile(member).read()  # type: ignore[union-attr]
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
                texts.append(raw.decode("utf-8", errors="replace"))
    return "\n".join(texts)


def test_recorder_with_detectors_keeps_canaries_out_of_journal_export_and_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sage.pack import pack_artifact

    monkeypatch.chdir(tmp_path)
    canaries = [corpus.AWS_ACCESS_KEY_ID, corpus.EMAIL, corpus.JWT, corpus.GITHUB_TOKEN, corpus.CARD_NUMBER]
    rec = SageRecorder(
        title=f"run for {corpus.EMAIL}",
        trace_id="detector-trace",
        journal_dir=tmp_path / "j",
        blob_store=tmp_path / "blobs",
        redaction_policy={"detectors": ["aws_access_key_id", "email", "jwt", "github_token", "card_number"]},
        metadata={"owner": corpus.EMAIL},
    )
    with rec:
        with rec.llm_call("model", inputs={"prompt": f"use {corpus.AWS_ACCESS_KEY_ID} and {corpus.JWT}"}) as llm:
            llm.set_output(text=("long answer " * 200) + corpus.GITHUB_TOKEN)
        try:
            with rec.tool_call("charge", inputs={"card": corpus.CARD_NUMBER}):
                raise RuntimeError(f"declined for {corpus.EMAIL}")
        except RuntimeError:
            pass
    out = rec.export(tmp_path / "bundle.sage.json")
    pack = pack_artifact(tmp_path / "j", tmp_path / "e.sage.tar.gz", hmac_key=b"k" * 32)
    texts = {
        "export": out.read_text(encoding="utf-8"),
        "journal": "\n".join(p.read_text(encoding="utf-8") for p in (tmp_path / "j").glob("*.json*")),
        "blobs": "\n".join(_tar_text(pack).splitlines()),
    }
    for where, text in texts.items():
        for canary in canaries:
            assert canary not in text, f"canary leaked into {where}"
    assert load_bundle(out, verify=True).redaction_policy["detectors"] == [
        "aws_access_key_id", "github_token", "jwt", "email", "card_number"
    ]


def test_detector_redaction_reason_names_rule_not_value() -> None:
    span = SageSpan(type="tool", name="t", trace_id="t", end_time="2026-01-01T00:00:01Z",
                    inputs={"q": f"mail {corpus.EMAIL}"})
    bundle = IncidentBundle(title="t", spans=[span], redaction_policy={"detectors": ["email"]})
    red = redact_bundle(bundle)
    entry = next(r for r in red.redactions if r["reason"] == "detector:email")
    assert entry == {"path": "spans.0.inputs.q", "reason": "detector:email"}
    assert corpus.EMAIL not in json.dumps(red.redactions)


def test_catalog_descriptions() -> None:
    for rule, detector in DETECTORS.items():
        assert detector.rule_id == rule and detector.description
