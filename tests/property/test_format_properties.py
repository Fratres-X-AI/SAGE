"""Property tests for the evidence format (docs/spec/FORMAT.md).

`HYPOTHESIS_PROFILE=thorough` raises the example counts; the default profile keeps the fast suite fast.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402

from sage.audit import canonical_json, redact_value  # noqa: E402
from sage.errors import SageError  # noqa: E402
from sage.journal import CHAIN_JSONL, MANIFEST_NAME, SPANS_JSONL, verify_journal  # noqa: E402
from sage.merkle import merkle_root  # noqa: E402
from sage.pack import pack_artifact  # noqa: E402
from sage.recorder import SageRecorder  # noqa: E402
from sage.schema import SageSpan  # noqa: E402
from sage.verify import verify_artifact  # noqa: E402

settings.register_profile("default", max_examples=40, deadline=None,
                          suppress_health_check=[HealthCheck.function_scoped_fixture])
settings.register_profile("thorough", max_examples=2000, deadline=None,
                          suppress_health_check=[HealthCheck.function_scoped_fixture])
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "default")
settings.load_profile(PROFILE)


def _n(count: int) -> int:
    return count * 25 if PROFILE == "thorough" else count

KEY = "property-test-key"

json_scalars = st.none() | st.booleans() | st.integers(-(2**53), 2**53) | st.text(max_size=40) | st.floats(
    allow_nan=False, allow_infinity=False
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4),
    max_leaves=20,
)
digests = st.binary(min_size=32, max_size=32).map(bytes.hex)


@given(json_values)
def test_canonical_json_round_trips_and_is_idempotent(value) -> None:
    text = canonical_json(value)
    assert json.loads(text) == value
    assert canonical_json(json.loads(text)) == text


@given(st.lists(digests, min_size=1, max_size=17), st.data())
def test_merkle_root_changes_when_any_leaf_changes(leaves, data) -> None:
    root = merkle_root(leaves)
    index = data.draw(st.integers(0, len(leaves) - 1))
    replacement = data.draw(digests.filter(lambda d: d != leaves[index]))
    changed = list(leaves)
    changed[index] = replacement
    assert merkle_root(changed) != root


@given(st.lists(digests, min_size=1, max_size=9))
def test_merkle_root_is_order_sensitive_and_deterministic(leaves) -> None:
    assert merkle_root(leaves) == merkle_root(list(leaves))
    if len(set(leaves)) > 1:
        assert merkle_root(leaves) != merkle_root(list(reversed(leaves))) or leaves == list(reversed(leaves))


secret_text = st.text(alphabet="ABCDEFGHJKMNPQRSTUVWXYZ23456789", min_size=12, max_size=24).map(lambda s: "Q9" + s)


@given(secret_text, st.sampled_from(["password", "api_key", "Authorization", "client_secret", "x-auth-token"]),
       json_values)
def test_sensitive_key_values_never_survive_redaction(secret, key, other) -> None:
    redacted = redact_value({"outer": {key: secret, "other": other}, "list": [{key: secret}]})
    assert secret not in canonical_json(redacted)


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", min_size=8, max_size=40),
       st.text(max_size=20), st.text(max_size=20))
def test_value_pattern_secrets_never_survive_redaction(body, prefix, suffix) -> None:
    secret = "sk-" + body
    redacted = redact_value({"note": f"{prefix} {secret} {suffix}"})
    assert secret not in canonical_json(redacted)


def _record(tmp: Path, payloads: list) -> Path:
    journal = tmp / "j"
    with SageRecorder(trace_id="prop", journal_dir=str(journal), blob_store=tmp / "blobs",
                      register_trace=False) as rec:
        for index, payload in enumerate(payloads):
            with rec.tool_call(f"tool-{index}", inputs={"payload": payload}):
                pass
    return journal


@settings(max_examples=_n(15))
@given(st.lists(json_values, min_size=1, max_size=4))
def test_sealed_spans_are_stored_in_normal_form(tmp_path_factory, payloads) -> None:
    journal = _record(tmp_path_factory.mktemp("nf"), payloads)
    for line in (journal / SPANS_JSONL).read_text(encoding="utf-8").splitlines():
        stored = json.loads(line)
        assert SageSpan.from_dict(stored).to_dict() == stored


@pytest.fixture(scope="module")
def sealed(tmp_path_factory) -> dict:
    tmp = tmp_path_factory.mktemp("sealed")
    journal = _record(tmp, ["alpha", {"k": [1, 2.5, None]}, "x" * 2048])
    files = {name: (journal / name).read_bytes() for name in (SPANS_JSONL, CHAIN_JSONL, MANIFEST_NAME)}
    pack = pack_artifact(journal, tmp / "p.sage.tar.gz", hmac_key=KEY, blob_store=tmp / "blobs")
    with tarfile.open(pack, "r:gz") as tar:
        members = [(m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()]
    report = verify_artifact(pack, hmac_key=KEY)
    return {"tmp": tmp, "files": files, "members": members, "report": report}


BOUND = ("bundle_hash", "bundle_id", "span_count")


def _bound_view(report: dict) -> tuple:
    pack = report.get("pack") or {}
    return tuple(report.get(k) for k in BOUND) + (pack.get("content_digest"), pack.get("blob_merkle"))


@settings(max_examples=_n(60))
@given(st.data())
def test_any_byte_change_in_a_sealed_journal_is_rejected(sealed, tmp_path_factory, data) -> None:
    name = data.draw(st.sampled_from(sorted(sealed["files"])))
    original = sealed["files"][name]
    offset = data.draw(st.integers(0, len(original) - 1))
    mask = data.draw(st.integers(1, 255))
    mutated = bytearray(original)
    mutated[offset] ^= mask
    root = tmp_path_factory.mktemp("mut")
    for other, raw in sealed["files"].items():
        (root / other).write_bytes(bytes(mutated) if other == name else raw)
    try:
        verify_journal(root, allow_live=False)
    except SageError:
        return
    # Accepted only if the change is JSON whitespace: the parsed content must be identical.
    assert _parsed(name, bytes(mutated)) == _parsed(name, original), (
        f"mutation accepted: {name} offset={offset} mask={mask}"
    )


def _parsed(name: str, raw: bytes) -> list[str]:
    text = raw.decode("utf-8")
    if name == MANIFEST_NAME:
        return [canonical_json(json.loads(text))]
    return [canonical_json(json.loads(line)) for line in text.split("\n") if line.strip()]


def _rebuild(members, target: str, mutate) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for member, raw in members:
            copy = tarfile.TarInfo(member.name)
            copy.type, copy.mode, copy.mtime = member.type, member.mode, member.mtime
            if raw is None:
                tar.addfile(copy)
                continue
            body = mutate(raw) if member.name == target else raw
            copy.size = len(body)
            tar.addfile(copy, io.BytesIO(body))
    return buf.getvalue()


@settings(max_examples=_n(60))
@given(st.data())
def test_pack_member_byte_change_is_rejected_or_harmless(sealed, tmp_path_factory, data) -> None:
    files = [m.name for m, raw in sealed["members"] if raw]
    target = data.draw(st.sampled_from(files))
    size = next(len(raw) for m, raw in sealed["members"] if m.name == target)
    offset = data.draw(st.integers(0, size - 1))
    mask = data.draw(st.integers(1, 255))

    def flip(raw: bytes) -> bytes:
        out = bytearray(raw)
        out[offset] ^= mask
        return bytes(out)

    path = tmp_path_factory.mktemp("pm") / "m.sage.tar.gz"
    path.write_bytes(_rebuild(sealed["members"], target, flip))
    try:
        report = verify_artifact(path, hmac_key=KEY)
    except SageError:
        return
    assert target.endswith("/pack.json"), f"mutation accepted in {target} offset={offset}"
    assert _bound_view(report) == _bound_view(sealed["report"]), f"pack.json change altered a bound value at {offset}"


@settings(max_examples=_n(60))
@given(st.data())
def test_raw_pack_bytes_change_never_escapes_as_a_non_sage_error(sealed, tmp_path_factory, data) -> None:
    raw = (sealed["tmp"] / "p.sage.tar.gz").read_bytes()
    offset = data.draw(st.integers(0, len(raw) - 1))
    mask = data.draw(st.integers(1, 255))
    mutated = bytearray(raw)
    mutated[offset] ^= mask
    path = tmp_path_factory.mktemp("raw") / "r.sage.tar.gz"
    path.write_bytes(bytes(mutated))
    try:
        report = verify_artifact(path, hmac_key=KEY)
    except SageError:
        return
    assert _bound_view(report) == _bound_view(sealed["report"])


@settings(max_examples=_n(80))
@given(st.binary(max_size=400) | st.text(max_size=200).map(lambda t: t.encode("utf-8")))
def test_arbitrary_journal_lines_fail_as_sage_errors(tmp_path_factory, blob) -> None:
    root = tmp_path_factory.mktemp("arb")
    (root / MANIFEST_NAME).write_text(json.dumps({"chain_tip": "0" * 64, "metadata": {}}), encoding="utf-8")
    (root / SPANS_JSONL).write_bytes(blob + b"\n")
    (root / CHAIN_JSONL).write_bytes(blob + b"\n")
    try:
        verify_journal(root, allow_live=False)
    except SageError:
        return
