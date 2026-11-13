"""Recompute the valid conformance vectors from docs/spec/FORMAT.md alone.

    python tests/vectors/reference_check.py

Standard library only; it does not import SAGE. Every hash, merkle root, content digest, MAC,
signature, and witness link in the valid vectors is recomputed by following the spec and compared
with the stored value. Port this file to check an implementation in another language.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZERO = "0" * 64
FAILURES: list[str] = []


def check(label: str, actual, expected) -> None:
    if actual != expected:
        FAILURES.append(f"{label}: expected {expected!r}, got {actual!r}")


# ------------------------------------------------------------------ section 2: encodings


def cj_u(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def cj_a(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mac(key: str, data: bytes) -> str:
    return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def check_encodings() -> None:
    """The rules of FORMAT.md section 2.2, as literal expected outputs."""
    cases = [
        ({"b": 1, "a": [True, False, None]}, '{"a":[true,false,null],"b":1}', '{"a":[true,false,null],"b":1}'),
        ({"s": "é😀\u2028/"}, '{"s":"é😀\u2028/"}', '{"s":"\\u00e9\\ud83d\\ude00\\u2028/"}'),
        ({"c": "\x00\x08\t\n\x0c\r\x1f\"\\\x7f"}, '{"c":"\\u0000\\b\\t\\n\\f\\r\\u001f\\"\\\\\x7f"}',
         '{"c":"\\u0000\\b\\t\\n\\f\\r\\u001f\\"\\\\\\u007f"}'),
        ({"f": [1e-05, 1e16, 100.0, 2.5, -0.0, 0.1, 19.99]}, '{"f":[1e-05,1e+16,100.0,2.5,-0.0,0.1,19.99]}',
         '{"f":[1e-05,1e+16,100.0,2.5,-0.0,0.1,19.99]}'),
        ({"\U0001f600": 1, "\uffff": 2, "Z": 3, "a": 4}, '{"Z":3,"a":4,"\uffff":2,"\U0001f600":1}',
         '{"Z":3,"a":4,"\\uffff":2,"\\ud83d\\ude00":1}'),
    ]
    for value, want_u, want_a in cases:
        check(f"CJ-U {want_u!r}", cj_u(value).decode("utf-8"), want_u)
        check(f"CJ-A {want_a!r}", cj_a(value).decode("ascii"), want_a)
    check("1.0 and 1 differ", cj_u(1.0) != cj_u(1), True)


# ------------------------------------------------------------------ section 5: chain and merkle


def merkle(leaves: list[str]) -> str:
    if not leaves:
        return ZERO
    level = [leaf.lower() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha((level[i] + level[i + 1]).encode("ascii")) for i in range(0, len(level), 2)]
    return level[0]


def chain_links(spans: list[dict]) -> list[dict]:
    content = {span["span_id"]: sha(cj_u(span)) for span in spans}
    links, prev = [], ZERO
    for index, span in enumerate(spans):
        parent = span["parent_id"]
        link = {
            "index": index,
            "span_id": span["span_id"],
            "span_type": span["type"],
            "span_name": span["name"],
            "timestamp": span["end_time"] or span["start_time"] or "",
            "prev_hash": prev,
            "span_hash": content[span["span_id"]],
            "content_hash": content[span["span_id"]],
            "parent_id": parent,
            "parent_content_hash": content.get(parent) if parent else None,
        }
        link["hash"] = sha(cj_u(link))
        links.append(link)
        prev = link["hash"]
    return links


def bundle_hash(bundle: dict) -> str:
    body = dict(bundle)
    body["audit"] = {"chain": bundle["audit"]["chain"], "bundle_hash": ""}
    body.pop("audit_chain", None)
    return sha(cj_u(body))


SPAN_MEMBERS = {"span_id", "parent_id", "trace_id", "type", "kind", "name", "start_time", "end_time", "status",
                "error", "agent_id", "agent_role", "attributes", "events", "data", "inputs", "outputs",
                "is_suspected_root_cause", "contribution_score", "failure_context"}


def check_spans(label: str, spans: list[dict]) -> None:
    for span in spans:
        check(f"{label} span members {span.get('span_id')}", set(span), SPAN_MEMBERS)
        want_kind = "RETRIEVER" if span["type"] == "retrieval" else span["type"].upper()
        check(f"{label} kind mirror {span['span_id']}", span["kind"], want_kind)
    check(f"{label} span order", [s["span_id"] for s in spans],
          [s["span_id"] for s in sorted(spans, key=lambda s: (s["start_time"], s["span_id"]))])


def blob_refs(value, out: set[str]) -> set[str]:
    if isinstance(value, dict):
        if "$sage_blob" in value:
            out.add(value["$sage_blob"])
        else:
            for child in value.values():
                blob_refs(child, out)
    elif isinstance(value, list):
        for child in value:
            blob_refs(child, out)
    return out


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ------------------------------------------------------------------ sections 3 to 6: bundle, journal


def check_bundle_file(path: Path, blob_root: Path) -> None:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    label = path.relative_to(HERE).as_posix()
    check_spans(label, bundle["spans"])
    check(f"{label} chain", bundle["audit"]["chain"], chain_links(bundle["spans"]))
    check(f"{label} audit_chain mirror", bundle["audit_chain"], bundle["audit"]["chain"])
    check(f"{label} run_id mirror", bundle["run_id"], bundle["source"]["run_id"])
    check(f"{label} bundle_hash", bundle_hash(bundle), bundle["audit"]["bundle_hash"])
    check_blobs(label, bundle["spans"], blob_root)


def check_blobs(label: str, spans: list[dict], blob_root: Path) -> None:
    for digest in sorted(blob_refs(spans, set())):
        path = blob_root / digest
        check(f"{label} blob {digest[:12]} present", path.is_file(), True)
        if path.is_file():
            check(f"{label} blob {digest[:12]}", sha(path.read_bytes()), digest)


def check_journal(journal: Path, blob_root: Path | None) -> dict:
    label = journal.relative_to(HERE).as_posix() if HERE in journal.parents else journal.name
    manifest = json.loads((journal / "manifest.sage.json").read_text(encoding="utf-8"))
    spans = read_jsonl(journal / "spans.jsonl")
    chain = read_jsonl(journal / "chain.jsonl")
    body = {k: v for k, v in manifest.items() if k != "manifest_seal"}
    check(f"{label} manifest_seal", sha(cj_u(body)), manifest["manifest_seal"])
    check_spans(label, spans)
    check(f"{label} chain.jsonl", chain, chain_links(spans))
    check(f"{label} chain_tip", manifest["chain_tip"], chain[-1]["hash"] if chain else ZERO)
    check(f"{label} merkle_root", manifest["merkle_root"], merkle([link["hash"] for link in chain]))
    check(f"{label} span_ids", manifest["span_ids"], [s["span_id"] for s in spans])
    bundle = {k: manifest[k] for k in ("schema_version", "bundle_id", "title", "created_at", "source", "status",
                                       "root_cause_hint", "metadata", "redactions", "redaction_policy")}
    bundle.update(spans=spans, audit={"chain": chain, "bundle_hash": ""}, run_id=manifest["source"]["run_id"])
    check(f"{label} bundle_hash", bundle_hash(bundle), manifest["audit"]["bundle_hash"])
    check(f"{label} sealed", "live_recording" in manifest["metadata"], False)
    if blob_root is not None:
        check_blobs(label, spans, blob_root)
    return {"manifest": manifest, "chain": chain}


# ------------------------------------------------------------------ sections 7 and 8: pack, witness


def check_witness(label: str, path: Path, key: str) -> list[dict]:
    records = read_jsonl(path)
    prev = ZERO
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        check(f"{label} witness[{i}] record_hash", sha(cj_a(body)), rec["record_hash"])
        check(f"{label} witness[{i}] prev_hash", rec["prev_hash"], prev)
        unsigned = {k: v for k, v in body.items() if k != "attestation"}
        check(f"{label} witness[{i}] mac", mac(key, cj_a(unsigned)), rec["attestation"]["mac"])
        prev = rec["record_hash"]
    return records


def content_digest(artifact: Path) -> str:
    files = [p for p in artifact.rglob("*") if p.is_file() and p.relative_to(artifact).as_posix() != "pack.json"]
    files.sort(key=lambda p: p.relative_to(artifact).as_posix().split("/"))
    entries = [[p.relative_to(artifact).as_posix(), sha(p.read_bytes())] for p in files]
    return sha(json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def check_pack(path: Path, key: str, pin: str) -> dict:
    label = path.relative_to(HERE).as_posix()
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
        check(f"{label} single top-level dir", {n.split("/")[0] for n in names}, {"sage_artifact"})
        tar.extractall(tmp, filter="data")
        art = Path(tmp) / "sage_artifact"
        meta = json.loads((art / "pack.json").read_text(encoding="utf-8"))
        check(f"{label} format", meta["format"], "sage.pack.v2")
        digest = content_digest(art)
        check(f"{label} content_digest", digest, meta["content_digest"])
        check(f"{label} blob_digests sorted", meta["blob_digests"], sorted(meta["blob_digests"]))
        check(f"{label} blob_merkle", merkle(meta["blob_digests"]), meta["blob_merkle"])
        blobs = {p.name: sha(p.read_bytes()) for p in (art / "blobs").iterdir()}
        check(f"{label} blob names are digests", all(name == d for name, d in blobs.items()), True)
        check(f"{label} blob inventory", sorted(blobs), meta["blob_digests"])
        journal = check_journal(art / "journal", art / "blobs")
        check(f"{label} bundle_hash anchor", meta["bundle_hash"], journal["manifest"]["audit"]["bundle_hash"])
        check(f"{label} merkle_root anchor", meta["merkle_root"], journal["manifest"]["merkle_root"])
        records = check_witness(label, art / "journal" / "witness.jsonl", key)
        check(f"{label} witness_tip anchor", meta["witness_tip"], records[-1]["record_hash"])
        check(f"{label} witness bundle_hash", records[-1]["bundle_hash"], meta["bundle_hash"])
        check(f"{label} witness chain_tip", records[-1]["chain_tip"], journal["manifest"]["chain_tip"])
        custody = {"blob_merkle": meta["blob_merkle"], "bundle_hash": meta["bundle_hash"], "content_digest": digest,
                   "merkle_root": meta["merkle_root"], "witness_tip": meta["witness_tip"]}
        check(f"{label} attestation mac", mac(key, cj_a(custody)), meta["attestation"]["mac"])
        sig = meta["signature"]
        check(f"{label} signature alg", sig["alg"], "ed25519")
        check(f"{label} signature verifies against the pinned key",
              ed25519_verify(b64u_decode(pin), cj_a(custody), b64u_decode(sig["sig"])), True)
        return {"content_digest": digest, "bundle_hash": meta["bundle_hash"], "bundle_id": meta["bundle_id"]}


# ------------------------------------------------------------------ sections 9 and 10: policy, receipt

POLICY_DEFAULTS = {
    "format": "sage.verify.policy.v1", "policy_id": "default", "require_sealed": True, "forbid_live_journal": True,
    "require_witness": False, "require_witness_hmac": False, "require_pack_hmac": False, "require_pack_v2": False,
    "require_pack_signature": False, "require_blob_inventory": True, "min_redaction_count": 0, "min_span_count": 0,
    "allowed_kinds": ["bundle", "journal", "pack"],
}


def policy_digest(policy: dict) -> str:
    return sha(cj_a({**POLICY_DEFAULTS, **policy}))


def check_kit(kit: Path, key: str, pin: str) -> None:
    label = kit.relative_to(HERE).as_posix()
    pack = check_pack(kit / "evidence.sage.tar.gz", key, pin)
    policy = json.loads((kit / "policy.json").read_text(encoding="utf-8"))
    receipt = json.loads((kit / "verify.receipt.json").read_text(encoding="utf-8"))
    body = {k: v for k, v in receipt.items() if k != "attestation"}
    check(f"{label} receipt format", body["format"], "sage.verify.receipt.v1")
    check(f"{label} receipt mac", mac(key, cj_a(body)), receipt["attestation"]["mac"])
    check(f"{label} receipt ok", body["ok"], True)
    check(f"{label} receipt fingerprint", body["artifact_fingerprint"], pack["content_digest"])
    check(f"{label} receipt bundle_hash", body["bundle_hash"], pack["bundle_hash"])
    check(f"{label} receipt bundle_id", body["bundle_id"], pack["bundle_id"])
    check(f"{label} receipt policy_digest", body["policy_digest"], policy_digest(policy))


# ------------------------------------------------------------------ RFC 8032 Ed25519 verification

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A, B = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    C, Dd = t1 * 2 * D * t2 % P, z1 * 2 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return E * F % P, G * H % P, F * G % P, E * H % P


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt, s = _add(pt, pt), s >> 1
    return q


def _decompress(raw: bytes):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x, y, 1, x * y % P


def _eq(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


G_POINT = _decompress(int.to_bytes(4 * pow(5, P - 2, P) % P, 32, "little"))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    A, R = _decompress(public), _decompress(signature[:32]) if len(signature) == 64 else None
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return _eq(_mul(s, G_POINT), _add(R, _mul(k, A)))


def check_ed25519() -> None:
    # RFC 8032 section 7.1 TEST 1 (empty message).
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    check("RFC 8032 TEST 1 verifies", ed25519_verify(pub, b"", sig), True)
    check("RFC 8032 TEST 1 rejects another message", ed25519_verify(pub, b"x", sig), False)


# ------------------------------------------------------------------ run


def main() -> int:
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    key = (HERE / manifest["hmac_key_file"]).read_text(encoding="utf-8").strip()
    pin = (HERE / manifest["public_key_file"]).read_text(encoding="utf-8").strip()
    check_encodings()
    check_ed25519()
    checked = 0
    for vec in manifest["vectors"]:
        if vec["expect"] != "accept":
            continue
        target = HERE / vec["artifact"]
        blob_root = HERE / vec["blob_root"] if vec.get("blob_root") else None
        if vec["kind"] == "bundle":
            check_bundle_file(target, blob_root)
        elif vec["kind"] == "journal":
            check_journal(target, blob_root)
        elif vec["kind"] == "pack":
            check_pack(target, key, pin)
        elif vec["kind"] == "kit":
            check_kit(target, key, pin)
        elif vec["kind"] == "policy":
            policy = json.loads(target.read_text(encoding="utf-8"))
            check(f"{vec['id']} known members", set(policy) <= set(POLICY_DEFAULTS), True)
        checked += 1
    for line in FAILURES:
        print("FAIL", line)
    print(f"reference check: {checked} valid vectors, {len(FAILURES)} mismatches")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
