"""Pre-share leak check for packs, bundles, and journals (`sage scan`).

The scan reads every member a recipient would get (journal files, `pack.json`, the witness log,
and content-addressed blobs) and reports strings that look like secrets, personal data, or local
paths. A finding names the rule and the location (file member, line, span id, JSON path). It never
contains the matched text or any part of it: only its length and the first 8 hex characters of its
SHA-256, so two findings of the same value can be matched up.

Exit codes for `sage scan`: 0 no findings, 1 findings, 2 setup or usage error.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from sage.audit import DEFAULT_REDACTION_KEYS, DEFAULT_VALUE_PATTERNS, _is_sensitive_key
from sage.detectors import ALL_DETECTORS, find_spans, is_card_number, resolve_detector_ids
from sage.errors import SageError

MAX_MEMBER_BYTES = 256 * 1024 * 1024
REDACTED = "[REDACTED]"
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DEFAULT_PATTERN_RES = tuple(re.compile(p) for p in DEFAULT_VALUE_PATTERNS)


class ScanSetupError(SageError):
    """The target cannot be scanned (missing, unreadable, or not a SAGE artifact)."""


@dataclass(frozen=True)
class Finding:
    rule: str
    member: str
    path: str
    length: int
    sha256_prefix: str
    span_id: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule,
            "member": self.member,
            "path": self.path,
            "length": self.length,
            "sha256_prefix": self.sha256_prefix,
        }
        if self.span_id is not None:
            out["span_id"] = self.span_id
        if self.line is not None:
            out["line"] = self.line
        return out

    def location(self) -> str:
        parts = [self.member]
        if self.line is not None:
            parts.append(f"line {self.line}")
        if self.span_id:
            parts.append(f"span {self.span_id}")
        parts.append(self.path)
        return " ".join(parts)


@dataclass
class ScanReport:
    target: str
    kind: str
    rules: tuple[str, ...]
    findings: list[Finding] = field(default_factory=list)
    members_scanned: int = 0
    blobs_scanned: int = 0
    blobs_unavailable: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.rule] = out.get(finding.rule, 0) + 1
        return dict(sorted(out.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "target": self.target,
            "kind": self.kind,
            "rules": list(self.rules),
            "finding_count": len(self.findings),
            "counts": self.counts(),
            "members_scanned": self.members_scanned,
            "blobs_scanned": self.blobs_scanned,
            "blobs_unavailable": self.blobs_unavailable,
            "findings": [f.to_dict() for f in self.findings],
        }

    def summary(self) -> str:
        if self.ok:
            return f"no possible leaks found in {self.kind} ({self.members_scanned} members scanned)"
        rules = ", ".join(f"{rule} x{n}" for rule, n in self.counts().items())
        return f"{len(self.findings)} possible leak(s) in {self.kind}: {rules}"


SCAN_RULES = (*ALL_DETECTORS, "value_pattern", "sensitive_key")


def _fingerprint(text: str) -> tuple[int, str]:
    return len(text), hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()[:8]


def _segment(key: str, index: int, hidden: bool) -> str:
    if hidden:
        return f"[<key #{index}>]"
    if _IDENT_RE.match(key):
        return f".{key}"
    return "[" + json.dumps(key, ensure_ascii=True) + "]"


class _Scanner:
    def __init__(self, report: ScanReport) -> None:
        self.report = report
        self.detectors = tuple(r for r in report.rules if r in ALL_DETECTORS)
        self.value_patterns = "value_pattern" in report.rules
        self.sensitive_keys = "sensitive_key" in report.rules
        self.blob_digests: set[str] = set()

    def _hits(self, text: str, key: str) -> list[tuple[str, str]]:
        hits = find_spans(text, self.detectors, key=key)
        out = [(rule, text[start:end]) for start, end, rule in hits]
        if self.value_patterns:
            for regex in _DEFAULT_PATTERN_RES:
                for match in regex.finditer(text):
                    start, end = match.span()
                    if not any(s < end and start < e for s, e, _r in hits):
                        out.append(("value_pattern", match.group(0)))
        return out

    def _add(self, rule: str, matched: str, member: str, path: str, span_id: str | None, line: int | None) -> None:
        length, prefix = _fingerprint(matched)
        self.report.findings.append(
            Finding(rule=rule, member=member, path=path, length=length, sha256_prefix=prefix, span_id=span_id, line=line)
        )

    def text(self, text: str, member: str, *, line: int | None = None, path: str = "$", key: str = "") -> None:
        for rule, matched in self._hits(text, key):
            self._add(rule, matched, member, path, None, line)

    def json(self, value: Any, member: str, *, line: int | None = None) -> None:
        self._walk(value, member, "$", "", None, line)

    def _walk(self, value: Any, member: str, path: str, key: str, span_id: str | None, line: int | None) -> None:
        if isinstance(value, str):
            if value == REDACTED:
                return
            for rule, matched in self._hits(value, key):
                self._add(rule, matched, member, path, span_id, line)
            return
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, int):
            if "card_number" in self.detectors and value >= 10**12 and is_card_number(str(value)):
                self._add("card_number", str(value), member, path, span_id, line)
            return
        if isinstance(value, dict):
            if isinstance(value.get("$sage_blob"), str):
                self.blob_digests.add(value["$sage_blob"].split(":", 1)[-1])
            sid = value.get("span_id")
            if isinstance(sid, str) and ("type" in value or "span_type" in value):
                span_id = sid
            for index, (child_key, child) in enumerate(value.items()):
                key_s = str(child_key)
                key_hits = self._hits(key_s, "")
                for rule, matched in key_hits:
                    self._add(rule, matched, member, f"{path}[<key #{index}>]", span_id, line)
                child_path = path + _segment(key_s, index, bool(key_hits))
                if (
                    self.sensitive_keys
                    and _is_sensitive_key(key_s.lower(), DEFAULT_REDACTION_KEYS, child)
                    and _carries_text(child)
                ):
                    self._add("sensitive_key", _as_text(child), member, child_path, span_id, line)
                    continue
                self._walk(child, member, child_path, key_s, span_id, line)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._walk(child, member, f"{path}[{index}]", key, span_id, line)

    def document(self, raw: bytes, member: str) -> None:
        """Scan one file: JSON, JSON Lines, or plain text (gzip is unwrapped first)."""
        self.report.members_scanned += 1
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                pass
        text = raw.decode("utf-8", errors="replace")
        if member.endswith(".jsonl"):
            for number, line_text in enumerate(text.splitlines(), start=1):
                if not line_text.strip():
                    continue
                try:
                    self.json(json.loads(line_text), member, line=number)
                except json.JSONDecodeError:
                    self.text(line_text, member, line=number)
            return
        stripped = text.lstrip()
        if stripped[:1] in ("{", "[", '"'):
            try:
                self.json(json.loads(text), member)
                return
            except json.JSONDecodeError:
                pass
        self.text(text, member)


def _carries_text(value: Any) -> bool:
    if isinstance(value, str):
        return value not in ("", REDACTED)
    if isinstance(value, dict):
        return any(_carries_text(v) for v in value.values())
    if isinstance(value, list):
        return any(_carries_text(v) for v in value)
    return False


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)


def _detect_kind(path: Path) -> str:
    name = path.name.lower()
    if path.is_file():
        if name.endswith((".tar.gz", ".tgz")):
            return "pack"
        if name.endswith(".json"):
            return "bundle"
        raise ScanSetupError(f"not a SAGE pack (.sage.tar.gz) or bundle (.json): {path.name}")
    if path.is_dir():
        if (path / "pack.json").exists() or (path / "sage_artifact" / "pack.json").exists():
            return "unpacked-pack"
        if (path / "manifest.sage.json").exists() or (path / "spans.jsonl").exists():
            return "journal"
        raise ScanSetupError(f"directory is not a SAGE journal or unpacked pack: {path}")
    raise ScanSetupError(f"path does not exist: {path}")


def _iter_tar(path: Path) -> Iterator[tuple[str, bytes]]:
    try:
        with tarfile.open(path, "r:*") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                if member.size > MAX_MEMBER_BYTES:
                    raise ScanSetupError(f"pack member too large to scan: {member.name} ({member.size} bytes)")
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                yield member.name, handle.read()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ScanSetupError(f"cannot read pack {path.name}: {exc}") from exc


def _iter_dir(root: Path) -> Iterator[tuple[str, bytes]]:
    for file in sorted(p for p in root.rglob("*") if p.is_file()):
        if file.stat().st_size > MAX_MEMBER_BYTES:
            raise ScanSetupError(f"file too large to scan: {file.relative_to(root).as_posix()}")
        yield file.relative_to(root).as_posix(), file.read_bytes()


def _scan_external_blobs(scanner: _Scanner, store_root: Path | None) -> None:
    from sage.blobs import BlobStore

    digests = sorted(scanner.blob_digests)
    if not digests:
        return
    if store_root is None or not Path(store_root).is_dir():
        scanner.report.blobs_unavailable += len(digests)
        return
    store = BlobStore(store_root)
    for digest in digests:
        try:
            raw = store.get_bytes(digest, verify=True)
        except Exception:
            scanner.report.blobs_unavailable += 1
            continue
        scanner.report.blobs_scanned += 1
        scanner.document(raw, f"blob:{digest}")


def scan_path(
    path: str | Path,
    *,
    rules: list[str] | tuple[str, ...] | None = None,
    blob_root: str | Path | None = None,
) -> ScanReport:
    """Scan a pack, unpacked pack, bundle, or journal for possible leaks before sharing it.

    ``rules`` limits the scan to some rule ids (default: all of `SCAN_RULES`). For a bundle or a
    journal, blobs it references are read from ``blob_root`` (or the store it was sealed with)
    when available; a pack carries its own blobs.
    """
    target = Path(path)
    kind = _detect_kind(target)
    if rules:
        unknown = [r for r in rules if r not in SCAN_RULES and r != "all"]
        if unknown:
            raise ScanSetupError(f"unknown scan rule(s): {', '.join(unknown)}; known: {', '.join(SCAN_RULES)}")
        chosen = SCAN_RULES if "all" in rules else tuple(r for r in SCAN_RULES if r in rules)
    else:
        chosen = SCAN_RULES
    resolve_detector_ids([r for r in chosen if r in ALL_DETECTORS])
    report = ScanReport(target=str(target), kind=kind, rules=chosen)
    scanner = _Scanner(report)

    if kind == "pack":
        for name, raw in _iter_tar(target):
            if "/blobs/" in f"/{name}":
                report.blobs_scanned += 1
            scanner.document(raw, name)
        return report
    if kind == "unpacked-pack":
        for name, raw in _iter_dir(target):
            if "/blobs/" in f"/{name}":
                report.blobs_scanned += 1
            scanner.document(raw, name)
        return report

    if kind == "bundle":
        try:
            raw = target.read_bytes()
        except OSError as exc:
            raise ScanSetupError(f"cannot read bundle {target.name}: {exc}") from exc
        scanner.document(raw, target.name)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScanSetupError(f"bundle is not valid JSON: {target.name}") from exc
    else:
        for name, raw in _iter_dir(target):
            scanner.document(raw, name)
        manifest = target / "manifest.sage.json"
        try:
            data = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
        except (OSError, json.JSONDecodeError):
            data = {}
    if blob_root is None and isinstance(data, dict):
        from sage.blobs import resolve_blob_root

        meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        blob_root = resolve_blob_root({"bundle_id": data.get("bundle_id"), "metadata": meta})
        if blob_root is not None and not blob_root.is_absolute() and not blob_root.is_dir():
            beside = (target if kind == "journal" else target.parent) / blob_root
            if beside.is_dir():
                blob_root = beside
    _scan_external_blobs(scanner, Path(blob_root) if blob_root else None)
    return report


def format_report(report: ScanReport) -> str:
    lines = [f"sage scan: {report.summary()}", f"target: {report.target}"]
    if report.blobs_unavailable:
        lines.append(
            f"note: {report.blobs_unavailable} referenced blob(s) were not available and were not scanned "
            "(pass --blob-root)"
        )
    for finding in report.findings:
        lines.append(
            f"  {finding.rule:<18} {finding.location()}  (length {finding.length}, sha256 {finding.sha256_prefix}...)"
        )
    if report.findings:
        lines.append("Values are never printed. Review each location before sharing.")
    return "\n".join(lines)
