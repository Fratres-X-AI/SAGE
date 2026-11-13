"""Import OTLP trace exports (JSON, JSON Lines or protobuf) into sealed SAGE bundles.

JSON needs no extra packages. Binary protobuf (an ``ExportTraceServiceRequest`` or
``TracesData`` message, as sent by OTLP/HTTP exporters with
``Content-Type: application/x-protobuf``) needs the ``otlp`` extra::

    pip install "sage-incident-bundles[otlp]"

Usage::

    from sage.importers.otlp import load_otlp_file
    from sage.bundle_io import save_bundle

    bundle = load_otlp_file("traces.pb")          # or traces.json / traces.jsonl
    save_bundle(bundle, "incident.sage.json")

CLI: ``sage import traces.pb --format otlp --out incident.sage.json``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sage.importers.openinference import import_openinference, load_json_or_jsonl
from sage.schema import IncidentBundle

OTLP_INSTALL_HINT = 'OTLP protobuf import needs opentelemetry-proto: pip install "sage-incident-bundles[otlp]"'


def otlp_protobuf_to_dict(raw: bytes) -> dict[str, Any]:
    """Decode a binary ``ExportTraceServiceRequest`` into its ``MessageToDict`` JSON form."""
    try:
        from google.protobuf.json_format import MessageToDict
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
    except ImportError as exc:
        raise ImportError(OTLP_INSTALL_HINT) from exc
    from google.protobuf.message import DecodeError

    message = ExportTraceServiceRequest()
    try:
        message.ParseFromString(raw)
    except DecodeError as exc:
        raise ValueError(f"not an OTLP ExportTraceServiceRequest protobuf: {exc}") from None
    return MessageToDict(message)


def parse_otlp_bytes(raw: bytes) -> Any:
    """Parse OTLP bytes: JSON, JSON Lines, or binary protobuf (detected by the first byte)."""
    stripped = raw.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped[:1] in (b"{", b"["):
        return load_json_or_jsonl(stripped.decode("utf-8"))
    if not stripped:
        raise ValueError("empty OTLP payload")
    return otlp_protobuf_to_dict(raw)


def import_otlp(data: Any, *, title: str = "Imported OTLP trace") -> IncidentBundle:
    """Seal an OTLP payload (bytes, or already-parsed JSON) as a SAGE bundle."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = parse_otlp_bytes(bytes(data))
    return import_openinference(data, title=title, framework="opentelemetry", importer="otlp")


def load_otlp_file(path: str | Path, *, title: str | None = None) -> IncidentBundle:
    path = Path(path)
    return import_otlp(path.read_bytes(), title=title or path.name.split(".")[0])
