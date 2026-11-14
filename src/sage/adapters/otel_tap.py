from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from sage.importers.openinference import convert_span, import_openinference
from sage.recorder import SageRecorder
from sage.schema import ensure_typed_data, utc_now


class OpenTelemetryTap:
    """Live tap: ingest OTLP/OpenInference-shaped span dicts into a SageRecorder.

    No OpenTelemetry SDK dependency. Wire from an exporter/processor::

        tap = attach_otel_tap(trace_id="run-1", journal_dir=".sage/runs/run-1")
        processor = tap.as_span_callback()  # fn(span_dict) -> span_id
    """

    def __init__(
        self,
        recorder: SageRecorder | None = None,
        *,
        trace_id: str | None = None,
        framework: str = "opentelemetry",
        auto_export: str | Path | None = None,
        journal_dir: str | Path | None = None,
        journal_durability: str | None = None,
    ) -> None:
        self.recorder = recorder or SageRecorder(
            title="otel-tap",
            trace_id=trace_id,
            framework=framework,
            auto_export=auto_export,
            journal_dir=journal_dir,
            journal_durability=journal_durability,
            register_trace=True,
        )
        self._seen: set[str] = set()
        self._entered = False

    def __enter__(self) -> "OpenTelemetryTap":
        self.recorder.__enter__()
        self._entered = True
        return self

    def __exit__(self, *args: Any) -> None:
        if self._entered:
            self.recorder.__exit__(*args)
            self._entered = False

    def on_span(self, span: dict[str, Any]) -> str:
        """Map one OTel/OpenInference span into the live recorder and return span_id."""
        converted = convert_span(span)
        if converted.span_id in self._seen:
            return converted.span_id
        converted.trace_id = self.recorder.bundle.bundle_id
        ensure_typed_data(converted)
        if not converted.end_time:
            converted.end_time = utc_now()
        self.recorder.bundle.add_span(converted)
        self.recorder._open_spans.discard(converted.span_id)
        self.recorder._journal_append(converted)
        self._seen.add(converted.span_id)
        return converted.span_id

    def as_span_callback(self) -> Callable[[dict[str, Any]], str]:
        """Return a plain callback suitable for wrapping an OTel SpanExporter/Processor."""
        return self.on_span

    def ingest_payload(self, data: Any) -> int:
        before = len(self.recorder.bundle.spans)
        imported = import_openinference(data, title=self.recorder.bundle.title)
        for span in imported.spans:
            if span.span_id in self._seen:
                continue
            span.trace_id = self.recorder.bundle.bundle_id
            self.recorder.bundle.add_span(span)
            self.recorder._open_spans.discard(span.span_id)
            self.recorder._journal_append(span)
            self._seen.add(span.span_id)
        return len(self.recorder.bundle.spans) - before

    def ingest_file(self, path: str | Path) -> int:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.ingest_payload(data)

    def finalize(self, **kwargs: Any):
        return self.recorder.finalize(**kwargs)

    def export(self, path: str | Path, **kwargs: Any) -> Path:
        return self.recorder.export(path, **kwargs)


def attach_otel_tap(
    *,
    trace_id: str | None = None,
    auto_export: str | Path | None = None,
    journal_dir: str | Path | None = None,
    journal_durability: str | None = None,
) -> OpenTelemetryTap:
    """Factory: attach point for existing OTel export pipelines."""
    return OpenTelemetryTap(
        trace_id=trace_id,
        auto_export=auto_export,
        journal_dir=journal_dir,
        journal_durability=journal_durability,
    )
