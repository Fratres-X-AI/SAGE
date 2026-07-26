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
    ) -> None:
        self.recorder = recorder or SageRecorder(
            title="otel-tap",
            trace_id=trace_id,
            framework=framework,
            auto_export=auto_export,
            journal_dir=journal_dir,
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
        if self.recorder.journal_dir is not None and converted.span_id not in self.recorder._journal_appended:
            from sage.journal import append_live_span, write_live_manifest

            _disk, link = append_live_span(
                self.recorder.journal_dir,
                converted,
                index=self.recorder._journal_index,
                prev_hash=self.recorder._chain_prev_hash,
                blob_store=self.recorder.blob_store,
                redaction_policy=self.recorder.bundle.redaction_policy,
                blob_threshold=self.recorder.blob_threshold,
                content_by_id=self.recorder._journal_content,
            )
            self.recorder._journal_content[converted.span_id] = link["content_hash"]
            self.recorder._chain_prev_hash = link["hash"]
            self.recorder._journal_index += 1
            self.recorder._journal_appended.add(converted.span_id)
            write_live_manifest(
                self.recorder.bundle,
                self.recorder.journal_dir,
                live=True,
                chain_tip=self.recorder._chain_prev_hash,
            )
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
            if self.recorder.journal_dir is not None and span.span_id not in self.recorder._journal_appended:
                from sage.journal import append_live_span, write_live_manifest

                _disk, link = append_live_span(
                    self.recorder.journal_dir,
                    span,
                    index=self.recorder._journal_index,
                    prev_hash=self.recorder._chain_prev_hash,
                    blob_store=self.recorder.blob_store,
                    redaction_policy=self.recorder.bundle.redaction_policy,
                    blob_threshold=self.recorder.blob_threshold,
                    content_by_id=self.recorder._journal_content,
                )
                self.recorder._journal_content[span.span_id] = link["content_hash"]
                self.recorder._chain_prev_hash = link["hash"]
                self.recorder._journal_index += 1
                self.recorder._journal_appended.add(span.span_id)
                write_live_manifest(
                    self.recorder.bundle,
                    self.recorder.journal_dir,
                    live=True,
                    chain_tip=self.recorder._chain_prev_hash,
                )
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
) -> OpenTelemetryTap:
    """Factory: attach point for existing OTel export pipelines."""
    return OpenTelemetryTap(
        trace_id=trace_id,
        auto_export=auto_export,
        journal_dir=journal_dir,
    )
