from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from sage.audit import finalize_bundle
from sage.blobs import DEFAULT_THRESHOLD, BlobStore, MemoryBudget
from sage.concurrency import (
    GLOBAL_TRACE_REGISTRY,
    concurrent_owner_id,
    stamp_span_order,
    validate_monotonic_chain,
)
from sage.schema import (
    BundleSource,
    IncidentBundle,
    SageSpan,
    SpanError,
    SpanKind,
    SpanStatus,
    SpanType,
    ensure_typed_data,
    new_id,
    normalize_status,
    normalize_type,
    utc_now,
)


class RecordedSpan:
    def __init__(self, span: SageSpan) -> None:
        self.span = span

    def set_input(self, **inputs: Any) -> None:
        self.span.inputs.update(inputs)
        self.span.data.setdefault("input", {})
        if isinstance(self.span.data["input"], dict):
            self.span.data["input"].update(inputs)

    def set_output(self, **outputs: Any) -> None:
        self.span.outputs.update(outputs)
        self.span.data["output"] = {**(self.span.data.get("output") or {}), **outputs}

    def set_data(self, **data: Any) -> None:
        self.span.data.update(data)

    def set_usage(self, **usage: Any) -> None:
        self.span.data.setdefault("usage", {}).update(usage)
        self.span.attributes["usage"] = self.span.data["usage"]

    def set_attributes(self, **attributes: Any) -> None:
        self.span.attributes.update(attributes)

    def set_model(self, model: str, **parameters: Any) -> None:
        self.span.data["model"] = model
        if parameters:
            self.span.data["parameters"] = {**(self.span.data.get("parameters") or {}), **parameters}

    def add_event(self, name: str, **payload: Any) -> None:
        self.span.events.append({"name": name, "timestamp": utc_now(), **payload})

    def mark_root_cause(self, note: str | None = None, score: float | None = None) -> None:
        self.span.is_suspected_root_cause = True
        if note is not None:
            self.span.failure_context = note
        if score is not None:
            self.span.contribution_score = score

    def fail(self, message: str, *, error_type: str = "Error", stack: str | None = None) -> None:
        self.span.status = "error"
        self.span.error = SpanError(type=error_type, message=message, stack=stack)
        if self.span.type == "tool":
            self.span.data["success"] = False


class SageRecorder:
    """Zero-friction in-process recorder for SAGE incident bundles.

    Drop-in usage (three lines around any existing agent loop)::

        from sage import SageRecorder
        with SageRecorder(trace_id="user-123") as recorder:
            agent.run(task)

    Invariants:
    - Redaction happens before hashing.
    - Large payloads (>1KB) are CAS-offloaded to .sage/blobs/ before hashing.
    - Finalize is fail-closed on incomplete required typed fields.

    Live journal (``journal_dir=``): ``journal_durability`` selects when closed spans reach disk.

    - ``"span"``: fsync before ``end_span`` returns. Nothing that was closed is lost.
    - ``"batch"`` (default): a background thread group-commits with fsync every
      ``journal_batch_interval_ms`` (default 50 ms) or ``journal_batch_max_spans`` (default 256)
      closed spans, whichever comes first. A crash loses at most the spans closed in that window
      plus the commit under way; never more than four batches' worth, because ``end_span`` then
      waits for the disk.
    - ``"close"``: background writes without fsync until ``flush_journal()`` or the seal.

    ``None`` reads ``$SAGE_JOURNAL_DURABILITY`` and falls back to ``"batch"``. Sealing always
    flushes, fsyncs, and stops the writer thread; a writer failure is raised, never dropped.
    Hashes do not depend on the mode.
    """

    def __init__(
        self,
        title: str | None = None,
        *,
        trace_id: str | None = None,
        run_id: str | None = None,
        framework: str = "custom",
        environment: str = "local",
        metadata: dict[str, Any] | None = None,
        redaction_policy: dict[str, Any] | None = None,
        agent_id: str | None = None,
        agent_role: str | None = None,
        blob_store: str | Path | BlobStore | None = None,
        blob_threshold: int = DEFAULT_THRESHOLD,
        auto_export: str | Path | None = None,
        memory_budget_bytes: int | None = None,
        register_trace: bool = True,
        journal_dir: str | Path | None = None,
        sanitize_on_close: bool = True,
        journal_durability: str | None = None,
        journal_batch_interval_ms: float | None = None,
        journal_batch_max_spans: int | None = None,
    ) -> None:
        from sage.journal import (
            DEFAULT_BATCH_INTERVAL_MS,
            DEFAULT_BATCH_MAX_SPANS,
            resolve_durability,
        )

        self.journal_durability = resolve_durability(journal_durability)
        self.journal_batch_interval_ms = (
            DEFAULT_BATCH_INTERVAL_MS if journal_batch_interval_ms is None else float(journal_batch_interval_ms)
        )
        self.journal_batch_max_spans = (
            DEFAULT_BATCH_MAX_SPANS if journal_batch_max_spans is None else int(journal_batch_max_spans)
        )
        if self.journal_batch_interval_ms < 0:
            raise ValueError("journal_batch_interval_ms must be >= 0")
        if self.journal_batch_max_spans < 1:
            raise ValueError("journal_batch_max_spans must be >= 1")
        run = run_id or trace_id or new_id("run")
        resolved_title = title or f"trace:{run}"
        self.bundle = IncidentBundle(
            title=resolved_title,
            bundle_id=trace_id or new_id("bundle"),
            source=BundleSource(framework=framework, run_id=run, environment=environment),
            metadata=metadata or {},
            redaction_policy=redaction_policy or {},
            status="partial",
        )
        if trace_id:
            self.bundle.metadata.setdefault("trace_id", trace_id)
        self.default_agent_id = agent_id
        self.default_agent_role = agent_role
        budget = MemoryBudget(memory_budget_bytes) if memory_budget_bytes is not None else None
        if isinstance(blob_store, BlobStore):
            self.blob_store = blob_store
            if budget is not None:
                self.blob_store.memory_budget = budget
        else:
            self.blob_store = BlobStore(blob_store, memory_budget=budget)
        self.blob_threshold = blob_threshold
        self.auto_export = Path(auto_export) if auto_export else None
        self.journal_dir = Path(journal_dir) if journal_dir else None
        self.register_trace = register_trace
        self.sanitize_on_close = sanitize_on_close
        self._owner = concurrent_owner_id()
        self._lock = threading.RLock()
        self._seq = 0
        self._stack: list[str] = []
        self._open_spans: set[str] = set()
        self._finalized: IncidentBundle | None = None
        self._journal_appended: set[str] = set()
        self._chain_prev_hash = "0" * 64
        self._journal_content: dict[str, str] = {}
        self._journal_index = 0
        self._journal_writer: Any = None
        # In "span" mode every offloaded blob is fsynced before end_span returns. Otherwise blobs
        # are fsynced in groups: before each journal commit, and always before the seal.
        self._blob_sync = self.journal_durability == "span"
        self._journal_header: dict[str, Any] | None = None
        self._journal_header_key: str | None = None
        self._span_by_id: dict[str, SageSpan] = {}

    def __enter__(self) -> "SageRecorder":
        if self.register_trace:
            GLOBAL_TRACE_REGISTRY.begin_write(self.bundle.bundle_id, self._owner)
        if self.journal_dir is not None:
            with self._lock:
                self._ensure_journal_writer().write_manifest(self._journal_snapshot())
        return self

    def __exit__(self, exc_type: object, exc: BaseException | None, tb: object) -> None:
        # Always stop the journal writer thread. A writer failure is raised unless that would mask
        # an exception that is already propagating.
        try:
            self._exit(exc)
        except BaseException:
            try:
                self.close_journal()
            except Exception:
                pass
            raise
        try:
            self.close_journal()
        except Exception:
            if exc is None:
                raise
        return None

    def _exit(self, exc: BaseException | None) -> None:
        if self._finalized is None:
            has_errors = any(s.status in {"error", "timeout"} for s in self.bundle.spans)
            if self.bundle.root_cause_hint or has_errors or exc is not None:
                status = "failed"
            else:
                status = "completed"
            try:
                # Empty wraps (no spans) stay valid partial/completed shells.
                if not self.bundle.spans and exc is None:
                    self.bundle.status = status  # type: ignore[assignment]
                    self._finalized = self.bundle
                    if self.register_trace:
                        GLOBAL_TRACE_REGISTRY.end_write(self.bundle.bundle_id, self._owner)
                else:
                    self.finalize(partial=False, status=status)
                if self.auto_export is not None and self._finalized is not None:
                    self.export(self.auto_export, redact=True, partial=False)
            except Exception:
                if self.register_trace:
                    GLOBAL_TRACE_REGISTRY.end_write(self.bundle.bundle_id, self._owner)
                if exc is None:
                    raise
            else:
                if self.register_trace:
                    GLOBAL_TRACE_REGISTRY.end_write(self.bundle.bundle_id, self._owner)
        elif self.register_trace:
            GLOBAL_TRACE_REGISTRY.end_write(self.bundle.bundle_id, self._owner)
        return None

    def start_span(
        self,
        type_or_kind: SpanType | SpanKind | str,
        name: str,
        *,
        parent_id: str | None = None,
        agent_id: str | None = None,
        agent_role: str | None = None,
        inputs: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> SageSpan:
        with self._lock:
            span_type = normalize_type(str(type_or_kind))
            parent = parent_id if parent_id is not None else (self._stack[-1] if self._stack else None)
            span = SageSpan(
                type=span_type,
                name=name,
                parent_id=parent,
                trace_id=self.bundle.bundle_id,
                agent_id=agent_id or self.default_agent_id,
                agent_role=agent_role or self.default_agent_role,
                inputs=inputs or {},
                attributes=attributes or {},
                data=data or {},
                status="ok",
            )
            stamp_span_order(span, self._seq, time.perf_counter_ns())
            self._seq += 1
            self.bundle.add_span(span)
            self._span_by_id[span.span_id] = span
            self._open_spans.add(span.span_id)
            self._stack.append(span.span_id)
            self._finalized = None
            return span

    def end_span(
        self,
        span_id: str,
        *,
        status: SpanStatus | str = "ok",
        outputs: dict[str, Any] | None = None,
        error: Any = None,
        data: dict[str, Any] | None = None,
    ) -> SageSpan:
        span = self._get_span(span_id)
        span.finish(status=normalize_status(status), outputs=outputs, error=error, data=data)
        ensure_typed_data(span)
        self._open_spans.discard(span_id)
        if self._stack and self._stack[-1] == span_id:
            self._stack.pop()
        elif span_id in self._stack:
            self._stack.remove(span_id)
        self._finalized = None

        prepared = None
        if self.sanitize_on_close:
            from sage.journal import prepare_span_for_disk, apply_sanitized_fields

            prepared = prepare_span_for_disk(
                span,
                blob_store=self.blob_store,
                redaction_policy=self.bundle.redaction_policy,
                blob_threshold=self.blob_threshold,
                blob_sync=self._blob_sync,
            )
            apply_sanitized_fields(span, prepared)

        if self.journal_dir is not None:
            self._journal_append(span, prepared)
        return span

    # -- live journal -----------------------------------------------------------------------------

    def _ensure_journal_writer(self) -> Any:
        # Caller holds self._lock.
        writer = self._journal_writer
        if writer is None or writer.closed:
            from sage.journal import LiveJournalWriter

            assert self.journal_dir is not None
            writer = LiveJournalWriter(
                self.journal_dir,
                durability=self.journal_durability,
                batch_interval_ms=self.journal_batch_interval_ms,
                batch_max_spans=self.journal_batch_max_spans,
                pre_commit=self.blob_store.sync_pending,
            )
            self._journal_writer = writer
        return writer

    def _journal_snapshot(self) -> Any:
        """Manifest state for the spans appended so far. The header is rebuilt only when it changes."""
        import json

        from sage.journal import live_manifest_header, snapshot_live_manifest

        bundle = self.bundle
        key = json.dumps(
            [
                bundle.schema_version,
                bundle.bundle_id,
                bundle.title,
                bundle.created_at,
                bundle.source.to_dict(),
                bundle.root_cause_hint,
                bundle.metadata,
                bundle.redactions,
                bundle.redaction_policy,
            ],
            sort_keys=True,
        )
        if key != self._journal_header_key or self._journal_header is None:
            self._journal_header = live_manifest_header(bundle, live=True)
            self._journal_header_key = key
        return snapshot_live_manifest(
            bundle, live=True, chain_tip=self._chain_prev_hash, header=self._journal_header
        )

    def _journal_append(self, span: SageSpan, prepared: SageSpan | None = None) -> None:
        """Append one closed span to the live journal (redacted and offloaded first)."""
        from sage.journal import _jsonl_line, encode_span_record, make_chain_link, prepare_span_for_disk

        with self._lock:
            if self.journal_dir is None or span.span_id in self._journal_appended:
                return
            writer = self._ensure_journal_writer()
            disk_span = prepared or prepare_span_for_disk(
                span,
                blob_store=self.blob_store,
                redaction_policy=self.bundle.redaction_policy,
                blob_threshold=self.blob_threshold,
                blob_sync=self._blob_sync,
            )
            content_hash, span_line = encode_span_record(disk_span)
            content = {disk_span.span_id: content_hash}
            parent_id = disk_span.parent_id
            if parent_id:
                # Every span this recorder journaled is in the map; a parent that is still open
                # has no content hash yet, exactly as before.
                parent_hash = self._journal_content.get(parent_id)
                if parent_hash:
                    content[parent_id] = parent_hash
            link = make_chain_link(
                disk_span, index=self._journal_index, prev_hash=self._chain_prev_hash, content_by_id=content
            )
            previous_tip = self._chain_prev_hash
            self._chain_prev_hash = link["hash"]
            try:
                writer.append(span_line, _jsonl_line(link), self._journal_snapshot())
            except BaseException:
                self._chain_prev_hash = previous_tip
                raise
            self._journal_content[span.span_id] = content_hash
            self._journal_index += 1
            self._journal_appended.add(span.span_id)

    def flush_journal(self) -> None:
        """Block until every span closed so far is in the live journal and fsynced.

        A no-op without ``journal_dir``. Raises ``JournalWriteError`` if the writer thread failed.
        """
        with self._lock:
            writer = self._journal_writer
        if writer is not None and not writer.closed:
            writer.flush(sync=True)

    def close_journal(self) -> None:
        """Flush, fsync, and stop the journal writer thread. Sealing calls this; it is idempotent."""
        with self._lock:
            writer = self._journal_writer
        if writer is not None:
            writer.close()

    @contextmanager
    def span(
        self,
        type_or_kind: SpanType | SpanKind | str,
        name: str,
        *,
        inputs: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        agent_id: str | None = None,
        agent_role: str | None = None,
        status: SpanStatus | str = "ok",
    ) -> Iterator[RecordedSpan]:
        span = self.start_span(
            type_or_kind,
            name,
            inputs=inputs,
            attributes=attributes,
            data=data,
            agent_id=agent_id,
            agent_role=agent_role,
        )
        handle = RecordedSpan(span)
        try:
            yield handle
        except BaseException as exc:
            self.end_span(span.span_id, status="error", error=exc, outputs=span.outputs)
            raise
        else:
            final = span.status if span.status == "error" else normalize_status(status)
            self.end_span(span.span_id, status=final, outputs=span.outputs, data=span.data)

    def agent_step(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("agent", name, **kwargs)

    def chain(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("chain", name, **kwargs)

    def llm_call(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("llm", name, **kwargs)

    def tool_call(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("tool", name, **kwargs)

    def retrieval(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("retrieval", name, **kwargs)

    def guardrail(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("guardrail", name, **kwargs)

    def human_intervention(self, name: str, **kwargs: Any) -> Iterator[RecordedSpan]:
        return self.span("human", name, **kwargs)

    def handoff(
        self,
        name: str,
        *,
        from_agent: str,
        to_agent: str,
        context_passed: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Iterator[RecordedSpan]:
        data = {
            "from_agent": from_agent,
            "to_agent": to_agent,
            "context_passed": context_passed or {},
        }
        attributes = {**(kwargs.pop("attributes", None) or {}), "from_agent": from_agent, "to_agent": to_agent}
        return self.span("handoff", name, data=data, attributes=attributes, agent_id=from_agent, **kwargs)

    def policy_decision(
        self,
        name: str,
        *,
        decision: str,
        inputs: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
        rule_id: str | None = None,
        reason: str | None = None,
    ) -> SageSpan:
        span = self.start_span(
            "policy",
            name,
            inputs=inputs,
            attributes=attributes,
            data={
                "policy_name": name,
                "rule_id": rule_id or name,
                "decision": decision,
                "reason": reason,
                "checked_input": inputs or {},
            },
        )
        status = "error" if decision.lower() in {"deny", "block"} else "ok"
        return self.end_span(
            span.span_id,
            status=status,
            outputs={"decision": decision, "reason": reason},
            error=reason if status == "error" else None,
        )

    def mark_failure(self, span_id: str, *, note: str | None = None) -> None:
        span = self._get_span(span_id)
        span.is_suspected_root_cause = True
        if note and self.sanitize_on_close:
            from sage.audit import _scrub_string, resolve_redaction_rules

            _fragments, patterns = resolve_redaction_rules(self.bundle.redaction_policy)
            note = _scrub_string(note, path="failure_context", redacted_paths=None, value_patterns=patterns)
        span.failure_context = note
        self.bundle.root_cause_hint = span_id
        self.bundle.status = "failed"
        self._finalized = None

    def finalize(
        self,
        *,
        partial: bool = False,
        redact: bool = True,
        status: str | None = None,
        offload_blobs: bool = True,
    ) -> IncidentBundle:
        if self._finalized is not None and not partial:
            return self._finalized

        if self._open_spans and not partial:
            raise RuntimeError(
                f"cannot finalize: open spans remain: {sorted(self._open_spans)}"
            )

        for span in self.bundle.spans:
            ensure_typed_data(span)
            if not span.end_time:
                if partial:
                    span.end_time = utc_now()
                else:
                    raise RuntimeError(f"span {span.span_id} has no end_time")

        final_status = status or (
            "partial"
            if partial
            else (
                "failed"
                if any(s.status == "error" for s in self.bundle.spans)
                else "completed"
            )
        )
        with self._lock:
            # The live journal must be complete and its writer stopped before the seal rewrites it.
            self.close_journal()
            self.blob_store.sync_pending()
            if self.register_trace:
                GLOBAL_TRACE_REGISTRY.begin_write(self.bundle.bundle_id, self._owner)
            try:
                validate_monotonic_chain(self.bundle)
                finalized = finalize_bundle(
                    self.bundle,
                    redact=redact,
                    status=final_status,
                    blob_store=self.blob_store,
                    blob_threshold=self.blob_threshold,
                    offload_blobs=offload_blobs,
                )
                validate_monotonic_chain(finalized)
                if self.register_trace:
                    GLOBAL_TRACE_REGISTRY.finalize_claim(
                        finalized.bundle_id,
                        self._owner,
                        finalized.audit.bundle_hash,
                        len(finalized.spans),
                    )
                self._finalized = finalized
                if self.journal_dir is not None:
                    from sage.journal import save_journal

                    # Rewrite journal with sealed/redacted/CAS-compact form.
                    save_journal(finalized, self.journal_dir)
                return finalized
            except Exception:
                if self.register_trace:
                    GLOBAL_TRACE_REGISTRY.end_write(self.bundle.bundle_id, self._owner)
                raise

    def finalized_bundle(self, *, redact: bool = True) -> IncidentBundle:
        return self.finalize(partial=False, redact=redact)

    def export(self, path: str | Path, *, redact: bool = True, partial: bool = False) -> Path:
        from sage.bundle_io import save_bundle

        bundle = self.finalize(partial=partial, redact=redact, offload_blobs=True)
        return save_bundle(bundle, path)

    def _get_span(self, span_id: str) -> SageSpan:
        span = self._span_by_id.get(span_id)
        if span is not None:
            return span
        # Spans added to the bundle directly (importers, taps) are not in the index.
        for span in self.bundle.spans:
            if span.span_id == span_id:
                return span
        raise KeyError(f"unknown span_id {span_id}")
