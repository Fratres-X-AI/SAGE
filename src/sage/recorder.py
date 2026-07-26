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
    ) -> None:
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

    def __enter__(self) -> "SageRecorder":
        if self.register_trace:
            GLOBAL_TRACE_REGISTRY.begin_write(self.bundle.bundle_id, self._owner)
        if self.journal_dir is not None:
            from sage.journal import write_live_manifest

            self.journal_dir.mkdir(parents=True, exist_ok=True)
            write_live_manifest(
                self.bundle,
                self.journal_dir,
                live=True,
                chain_tip=self._chain_prev_hash,
            )
        return self

    def __exit__(self, exc_type: object, exc: BaseException | None, tb: object) -> None:
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
            )
            apply_sanitized_fields(span, prepared)

        if self.journal_dir is not None and span_id not in self._journal_appended:
            from sage.journal import append_live_span, write_live_manifest

            _disk_span, link = append_live_span(
                self.journal_dir,
                span,
                index=self._journal_index,
                prev_hash=self._chain_prev_hash,
                blob_store=self.blob_store,
                redaction_policy=self.bundle.redaction_policy,
                blob_threshold=self.blob_threshold,
                content_by_id=self._journal_content,
                disk_span=prepared,
            )
            self._journal_content[span.span_id] = link["content_hash"]
            self._chain_prev_hash = link["hash"]
            self._journal_index += 1
            self._journal_appended.add(span_id)
            write_live_manifest(
                self.bundle,
                self.journal_dir,
                live=True,
                chain_tip=self._chain_prev_hash,
            )
        return span

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
        for span in self.bundle.spans:
            if span.span_id == span_id:
                return span
        raise KeyError(f"unknown span_id {span_id}")
