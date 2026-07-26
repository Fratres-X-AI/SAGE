from __future__ import annotations

from typing import Any

from sage.schema import IncidentBundle

# Hard cap so cyclic/recursive agent graphs cannot explode inspect output.
MAX_SWIMLANE_EVENTS = 256
MAX_CYCLE_REPORTS = 32


def detect_handoff_cycles(bundle: IncidentBundle) -> list[list[str]]:
    """Return agent-id cycles from handoff edges (A→B→A)."""
    edges: dict[str, set[str]] = {}
    for span in bundle.spans:
        if span.type != "handoff":
            continue
        src = str(span.data.get("from_agent") or span.agent_id or "")
        dst = str(span.data.get("to_agent") or "")
        if not src or not dst:
            continue
        edges.setdefault(src, set()).add(dst)

    cycles: list[list[str]] = []
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def dfs(node: str) -> None:
        if node in visiting:
            if node in stack:
                idx = stack.index(node)
                cycle = stack[idx:] + [node]
                if cycle not in cycles and len(cycles) < MAX_CYCLE_REPORTS:
                    cycles.append(cycle)
            return
        if node in visited:
            return
        visiting.add(node)
        stack.append(node)
        for nxt in sorted(edges.get(node, ())):
            dfs(nxt)
        stack.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(edges):
        dfs(node)
    return cycles


def build_swimlane(bundle: IncidentBundle) -> dict[str, Any]:
    """Bounded multi-agent swimlane that tolerates cyclic handoffs."""
    lanes: dict[str, list[str]] = {}
    truncated = False
    total = 0
    for span in sorted(bundle.spans, key=lambda s: (s.start_time or "", s.span_id)):
        if total >= MAX_SWIMLANE_EVENTS:
            truncated = True
            break
        key = span.agent_id or "unassigned"
        if span.type == "handoff":
            label = (
                f"handoff:{span.data.get('from_agent')}->{span.data.get('to_agent')}"
                f":{span.name}"
            )
        else:
            label = f"{span.type}:{span.name}"
        lanes.setdefault(key, []).append(label)
        total += 1
    cycles = detect_handoff_cycles(bundle)
    return {
        "lanes": lanes,
        "cycles": cycles,
        "cycle_count": len(cycles),
        "truncated": truncated,
        "event_count": total,
        "max_events": MAX_SWIMLANE_EVENTS,
    }


def build_inspect_report(bundle: IncidentBundle, *, view: str = "all") -> dict[str, Any]:
    errors = [s for s in bundle.spans if s.status in {"error", "timeout"}]
    timeline = [
        {
            "span_id": s.span_id,
            "type": s.type,
            "name": s.name,
            "status": s.status,
            "agent_id": s.agent_id,
            "parent_id": s.parent_id,
            "start_time": s.start_time,
            "end_time": s.end_time,
        }
        for s in sorted(bundle.spans, key=lambda x: (x.start_time or "", x.span_id))
    ]
    critical = [s.span_id for s in bundle.spans if s.is_suspected_root_cause]
    if bundle.root_cause_hint:
        if isinstance(bundle.root_cause_hint, list):
            critical.extend(bundle.root_cause_hint)
        else:
            critical.append(bundle.root_cause_hint)

    swimlane = build_swimlane(bundle) if view in {"swimlane", "all"} else None
    return {
        "ok": True,
        "bundle_id": bundle.bundle_id,
        "run_id": bundle.run_id,
        "title": bundle.title,
        "status": bundle.status,
        "schema_version": bundle.schema_version,
        "span_count": len(bundle.spans),
        "audit_ok": True,
        "bundle_hash": bundle.audit.bundle_hash,
        "root_cause_hint": bundle.root_cause_hint,
        "critical_path": list(dict.fromkeys(critical)),
        "errors": [
            {
                "span_id": s.span_id,
                "type": s.type,
                "name": s.name,
                "message": s.error.message if s.error else None,
            }
            for s in errors
        ],
        "timeline": timeline if view in {"timeline", "all"} else timeline[:10],
        "swimlane": swimlane,
        "kinds": {
            t: sum(1 for s in bundle.spans if s.type == t)
            for t in sorted({s.type for s in bundle.spans})
        },
    }
