from __future__ import annotations

import json
from typing import Any

from sage.blobs import is_blob_ref
from sage.bundle_io import load_bundle
from sage.inspect_views import build_inspect_report, detect_handoff_cycles
from sage.replay import pure_recorded_replay


def _require_textual():
    try:
        import textual  # noqa: F401
        from textual.app import App
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.widgets import Footer, Header, RichLog, Static, Tree
    except ImportError as exc:
        raise SystemExit(
            json.dumps(
                {
                    "ok": False,
                    "error": "Textual TUI requires optional deps. Install with: pip install -e '.[tui]'",
                }
            )
        ) from exc
    return App, Binding, Horizontal, Vertical, Footer, Header, RichLog, Static, Tree


def _span_label(span) -> str:
    flag = " !" if span.is_suspected_root_cause else ""
    err = " ERR" if span.status in {"error", "timeout"} else ""
    agent = f" [{span.agent_id}]" if span.agent_id else ""
    return f"{span.type}:{span.name}{agent}{err}{flag}"


def _highlight_redactions(text: str) -> str:
    return text.replace("[REDACTED]", "[bold red][REDACTED][/]")


def run_inspect_tui(path: str, *, view: str = "all") -> int:
    App, Binding, Horizontal, Vertical, Footer, Header, RichLog, Static, Tree = _require_textual()

    bundle = load_bundle(path, verify=True, rehydrate=True)
    report = build_inspect_report(bundle, view=view)
    cycles = detect_handoff_cycles(bundle)

    class SageInspectApp(App):
        CSS = """
        Screen { layout: vertical; }
        #title { height: 3; padding: 1; background: #1b2a33; color: #e8f1f5; }
        #body { height: 1fr; }
        #tree { width: 42%; border: solid #3d5a68; }
        #detail { width: 1fr; border: solid #3d5a68; }
        .redacted { color: red; }
        """
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("r", "replay", "Replay"),
            Binding("enter", "expand", "Expand", show=False),
        ]

        def __init__(self) -> None:
            super().__init__()
            self.bundle = bundle
            self.selected_span_id: str | None = None

        def compose(self):
            yield Header(show_clock=True)
            yield Static(
                f"SAGE inspect  ·  {bundle.title}  ·  {bundle.bundle_id}"
                + (f"  ·  cycles={len(cycles)}" if cycles else ""),
                id="title",
            )
            with Horizontal(id="body"):
                yield Tree("Swimlane / Spans", id="tree")
                with Vertical(id="detail"):
                    yield RichLog(id="detail_log", highlight=True, markup=True)
            yield Footer()

        def on_mount(self) -> None:
            tree = self.query_one(Tree)
            tree.root.expand()
            lanes = (report.get("swimlane") or {}).get("lanes") or {}
            if lanes:
                for agent, span_ids in lanes.items():
                    branch = tree.root.add(f"agent:{agent}", expand=True)
                    for span_id in span_ids:
                        span = next((s for s in bundle.spans if s.span_id == span_id), None)
                        if span:
                            branch.add_leaf(_span_label(span), data=span.span_id)
            else:
                for span in bundle.spans:
                    tree.root.add_leaf(_span_label(span), data=span.span_id)
            log = self.query_one("#detail_log", RichLog)
            log.write(_highlight_redactions(json.dumps(report.get("summary") or report, indent=2)))

        def on_tree_node_selected(self, event) -> None:
            span_id = event.node.data
            if not isinstance(span_id, str):
                return
            self.selected_span_id = span_id
            span = next((s for s in self.bundle.spans if s.span_id == span_id), None)
            if not span:
                return
            log = self.query_one("#detail_log", RichLog)
            log.clear()
            payload: dict[str, Any] = span.to_dict()
            # Annotate any residual blob refs (should be rare after rehydrate).
            for field in ("inputs", "outputs", "data"):
                value = getattr(span, field)
                if is_blob_ref(value):
                    payload[field] = {"note": "blob ref", **value}
            text = json.dumps(payload, indent=2, default=str)
            log.write(_highlight_redactions(text))

        def action_replay(self) -> None:
            log = self.query_one("#detail_log", RichLog)
            result = pure_recorded_replay(self.bundle)
            log.write(
                "\n[bold cyan]Replay[/] "
                + ("[green]OK[/]" if result.ok else "[red]DIVERGED[/]")
                + f" status={result.final_status}"
            )
            if result.divergences:
                log.write(_highlight_redactions(json.dumps([d.__dict__ for d in result.divergences], indent=2)))

        def action_expand(self) -> None:
            tree = self.query_one(Tree)
            if tree.cursor_node:
                tree.cursor_node.expand()

    SageInspectApp().run()
    return 0
