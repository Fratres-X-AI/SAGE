from __future__ import annotations

from pathlib import Path

from sage.schema import IncidentBundle


def _short_id(bundle: IncidentBundle) -> str:
    return (bundle.bundle_id or bundle.run_id).replace("-", "")[-12:]


def _failure_signature(bundle: IncidentBundle) -> tuple[str | None, str | None, str | None]:
    hint = bundle.root_cause_hint
    if isinstance(hint, list):
        hint = hint[0] if hint else None
    for span in bundle.spans:
        if span.is_suspected_root_cause or (hint and span.span_id == hint):
            msg = span.error.message if span.error else None
            return span.span_id, span.status, msg
    for span in bundle.spans:
        if span.status == "error":
            msg = span.error.message if span.error else None
            return span.span_id, span.status, msg
    return None, None, None


def generate_pytest(
    bundle: IncidentBundle,
    *,
    test_name: str | None = None,
    with_heal: bool = False,
    heal_span_id: str | None = None,
    secondary_bundle_name: str | None = None,
) -> str:
    short = _short_id(bundle)
    name = test_name or f"test_incident_{short}"
    critical_id, critical_status, error_message = _failure_signature(bundle)
    critical_id = critical_id or ""
    error_message = (error_message or "").replace("\\", "\\\\").replace('"', '\\"')
    failure_note = bundle.metadata.get("failure_mode") or bundle.title
    heal_id = heal_span_id or critical_id or ""

    lines = [
        '"""Auto-generated SAGE regression test.',
        "",
        f"Failure mode: {failure_note}",
        "This test replays the recorded incident cassette (no live LLM/tool calls).",
        '"""',
        "",
        "from pathlib import Path",
        "",
        "from sage.bundle_io import load_bundle",
        "from sage.diff import diff_bundles",
        "from sage.replay import apply_heal, pure_recorded_replay",
        "",
        "",
        f"def {name}() -> None:",
        f'    """Reproduce incident {bundle.bundle_id}: {failure_note}."""',
        f'    bundle_path = Path(__file__).resolve().parent / "{bundle.bundle_id}.sage.json"',
        "    recorded = load_bundle(bundle_path, verify=True, rehydrate=True)",
        "    result = pure_recorded_replay(recorded)",
        "",
        "    # Primary failure signature from the original incident",
        f'    assert recorded.status == "{bundle.status}"',
        "    assert result.final_status == recorded.status",
    ]
    if critical_id:
        lines += [
            f'    critical = result.get_span("{critical_id}")',
            "    assert critical is not None, 'critical span missing from replay'",
            f'    assert critical.status == "{critical_status or "error"}"',
        ]
        if error_message:
            lines.append(
                f'    assert "{error_message}" in (critical.error.message if critical.error else "")'
            )
    else:
        lines.append('    assert any(span.status == "error" for span in recorded.spans)')

    if with_heal and heal_id:
        if secondary_bundle_name:
            lines += [
                "",
                "    # Heal fixed the original fault but introduced a secondary divergence.",
                "    # Linked trace captures the new failure context.",
                f'    secondary_path = Path(__file__).resolve().parent / "{secondary_bundle_name}"',
                "    secondary = load_bundle(secondary_path, verify=True, rehydrate=True)",
                '    assert secondary.metadata.get("healed_from_bundle_id") == recorded.bundle_id',
                '    assert secondary.metadata.get("secondary_failure") is True',
                '    assert secondary.status == "failed"',
                "    report = diff_bundles(recorded, secondary)",
                "    assert not report.ok",
                "    assert report.first_divergence_span_id is not None",
                "    assert pure_recorded_replay(secondary).final_status == \"failed\"",
            ]
        else:
            lines += [
                "",
                "    # Counterfactual: healing the suspected root-cause span should clear the failure",
                f'    healed = apply_heal(recorded, span_id="{heal_id}")',
                "    healed_result = pure_recorded_replay(healed)",
                '    assert healed.status == "completed"',
                '    assert healed_result.final_status == "completed"',
            ]
    lines.append("")
    return "\n".join(lines)


def write_regression_test(
    bundle: IncidentBundle,
    directory: str | Path,
    *,
    test_name: str | None = None,
    with_heal: bool = False,
    heal_span_id: str | None = None,
    secondary_bundle: IncidentBundle | None = None,
) -> tuple[Path, Path]:
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    short = _short_id(bundle)
    resolved_name = test_name or f"test_incident_{short}"
    bundle_path = out_dir / f"{bundle.bundle_id}.sage.json"
    test_path = out_dir / f"{resolved_name}.py"
    from sage.bundle_io import save_bundle

    save_bundle(bundle, bundle_path)
    secondary_name = None
    if secondary_bundle is not None:
        secondary_name = f"{secondary_bundle.bundle_id}.sage.json"
        save_bundle(secondary_bundle, out_dir / secondary_name)
    test_path.write_text(
        generate_pytest(
            bundle,
            test_name=resolved_name,
            with_heal=with_heal,
            heal_span_id=heal_span_id,
            secondary_bundle_name=secondary_name,
        ),
        encoding="utf-8",
    )
    return bundle_path, test_path


def write_heal_boundary_test(
    original: IncidentBundle,
    healed_secondary: IncidentBundle,
    directory: str | Path,
    *,
    heal_span_id: str,
    test_name: str | None = None,
) -> tuple[Path, Path]:
    """Generate a regression that links original failure to a secondary post-heal trace.

    Runs security boundary validation first; adversarial layout/parent tampering
    raises SecurityDivergence and aborts generation (breaks the heal chain).
    """
    from sage.security import validate_heal_boundary

    validate_heal_boundary(
        original,
        healed_secondary,
        heal_span_id=heal_span_id,
        allow_secondary_failure=True,
    )
    return write_regression_test(
        original,
        directory,
        test_name=test_name,
        with_heal=True,
        heal_span_id=heal_span_id,
        secondary_bundle=healed_secondary,
    )
