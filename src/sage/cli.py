from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sage.bundle_io import load_bundle, save_bundle
from sage.diff import diff_bundles
from sage.importers.openinference import load_openinference_file
from sage.replay import pure_recorded_replay, replay_bundle
from sage.regression import write_regression_test


def _fail(message: str, code: int = 1) -> int:
    print(json.dumps({"ok": False, "error": message}, indent=2), file=sys.stderr)
    return code


def _load_verified(path: str, *, rehydrate: bool = True):
    """Verify compact on-disk form, then optionally rehydrate CAS blobs."""
    try:
        return load_bundle(path, verify=True, rehydrate=rehydrate)
    except Exception as exc:
        raise SystemExit(_fail(str(exc))) from exc


def _cmd_inspect(args: argparse.Namespace) -> int:
    from sage.fault import audit_path, recover_bundle_carcass
    from sage.inspect_views import build_inspect_report
    from sage.journal import is_journal_path, recover_journal

    try:
        if getattr(args, "tui", False):
            from sage.tui_app import run_inspect_tui

            return run_inspect_tui(args.path, view=args.view)
        try:
            bundle = _load_verified(args.path, rehydrate=True)
            payload = build_inspect_report(bundle, view=args.view)
            print(json.dumps(payload, indent=2))
            return 0
        except SystemExit:
            if is_journal_path(args.path):
                report = recover_journal(args.path)
            else:
                report = recover_bundle_carcass(args.path)
            print(json.dumps({"ok": False, "mode": "fault_recovery", **report.to_dict()}, indent=2))
            return 2
    except Exception as exc:
        report = audit_path(args.path)
        if report.boundary is not None:
            print(json.dumps({"ok": False, "mode": "fault_recovery", **report.to_dict()}, indent=2))
            return 2
        return _fail(str(exc))


def _cmd_export_journal(args: argparse.Namespace) -> int:
    try:
        bundle = _load_verified(args.path, rehydrate=False)
        out = save_bundle(bundle, args.out, format="journal")
    except SystemExit as exc:
        return int(exc.code or 1)
    except Exception as exc:
        return _fail(str(exc))
    print(str(out))
    return 0


def _cmd_verify_journal(args: argparse.Namespace) -> int:
    from sage.journal import verify_journal

    try:
        report = verify_journal(args.path, allow_live=not args.require_sealed)
    except Exception as exc:
        return _fail(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from sage.errors import FaultRecoveryError
    from sage.receipt import write_receipt
    from sage.verify import verify_artifact

    require_sealed = bool(args.require_sealed) and not bool(getattr(args, "allow_live", False))
    try:
        report = verify_artifact(
            args.path,
            require_sealed=require_sealed,
            blob_root=args.blob_root,
            hmac_key=args.hmac_key,
            check_blobs=not args.skip_blobs,
            check_witness=args.witness,
            witness_key=args.witness_key,
            policy=args.policy,
            require_signature=bool(getattr(args, "require_signature", False)),
            public_key=getattr(args, "public_key", None),
            allow_tofu_signature=bool(getattr(args, "allow_tofu_signature", False)),
            key_id=args.key_id,
            key_ring=args.key_ring,
        )
        if args.receipt:
            write_receipt(
                report,
                args.receipt,
                hmac_key=args.verify_key or args.hmac_key,
                key_id=args.key_id,
                key_ring=args.key_ring,
            )
            report["receipt_path"] = args.receipt
    except FaultRecoveryError as exc:
        return _fail(str(exc), code=2)
    except Exception as exc:
        return _fail(str(exc), code=1)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    from sage.receipt import verify_receipt

    try:
        report = verify_receipt(
            args.path,
            hmac_key=args.verify_key or args.hmac_key,
            key_id=args.key_id,
            key_ring=args.key_ring,
            expect_fingerprint=args.expect_fingerprint,
            allow_unsigned=bool(getattr(args, "allow_unsigned", False)),
        )
    except Exception as exc:
        return _fail(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_handoff(args: argparse.Namespace) -> int:
    from sage.handoff import create_handoff

    try:
        out = create_handoff(
            args.path,
            args.out_dir,
            hmac_key=args.hmac_key,
            policy=args.policy,
            actor=args.actor,
            key_id=args.key_id,
        )
    except Exception as exc:
        return _fail(str(exc))
    print(str(out))
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    from sage.version import version_report

    print(json.dumps(version_report(), indent=2, sort_keys=True))
    return 0


def _cmd_pack(args: argparse.Namespace) -> int:
    from sage.pack import pack_artifact

    try:
        out = pack_artifact(
            args.path,
            args.out,
            hmac_key=args.hmac_key,
            pack_version=args.pack_version,
            key_id=args.key_id,
            sign=bool(getattr(args, "sign", False)) or None,
        )
    except Exception as exc:
        return _fail(str(exc))
    print(str(out))
    return 0


def _cmd_unpack(args: argparse.Namespace) -> int:
    from sage.pack import unpack_artifact

    try:
        out = unpack_artifact(
            args.path,
            args.out_dir,
            blob_root=args.blob_root,
            hmac_key=args.hmac_key,
            quarantine=not bool(getattr(args, "no_quarantine", False)),
            require_signature=bool(getattr(args, "require_signature", False)),
            public_key=getattr(args, "public_key", None),
            allow_tofu_signature=bool(getattr(args, "allow_tofu_signature", False)),
            key_id=getattr(args, "key_id", None),
            key_ring=getattr(args, "key_ring", None),
        )
    except Exception as exc:
        return _fail(str(exc))
    print(str(out))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    from sage.doctor import run_doctor

    report = run_doctor(deep=not args.quick)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    from sage.signing import write_keypair

    try:
        out = write_keypair(args.out)
    except Exception as exc:
        return _fail(str(exc))
    print(str(out))
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    from sage.fault import audit_path

    report = audit_path(args.path)
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 2


def _cmd_import(args: argparse.Namespace) -> int:
    try:
        if args.format == "openinference":
            bundle = load_openinference_file(args.path, title=args.title)
        else:
            bundle = _load_verified(args.path, rehydrate=False)
        save_bundle(bundle, args.out)
    except SystemExit as exc:
        return int(exc.code or 1)
    except Exception as exc:
        return _fail(str(exc))
    print(args.out)
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    try:
        recorded = _load_verified(args.recorded, rehydrate=True)
        if args.candidate:
            if getattr(args, "unverified_candidate", False):
                candidate = load_bundle(args.candidate, verify=False, rehydrate=True)
            else:
                candidate = load_bundle(args.candidate, verify=True, rehydrate=True)
            result = replay_bundle(
                recorded,
                candidate_bundle=candidate,
                strict=not args.loose,
                live_tools=args.live_tools,
            )
        else:
            result = pure_recorded_replay(recorded)
    except SystemExit as exc:
        return int(exc.code or 1)
    except Exception as exc:
        return _fail(str(exc))

    payload = {
        "ok": result.ok,
        "final_status": result.final_status,
        "error_message": result.error_message,
        "matched": result.matched,
        "divergences": [d.__dict__ for d in result.divergences],
        "report": result.report.to_dict() if result.report else None,
    }
    print(json.dumps(payload, indent=2))
    return 0 if result.ok else 1


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        left = _load_verified(args.left, rehydrate=True)
        if getattr(args, "unsafe_right", False):
            right = load_bundle(args.right, verify=False, rehydrate=True)
        else:
            right = load_bundle(args.right, verify=True, rehydrate=True)
        report = diff_bundles(left, right)
    except SystemExit as exc:
        return int(exc.code or 1)
    except Exception as exc:
        return _fail(str(exc))
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_make_test(args: argparse.Namespace) -> int:
    try:
        bundle = _load_verified(args.path, rehydrate=True)
        heal_span = args.heal_span
        if args.with_heal and not heal_span:
            if isinstance(bundle.root_cause_hint, str):
                heal_span = bundle.root_cause_hint
            else:
                for span in bundle.spans:
                    if span.is_suspected_root_cause:
                        heal_span = span.span_id
                        break
        bundle_path, test_path = write_regression_test(
            bundle,
            args.out_dir,
            test_name=args.name,
            with_heal=args.with_heal,
            heal_span_id=heal_span,
        )
    except Exception as exc:
        return _fail(str(exc))
    print(json.dumps({"bundle": str(bundle_path), "test": str(test_path)}, indent=2))
    return 0


def _cmd_attribute(args: argparse.Namespace) -> int:
    from sage.attribution.engine import attribution_report

    try:
        bundle = _load_verified(args.path, rehydrate=True)
        report = attribution_report(
            bundle,
            method=args.method,
            model_path=args.model,
            top_k=args.top_k,
        )
    except SystemExit as exc:
        return int(exc.code or 1)
    except Exception as exc:
        return _fail(str(exc))
    print(json.dumps(report, indent=2))
    return 0


def _cmd_export_otel(args: argparse.Namespace) -> int:
    from sage.otel_export import export_bundle_to_otel

    try:
        # Export from compact verified form so OTel carries blob refs + metadata;
        # rehydrate optionally for full attribute payloads.
        bundle = _load_verified(args.path, rehydrate=not args.compact)
        payload = export_bundle_to_otel(bundle, service_name=args.service_name)
        out = Path(args.out) if args.out else None
        text = json.dumps(payload, indent=2)
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(str(out))
        else:
            print(text)
    except SystemExit as exc:
        return int(exc.code or 1)
    except Exception as exc:
        return _fail(str(exc))
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    from sage.attribution.train import TrainConfig, train_attribution_model

    metrics = train_attribution_model(
        TrainConfig(
            n_train=args.n_train,
            n_val=args.n_val,
            epochs=args.epochs,
            batch_size=args.batch_size,
            out_dir=Path(args.out_dir),
            seed=args.seed,
        )
    )
    print(json.dumps(metrics, indent=2))
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from sage.attribution.bench import run_benchmark

    payload = run_benchmark(
        n=args.n,
        seed=args.seed,
        model_path=args.model,
        corpus_dir=args.corpus,
        out_path=args.out,
    )
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_synth(args: argparse.Namespace) -> int:
    from sage.synth.failures import generate_corpus

    items = generate_corpus(args.n, seed=args.seed, out_dir=args.out_dir)
    print(json.dumps({"count": len(items), "out_dir": args.out_dir}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sage",
        description="SAGE agent incident forensics (fail-closed security tool)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    version = sub.add_parser("version", help="Print package + frozen format versions")
    version.set_defaults(func=_cmd_version)

    doctor = sub.add_parser("doctor", help="Environment / integrity self-check")
    doctor.add_argument("--quick", action="store_true", help="Skip mini verify loop")
    doctor.set_defaults(func=_cmd_doctor)

    keygen = sub.add_parser(
        "keygen",
        help="Generate Ed25519 keypair (requires: pip install -e '.[sign]')",
    )
    keygen.add_argument("--out", required=True, help="Output JSON path (keep private)")
    keygen.set_defaults(func=_cmd_keygen)

    inspect = sub.add_parser("inspect", help="Validate and summarize an incident bundle")
    inspect.add_argument("path")
    inspect.add_argument("--view", choices=["summary", "timeline", "swimlane", "all"], default="all")
    inspect.add_argument(
        "--tui",
        action="store_true",
        help="Interactive Textual TUI (requires: pip install -e '.[tui]')",
    )
    inspect.set_defaults(func=_cmd_inspect)

    audit = sub.add_parser(
        "audit",
        help="Verify bundle_hash or recover last valid SHA-256 crash boundary from a carcass",
    )
    audit.add_argument("path")
    audit.set_defaults(func=_cmd_audit)

    export_otel = sub.add_parser(
        "export-otel",
        help="Compile a verified .sage bundle into OpenTelemetry-compatible JSON",
    )
    export_otel.add_argument("path")
    export_otel.add_argument("--out", default=None)
    export_otel.add_argument("--service-name", default="sage-agent")
    export_otel.add_argument(
        "--compact",
        action="store_true",
        help="Keep CAS blob refs instead of rehydrating large payloads",
    )
    export_otel.set_defaults(func=_cmd_export_otel)

    imp = sub.add_parser("import", help="Import a trace into a SAGE bundle")
    imp.add_argument("path")
    imp.add_argument("--format", choices=["openinference", "sage"], default="openinference")
    imp.add_argument("--title", default=None)
    imp.add_argument("--out", required=True)
    imp.set_defaults(func=_cmd_import)

    replay = sub.add_parser("replay", help="Pure recorded replay (or compare against a candidate)")
    replay.add_argument("recorded")
    replay.add_argument("candidate", nargs="?", default=None)
    replay.add_argument("--loose", action="store_true")
    replay.add_argument("--live-tools", action="store_true", help="Non-default hybrid mode")
    replay.add_argument(
        "--unverified-candidate",
        action="store_true",
        help="Research-only: load candidate without audit verify (unsafe)",
    )
    replay.set_defaults(func=_cmd_replay)

    diff = sub.add_parser("diff", help="Structured divergence report between two bundles")
    diff.add_argument("left")
    diff.add_argument("right")
    diff.add_argument(
        "--unsafe-right",
        action="store_true",
        help="Research-only: load right bundle without audit verify (unsafe)",
    )
    diff.set_defaults(func=_cmd_diff)

    make_test = sub.add_parser("make-test", help="Generate pytest regression from a bundle")
    make_test.add_argument("path")
    make_test.add_argument("--out-dir", default="tests/generated")
    make_test.add_argument("--name", default=None)
    make_test.add_argument("--with-heal", action="store_true")
    make_test.add_argument("--heal-span", default=None)
    make_test.set_defaults(func=_cmd_make_test)

    journal = sub.add_parser(
        "export-journal",
        help="Export a verified bundle to crash-safe journal (spans.jsonl + chain.jsonl + sealed manifest)",
    )
    journal.add_argument("path")
    journal.add_argument("--out", required=True, help="Output directory")
    journal.set_defaults(func=_cmd_export_journal)

    verify_j = sub.add_parser(
        "verify-journal",
        help="Fail-closed verify of journal seal / chain tip / merkle (CI gate)",
    )
    verify_j.add_argument("path", help="Journal directory")
    verify_j.add_argument(
        "--require-sealed",
        action="store_true",
        help="Refuse live (unsealed) journals",
    )
    verify_j.set_defaults(func=_cmd_verify_journal)

    verify = sub.add_parser(
        "verify",
        help="Unified fail-closed verify for .sage.json / journal / .sage.tar.gz (CI gate)",
    )
    verify.add_argument("path")
    verify.add_argument(
        "--require-sealed",
        action="store_true",
        default=True,
        help="Refuse live journals (default: true)",
    )
    verify.add_argument(
        "--allow-live",
        action="store_true",
        help="Allow unsealed live journals",
    )
    verify.add_argument("--blob-root", default=None)
    verify.add_argument("--hmac-key", default=None, help="Pack HMAC key (or SAGE_PACK_KEY)")
    verify.add_argument("--skip-blobs", action="store_true", help="Skip CAS inventory verify")
    verify.add_argument("--witness", action="store_true", help="Require/verify witness.jsonl custody log")
    verify.add_argument("--witness-key", default=None, help="Witness HMAC key (or SAGE_WITNESS_KEY)")
    verify.add_argument("--policy", default=None, help="Path to sage.verify.policy.v1 JSON")
    verify.add_argument("--receipt", default=None, help="Write HMAC-sealed verify.receipt.json")
    verify.add_argument("--verify-key", default=None, help="Receipt HMAC key (or SAGE_VERIFY_KEY)")
    verify.add_argument("--key-id", default=None)
    verify.add_argument("--key-ring", default=None, help="Path to sage.keys.v1 JSON")
    verify.add_argument(
        "--require-signature",
        action="store_true",
        help="Require Ed25519 pack signature with pinned public key (TOFU refused)",
    )
    verify.add_argument(
        "--public-key",
        default=None,
        help="Pinned Ed25519 public key (or SAGE_SIGN_PUBLIC_KEY / key ring)",
    )
    verify.add_argument(
        "--allow-tofu-signature",
        action="store_true",
        help="Unsafe: accept embedded signature public_key without pin",
    )
    verify.set_defaults(func=_cmd_verify)

    verify_r = sub.add_parser("verify-receipt", help="Verify an HMAC-sealed verification receipt")
    verify_r.add_argument("path")
    verify_r.add_argument("--hmac-key", default=None)
    verify_r.add_argument("--verify-key", default=None)
    verify_r.add_argument("--key-id", default=None)
    verify_r.add_argument("--key-ring", default=None)
    verify_r.add_argument("--expect-fingerprint", default=None)
    verify_r.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Compatibility only: accept receipts without HMAC (unsafe)",
    )
    verify_r.set_defaults(func=_cmd_verify_receipt)

    handoff = sub.add_parser("handoff", help="Build offline evidence handoff kit (pack+policy+receipt)")
    handoff.add_argument("path")
    handoff.add_argument("--out-dir", required=True)
    handoff.add_argument("--hmac-key", default=None)
    handoff.add_argument("--policy", default=None)
    handoff.add_argument("--actor", default="handoff")
    handoff.add_argument("--key-id", default=None)
    handoff.set_defaults(func=_cmd_handoff)

    pack = sub.add_parser("pack", help="Pack bundle/journal + CAS blobs into portable .sage.tar.gz")
    pack.add_argument("path")
    pack.add_argument("--out", required=True)
    pack.add_argument(
        "--hmac-key",
        default=None,
        help="HMAC key for pack attestation (or set SAGE_PACK_KEY)",
    )
    pack.add_argument("--pack-version", type=int, default=2, choices=[1, 2])
    pack.add_argument("--key-id", default=None)
    pack.add_argument(
        "--sign",
        action="store_true",
        help="Also Ed25519-sign custody payload (needs SAGE_SIGN_PRIVATE_KEY / .[sign])",
    )
    pack.set_defaults(func=_cmd_pack)

    unpack = sub.add_parser("unpack", help="Unpack .sage.tar.gz into journal + local blob store")
    unpack.add_argument("path")
    unpack.add_argument("--out-dir", required=True)
    unpack.add_argument("--blob-root", default=None)
    unpack.add_argument(
        "--hmac-key",
        default=None,
        help="HMAC key to verify pack attestation (or set SAGE_PACK_KEY)",
    )
    unpack.add_argument(
        "--no-quarantine",
        action="store_true",
        help="Extract directly to out-dir (unsafe; default quarantines until verify)",
    )
    unpack.add_argument(
        "--require-signature",
        action="store_true",
        help="Require Ed25519 pack signature with pinned public key (TOFU refused)",
    )
    unpack.add_argument(
        "--public-key",
        default=None,
        help="Pinned Ed25519 public key (or SAGE_SIGN_PUBLIC_KEY / key ring)",
    )
    unpack.add_argument("--key-id", default=None)
    unpack.add_argument("--key-ring", default=None, help="Path to sage.keys.v1 JSON")
    unpack.add_argument(
        "--allow-tofu-signature",
        action="store_true",
        help="Unsafe: accept embedded signature public_key without pin",
    )
    unpack.set_defaults(func=_cmd_unpack)

    # Research surface — explicitly non-forensic; not part of custody claims.
    research = sub.add_parser(
        "research",
        help="NON-FORENSIC research harness (attribution/synth/train) — not for evidence custody",
    )
    research_sub = research.add_subparsers(dest="research_command", required=True)

    attribute = research_sub.add_parser("attribute", help="Rank root-cause spans (research)")
    attribute.add_argument("path")
    attribute.add_argument(
        "--method",
        choices=["auto", "heuristic", "counterfactual", "neural", "ensemble"],
        default="auto",
    )
    attribute.add_argument("--model", default="artifacts/span_cause.pt")
    attribute.add_argument("--top-k", type=int, default=5)
    attribute.set_defaults(func=_cmd_attribute)

    train = research_sub.add_parser("train", help="Train span-cause model (research)")
    train.add_argument("--n-train", type=int, default=4000)
    train.add_argument("--n-val", type=int, default=800)
    train.add_argument("--epochs", type=int, default=12)
    train.add_argument("--batch-size", type=int, default=64)
    train.add_argument("--out-dir", default="artifacts")
    train.add_argument("--seed", type=int, default=7)
    train.set_defaults(func=_cmd_train)

    bench = research_sub.add_parser("bench", help="Benchmark attribution (research)")
    bench.add_argument("--n", type=int, default=1000)
    bench.add_argument("--seed", type=int, default=99)
    bench.add_argument("--model", default="artifacts/span_cause.pt")
    bench.add_argument("--corpus", default=None)
    bench.add_argument("--out", default="artifacts/bench.json")
    bench.set_defaults(func=_cmd_bench)

    synth = research_sub.add_parser("synth", help="Synthetic failure corpus (research)")
    synth.add_argument("--n", type=int, default=1000)
    synth.add_argument("--seed", type=int, default=7)
    synth.add_argument("--out-dir", default="artifacts/corpus")
    synth.set_defaults(func=_cmd_synth)

    # Research-only under `sage research *`. Top-level aliases removed (2.1.1).
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    code = args.func(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main(sys.argv[1:])
