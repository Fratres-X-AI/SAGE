#!/usr/bin/env python3
"""Consultancy pilot demonstration: a synthetic client-support workflow recorded through real LangChain.

    python examples/consultancy_demo.py --scenario tool-error --mode sync --out demo-runs/run-01

Requires ``pip install "sage-incident-bundles[langchain,sign]"`` (or the same extras from a wheel).
Everything here is synthetic: fictional customer, fictional account, fictional credentials, and a
deterministic test model (``langchain_core`` ``FakeListChatModel``). No network or model provider is used.

Output layout (``--out`` must not already contain files):

    <out>/handoff/    shareable evidence kit (pack, policy, receipt, verifier, guide, summary, build record)
    <out>/keys/       producer key material: never share this directory with the kit
    <out>/producer/   local recording workspace (journal + blob store) used to build the pack
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("success", "tool-error", "tool-timeout")
MODES = ("sync", "async")
MODEL_LABEL = "deterministic test model (langchain_core FakeListChatModel); not a live model provider"

# Fictional data only. The token below is a synthetic marker used to demonstrate redaction.
CUSTOMER = {"name": "Dana Whitfield (fictional)", "account_id": "ACCT-000123", "city": "Springfield (fictional)"}
SYNTHETIC_API_TOKEN = "sk-demoFICTIONAL0000000000"
SUPPORT_REQUEST = (
    f"Hi, this is {CUSTOMER['name']}. Where is my order for account {CUSTOMER['account_id']}? "
    f"Our integration sends Bearer {SYNTHETIC_API_TOKEN} if that helps."
)
TOOL_BUDGET_S = 5.0
SIMULATED_SERVICE_LATENCY_S = 30.0

NOT_ESTABLISHED = (
    "Whether any statement made by the agent or model was true.",
    "That every event in the application was captured; only the instrumented workflow is recorded.",
    "The root cause of the failure; the summary reports where it was recorded, not why it happened.",
    "That all sensitive data was removed; redaction applies the configured key and pattern rules only.",
    "Hardware-backed identity of the producer, legal admissibility, or regulatory compliance.",
)


class AccountServiceError(RuntimeError):
    """Synthetic downstream account-service failure."""


class SimulatedClock:
    """Deterministic clock: advancing it never sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _fail(message: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "error": message}, indent=2), file=sys.stderr)
    return code


def _build_workflow(scenario: str, clock: SimulatedClock):
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_core.runnables import RunnableLambda
    from langchain_core.tools import tool

    def prepare_prompt(request: dict[str, Any]) -> list[Any]:
        return [
            SystemMessage(content="You are a support assistant. Reply with JSON: intent and account_id."),
            HumanMessage(content=request["message"]),
        ]

    model = FakeListChatModel(
        name="support-model",
        responses=[json.dumps({"intent": "order_status", "account_id": CUSTOMER["account_id"]})],
    )

    def plan_tool_call(message: Any) -> dict[str, Any]:
        decision = json.loads(message.content)
        return {"account_id": decision["account_id"], "api_token": SYNTHETIC_API_TOKEN}

    @tool
    def account_lookup(account_id: str, api_token: str) -> dict[str, Any]:
        """Look up order status for a (fictional) account."""
        if scenario == "tool-error":
            raise AccountServiceError(
                f"account service rejected credentials Bearer {api_token} for {account_id}"
            )
        if scenario == "tool-timeout":
            clock.advance(SIMULATED_SERVICE_LATENCY_S)
            if clock.now > TOOL_BUDGET_S:
                raise TimeoutError(
                    f"account service exceeded {TOOL_BUDGET_S:.1f}s budget "
                    f"(simulated latency {SIMULATED_SERVICE_LATENCY_S:.1f}s)"
                )
        return {"account_id": account_id, "order": "SO-4471", "status": "shipped", "carrier": "Fictional Freight"}

    def compose_reply(result: dict[str, Any]) -> str:
        return f"Order {result['order']} for account {result['account_id']} has {result['status']} via {result['carrier']}."

    return (
        RunnableLambda(prepare_prompt, name="prepare_prompt")
        | model
        | RunnableLambda(plan_tool_call, name="plan_tool_call")
        | account_lookup
        | RunnableLambda(compose_reply, name="compose_reply")
    ).with_config(run_name="support_workflow")


def _write_keys(keys_dir: Path, *, sign: bool) -> dict[str, str]:
    keys_dir.mkdir(parents=True)
    material: dict[str, str] = {"hmac_key": secrets.token_hex(32)}
    (keys_dir / "hmac.key").write_text(material["hmac_key"], encoding="utf-8")
    if sign:
        from sage.signing import _b64d, generate_keypair

        kp = generate_keypair()
        material["private_key"] = kp["private_key"]
        material["public_key"] = kp["public_key"]
        material["public_key_fingerprint"] = hashlib.sha256(_b64d(kp["public_key"])).hexdigest()
        (keys_dir / "ed25519.private.json").write_text(
            json.dumps({"alg": "ed25519", "private_key": kp["private_key"]}, indent=2), encoding="utf-8"
        )
        (keys_dir / "ed25519.public.txt").write_text(kp["public_key"], encoding="utf-8")
    (keys_dir / "README.md").write_text(
        "# Producer key material (do not share with the handoff kit)\n\n"
        "- `hmac.key`: shared HMAC verification key. Send to the recipient through a separate channel.\n"
        + (
            "- `ed25519.private.json`: signing private key. Never leaves the producer.\n"
            "- `ed25519.public.txt`: public key the recipient pins. Confirm its SHA-256 fingerprint "
            f"`{material.get('public_key_fingerprint', '')}` with the recipient out of band.\n"
            if sign
            else ""
        ),
        encoding="utf-8",
    )
    for path in keys_dir.iterdir():
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return material


def _run_workflow(scenario: str, mode: str) -> dict[str, Any]:
    from sage import SageRecorder
    from sage.adapters.langchain_callback import AsyncSageLangChainCallback, SageLangChainCallback

    clock = SimulatedClock()
    workflow = _build_workflow(scenario, clock)
    recorder = SageRecorder(
        title=f"support_workflow {scenario} ({mode})",
        trace_id=f"demo-{scenario}-{mode}",
        framework="langchain",
        environment="synthetic-demo",
        journal_dir=Path("journal"),
        blob_store=Path("blobs"),
        metadata={"scenario": scenario, "mode": mode, "model": MODEL_LABEL, "data": "synthetic"},
    )
    handler_cls = AsyncSageLangChainCallback if mode == "async" else SageLangChainCallback
    outcome: dict[str, Any] = {"workflow": "failed", "reply": None, "exception_type": None}
    with recorder:
        handler = handler_cls(recorder)
        config = {"callbacks": [handler], "run_name": "support_workflow"}
        try:
            if mode == "async":
                reply = asyncio.run(workflow.ainvoke({"message": SUPPORT_REQUEST}, config=config))
            else:
                reply = workflow.invoke({"message": SUPPORT_REQUEST}, config=config)
            outcome.update(workflow="succeeded", reply=reply)
        except (AccountServiceError, TimeoutError) as exc:
            outcome["exception_type"] = type(exc).__name__
        handler.assert_complete()
        outcome["capture"] = "complete"
    outcome["bundle"] = recorder.finalize()
    return outcome


def _failed_step(bundle: Any) -> Any | None:
    errored = [s for s in bundle.spans if s.status in {"error", "timeout"}]
    if not errored:
        return None
    parents = {s.parent_id for s in errored}
    leaves = [s for s in errored if s.span_id not in parents]
    return (leaves or errored)[0]


def _summary(*, scenario: str, mode: str, outcome: dict[str, Any], report: dict[str, Any],
             recipient: dict[str, Any], build: dict[str, Any]) -> str:
    bundle = outcome["bundle"]
    step = _failed_step(bundle)
    policy = report.get("policy") or {}
    lines = [
        "# Incident summary (generated from verified evidence)",
        "",
        f"- **Workflow outcome:** {outcome['workflow']}",
        f"- **Capture completeness:** {outcome['capture']}",
        f"- **Evidence verification:** {'passed' if report.get('ok') and recipient.get('ok') else 'FAILED'}",
        "",
        "These are separate results. A failed workflow can still produce complete, valid evidence.",
        "",
        "## What workflow ran?",
        "",
        f"`support_workflow`: a synthetic client-support assistant (scenario `{scenario}`, `{mode}` invocation) "
        f"built from real LangChain runnables, a {MODEL_LABEL}, and a local `account_lookup` tool. "
        f"{len(bundle.spans)} spans were recorded.",
        "",
        "## Which step failed?",
        "",
    ]
    if step is None:
        lines += ["No step failed. The workflow returned a reply.", ""]
    else:
        lines += [f"`{step.name}` ({step.type} span `{step.span_id}`).", ""]
    lines += ["## What exception category was recorded?", ""]
    if step is None or step.error is None:
        lines += ["None.", ""]
    else:
        lines += [f"`{step.error.type}`", ""]
    lines += ["## What context remains after redaction?", ""]
    if step is not None and step.error is not None:
        lines += [f"- Error message as recorded: `{step.error.message}`"]
        if step.inputs:
            lines += [f"- Tool inputs as recorded: `{json.dumps(step.inputs, sort_keys=True)[:300]}`"]
    lines += [
        f"- Redactions applied: {len(bundle.redactions)} (key and pattern rules from the bundle's redaction policy).",
        "",
        "## Did evidence verification succeed?",
        "",
        f"- Producer verification under policy `{policy.get('policy_id')}`: {'passed' if report.get('ok') else 'failed'}",
        f"- Recipient helper (`verify_handoff.py`, separate process): {'passed' if recipient.get('ok') else 'failed'}"
        f"; receipt bound to this pack: {recipient.get('receipt_bound', False)}"
        f"; signature verified against pinned key: {recipient.get('signature_pinned', False)}",
        f"- Bundle hash: `{report.get('bundle_hash')}`",
        "",
        "## Which policy and software version were used?",
        "",
        f"- Policy: `{policy.get('policy_id')}` digest `{policy.get('policy_digest')}`",
        f"- SAGE {build['sage_version']}, langchain-core {build['langchain_core']}, Python {build['python']}",
        "",
        "## What does this evidence not establish?",
        "",
        *[f"- {item}" for item in NOT_ESTABLISHED],
        "",
        "This summary is a convenience view rendered from the verified bundle. The pack is the evidence;",
        "re-run `verify_handoff.py` to check it independently.",
        "",
    ]
    return "\n".join(lines)


def _source_commit() -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout.strip() or None) if out.returncode == 0 else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=SCENARIOS, default="tool-error")
    parser.add_argument("--mode", choices=MODES, default="sync")
    parser.add_argument("--out", required=True, help="new run directory (must be empty or absent)")
    parser.add_argument("--no-sign", action="store_true", help="HMAC-only kit (strict policy) when cryptography is unavailable")
    args = parser.parse_args(argv)

    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        return _fail(f"--out already contains files: {out}. Choose a new run directory.")
    try:
        import langchain_core
    except ImportError:
        return _fail('langchain-core is required: pip install "sage-incident-bundles[langchain]"')
    import sage
    from sage.handoff import create_handoff
    from sage.policy import load_policy
    from sage.signing import signing_available
    from sage.verify import verify_artifact

    sign = not args.no_sign
    if sign and not signing_available():
        return _fail('signing needs cryptography: pip install "sage-incident-bundles[sign]" or pass --no-sign')
    policy = load_policy(ROOT / "policies" / ("auditor.json" if sign else "strict.json"))

    producer = out / "producer"
    producer.mkdir(parents=True)
    keys = _write_keys(out / "keys", sign=sign)
    cwd = Path.cwd()
    os.chdir(producer)
    try:
        outcome = _run_workflow(args.scenario, args.mode)
        kit = create_handoff(
            Path("journal"),
            out / "handoff",
            hmac_key=keys["hmac_key"],
            policy=policy,
            actor="consultancy-demo",
            public_key=keys.get("public_key"),
            private_key=keys.get("private_key"),
            sign=sign,
        )
    finally:
        os.chdir(cwd)

    report = verify_artifact(
        kit / "evidence.sage.tar.gz",
        policy=policy,
        hmac_key=keys["hmac_key"],
        witness_key=keys["hmac_key"],
        public_key=keys.get("public_key"),
    )
    if report.get("bundle_hash") != outcome["bundle"].audit.bundle_hash:
        return _fail("verified pack does not match the recorded bundle", code=1)

    env = {k: v for k, v in os.environ.items() if not k.startswith("SAGE_")}
    env["SAGE_PACK_KEY"] = keys["hmac_key"]
    helper_args = [sys.executable, str(kit / "verify_handoff.py")]
    if sign:
        helper_args.append(f"--public-key={keys['public_key']}")
    proc = subprocess.run(helper_args, capture_output=True, text=True, env=env, timeout=300)
    try:
        recipient = json.loads(proc.stdout if proc.returncode == 0 else proc.stderr)
    except json.JSONDecodeError:
        recipient = {"ok": False}

    build = {
        "format": "sage.demo.build_record.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scenario": args.scenario,
        "mode": args.mode,
        "model": MODEL_LABEL,
        "data": "synthetic (fictional customer, account, and credentials)",
        "sage_version": getattr(sage, "__version__", "unknown"),
        "langchain_core": getattr(langchain_core, "__version__", "unknown"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "source_commit": _source_commit(),
        "policy_id": (report.get("policy") or {}).get("policy_id"),
        "policy_digest": (report.get("policy") or {}).get("policy_digest"),
        "bundle_hash": report.get("bundle_hash"),
        "pack_sha256": hashlib.sha256((kit / "evidence.sage.tar.gz").read_bytes()).hexdigest(),
        "signed": sign,
        "public_key_fingerprint": keys.get("public_key_fingerprint"),
        "workflow_outcome": outcome["workflow"],
        "capture_completeness": outcome["capture"],
        "evidence_verification": "passed" if report.get("ok") and recipient.get("ok") else "failed",
    }
    (kit / "build_record.json").write_text(json.dumps(build, indent=2, sort_keys=True), encoding="utf-8")
    (kit / "INCIDENT_SUMMARY.md").write_text(
        _summary(scenario=args.scenario, mode=args.mode, outcome=outcome, report=report, recipient=recipient, build=build),
        encoding="utf-8",
    )

    print(json.dumps(
        {
            "workflow_outcome": outcome["workflow"],
            "capture_completeness": outcome["capture"],
            "evidence_verification": build["evidence_verification"],
            "handoff": str(kit),
            "keys_do_not_share": str(out / "keys"),
        },
        indent=2,
    ))
    return 0 if build["evidence_verification"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
