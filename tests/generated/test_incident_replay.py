"""Auto-generated regression test from a SAGE incident bundle."""

from pathlib import Path

from sage.audit import verify_audit_chain
from sage.bundle_io import load_bundle
from sage.replay import replay_bundle


def test_incident_replay() -> None:
    bundle_path = Path(__file__).resolve().parent / "run_ecb14d4ec6a94651892ac25496b7b39b.sage.json"
    recorded = load_bundle(bundle_path)
    assert verify_audit_chain(recorded), 'audit chain must verify'
    result = replay_bundle(recorded, recorded.spans, strict=True)
    assert result.ok, result.divergences
