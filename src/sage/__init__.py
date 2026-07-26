"""SAGE — fail-closed agent incident forensics (security tool).

Core runtime is stdlib-only. Optional extras:
  pip install -e '.[tui]'     # interactive inspect TUI
  pip install -e '.[train]'   # neural attribution (research)
  pip install -e '.[attr]'    # numpy attribution helpers (research)
"""

from sage.audit import build_audit_chain, redact_bundle, require_verified, verify_audit_chain
from sage.bundle_io import load_bundle, save_bundle
from sage.clock import FakeClock, set_clock
from sage.diff import DivergenceReport, diff_bundles
from sage.handoff import create_handoff
from sage.pack import pack_artifact, unpack_artifact
from sage.policy import VerifyPolicy, load_policy
from sage.receipt import verify_receipt, write_receipt
from sage.recorder import SageRecorder
from sage.regression import generate_pytest, write_heal_boundary_test, write_regression_test
from sage.replay import (
    ReplayCassette,
    ReplayDivergence,
    ReplayResult,
    apply_heal,
    pure_recorded_replay,
    replay_bundle,
)
from sage.schema import IncidentBundle, SageSpan
from sage.errors import (
    BlobIntegrityError,
    ChainIntegrityError,
    SecurityDivergence,
    SplitBrainError,
)
from sage.heal_capability import HealCapability, HealPatch, issue_heal_patch
from sage.sdk import FrameworkAdapter, instrument, wrap_run
from sage.verify import verify_artifact
from sage.version import __version__
from sage.witness import append_witness, verify_witness_log

__all__ = [
    "BlobIntegrityError",
    "ChainIntegrityError",
    "DivergenceReport",
    "FakeClock",
    "FrameworkAdapter",
    "HealCapability",
    "HealPatch",
    "IncidentBundle",
    "VerifyPolicy",
    "__version__",
    "append_witness",
    "apply_heal",
    "build_audit_chain",
    "create_handoff",
    "diff_bundles",
    "generate_pytest",
    "instrument",
    "issue_heal_patch",
    "load_bundle",
    "load_policy",
    "pack_artifact",
    "pure_recorded_replay",
    "redact_bundle",
    "replay_bundle",
    "require_verified",
    "save_bundle",
    "set_clock",
    "unpack_artifact",
    "verify_artifact",
    "verify_audit_chain",
    "verify_receipt",
    "verify_witness_log",
    "wrap_run",
    "write_heal_boundary_test",
    "write_receipt",
    "write_regression_test",
    "ReplayCassette",
    "ReplayDivergence",
    "ReplayResult",
    "SageRecorder",
    "SageSpan",
    "SecurityDivergence",
    "SplitBrainError",
]


def __getattr__(name: str):
    # Lazy optional attribution surface (may require numpy / torch).
    if name in {"AttributionCandidate", "attribute_incident", "attribution_report"}:
        from sage.attribution import (
            AttributionCandidate,
            attribute_incident,
            attribution_report,
        )

        mapping = {
            "AttributionCandidate": AttributionCandidate,
            "attribute_incident": attribute_incident,
            "attribution_report": attribution_report,
        }
        return mapping[name]
    raise AttributeError(f"module 'sage' has no attribute {name!r}")
