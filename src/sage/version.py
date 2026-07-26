"""Package and format versions for the SAGE v2 stability covenant."""

from __future__ import annotations

__version__ = "2.1.1"

# Bundle / span schema (content model). Independent of package semver.
SCHEMA_VERSION = "1.0"

# Frozen on-disk / on-wire forensic formats (v2 covenant).
FORMATS = {
    "bundle": "sage.bundle.v1",  # .sage.json content model (schema 1.0)
    "journal": "sage.journal.v1",
    "pack": "sage.pack.v2",
    "pack_legacy": "sage.pack.v1",
    "policy": "sage.verify.policy.v1",
    "receipt": "sage.verify.receipt.v1",
    "keys": "sage.keys.v1",
    "witness": "sage.witness.v1",
}

# Public API modules considered stable under semver (see COMPATIBILITY.md).
STABLE_PUBLIC_API = (
    "sage.SageRecorder",
    "sage.IncidentBundle",
    "sage.SageSpan",
    "sage.load_bundle",
    "sage.save_bundle",
    "sage.verify_artifact",
    "sage.require_verified",
    "sage.redact_bundle",
    "sage.pure_recorded_replay",
    "sage.diff_bundles",
    "sage.pack.pack_artifact",
    "sage.pack.unpack_artifact",
    "sage.doctor.run_doctor",
    "sage.signing.generate_keypair",
    "sage.signing.verify_signature",
    "sage.handoff.create_handoff",
    "sage.policy.VerifyPolicy",
    "sage.receipt.write_receipt",
    "sage.receipt.verify_receipt",
    "sage.witness.append_witness",
    "sage.witness.verify_witness_log",
    "sage.clock.FakeClock",
    "sage.clock.set_clock",
)


def version_report() -> dict:
    return {
        "sage_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "formats": dict(FORMATS),
        "stable_public_api": list(STABLE_PUBLIC_API),
    }
