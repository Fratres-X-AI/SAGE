from __future__ import annotations


class SageError(Exception):
    """Base for fail-closed forensic errors (never silent)."""


class BlobIntegrityError(SageError):
    """CAS payload digest does not match address, or mutation detected mid-flight."""


class MemoryBudgetExceeded(SageError):
    """Recorder refused to materialize a payload that would breach the memory budget."""


class SplitBrainError(SageError):
    """Two writers finalized or mutated the same trace_id with conflicting chains."""


class ChainIntegrityError(SageError):
    """Parent-hash / monotonic sequence / audit-chain invariant violated."""


class SecurityDivergence(SageError):
    """Heal / make-test path attempted layout or parent-graph manipulation."""

    def __init__(
        self,
        message: str,
        *,
        policy_span_id: str | None = None,
        guardrail_span_id: str | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.policy_span_id = policy_span_id
        self.guardrail_span_id = guardrail_span_id
        self.details = details or {}


class FaultRecoveryError(SageError):
    """Carcass is unrecoverable past the crash boundary."""
