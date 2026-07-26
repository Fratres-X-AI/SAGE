# Contributing to SAGE

SAGE is a **fail-closed security / forensics** toolkit. PRs that weaken verify defaults, skip quarantine, or treat research as custody will be rejected.

## Setup

```bash
pip install -e ".[dev]"
python scripts/release_check.py
pytest -q
```

## Rules

1. Compact verify before rehydrate (hash binding).
2. Redact / sanitize before hashing or journal append.
3. `--require-signature` must stay pinned-key (no TOFU by default).
4. Keep core stdlib-only; optional extras for sign/attr/train/tui.
5. Do not commit keys, soak logs, or `pod_export/`.
6. Research lives under `sage research *` only.

## PR checklist

- [ ] `python scripts/release_check.py`
- [ ] `pytest -q` green
- [ ] Docs/CHANGELOG updated if user-facing
- [ ] No secrets in the diff
