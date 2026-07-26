# Migrating to SAGE 2.0

## From 1.x

1. Upgrade: `pip install -U sage-incident-bundles` (or editable checkout).
2. Prefer **pack v2** (default): custody MAC binds witness tip.
3. CI: switch to `sage verify --policy policies/strict.json --witness`.
4. Use `sage handoff` for auditor export instead of ad-hoc tarballs.
5. Pin keys via env (`SAGE_PACK_KEY`) or `sage.keys.v1` ring — do not inline secrets.

## Behavior changes

| Area | 1.x | 2.0 |
|------|-----|-----|
| Default pack format | v1 or early v2 | **v2** custody MAC |
| Public API | Informal | Frozen list in `COMPATIBILITY.md` |
| Verify | Flags only | Policies + receipts first-class |
| Docs | README-heavy | Threat model + verify runbook |

## Still compatible

- Schema `1.0` bundles / journals verify unchanged.
- Pack v1 artifacts verify when `--hmac-key` matches (legacy MAC).
- `sage verify-journal` remains as a journal-specific alias path.

## Research demotion (unchanged)

`attribute` / `train` / `bench` / `synth` stay under `sage research` and are not forensic claims.
