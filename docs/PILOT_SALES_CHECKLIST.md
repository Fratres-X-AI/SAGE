# Pilot sales checklist (Kyle-owned)

Engineering shipped **2.3.0** on GitHub Releases. This checklist is what **you** close before taking money. Commercial prose lives in the private gitignored tree `artifacts/commercial-readiness/commercial/` (copy `00_INDEX.md` is the source of truth).

## Technical (can delegate to CI / scripts)

- [ ] [v2.3.0 release](https://github.com/Fratres-X-AI/SAGE/releases/tag/v2.3.0) is **published** (not draft) with wheel + pyz.
- [ ] `python scripts/recipient_check.py --dist dist` passes on the release wheel locally or in CI.
- [ ] Send prospects [PILOT_ONBOARDING.md](PILOT_ONBOARDING.md) instead of a feature branch name.

## Demo (you, ~30 minutes once)

- [ ] Run [20_demo_script.md](../artifacts/commercial-readiness/commercial/20_demo_script.md) twice without improvising.
- [ ] README five-minute pilot works from a **release wheel** install (not only editable checkout).

## Legal / business (do not let agents invent)

Work through **`[KYLE: …]` placeholders** listed in `artifacts/commercial-readiness/commercial/00_INDEX.md`:

- Legal entity, address, billing contact, tax ids, payment terms, governing law, liability caps, signatures.
- Per-customer fields on SOW, intake, invoice, change request.

Before first invoice:

- [ ] Counsel reviews `07_sow_draft.md`, `06_license_explainer.md`, `13_data_handling_statement.md`.
- [ ] Outreach templates still marked **DRAFT — NOT SENT** until you approve wording.

## Optional distribution

- [ ] PyPI: set repository variable `SAGE_PYPI_ENABLED=true` and configure trusted publishing on environment `pypi` (see [RELEASE.md](RELEASE.md)). Leave off until you want `pip install` without GitHub.