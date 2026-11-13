# Release checklist (SAGE 2.x)

No outside services required for this gate. Run before tagging.

## Preflight

```bash
pip install -e ".[dev,langchain]"
python scripts/release_check.py
pytest -q -m "not slow"
python examples/security_verify_loop.py
python examples/auditor_kit.py
python examples/consultancy_demo.py --scenario tool-error --mode sync --out demo-runs/preflight
python scripts/ci_smoke.py
sage doctor
```

## Build and recipient check

```bash
python -m build
python scripts/recipient_check.py --dist dist
```

`recipient_check.py` installs the wheel into a fresh virtual environment outside the checkout (no
editable install, no `PYTHONPATH`), confirms the import location, and verifies a demo kit with network
access disabled.

## Version sync

Must match across:

- `pyproject.toml` `[project].version`
- `src/sage/version.py` `__version__`
- `CHANGELOG.md` top section
- `README.md` current release line
- `SECURITY.md` supported versions table

## Tag + GitHub release

Read the version from the package so the tag cannot drift:

```bash
VERSION="$(python -c 'import sage; print(sage.__version__)')"
git tag -a "v${VERSION}" -m "SAGE ${VERSION}"
git push origin "v${VERSION}"
```

A release candidate (`rcN`) tag is a candidate, not a supported release; do not tag or publish without
the operator's decision.

## What the release workflow does

Pushing a `v*` tag runs `.github/workflows/release.yml`. Every action is pinned to a commit SHA.

1. **build**: checks the tag matches `sage.__version__`, runs `release_check.py`, the fast tests, the
   auditor kit, and `scripts/repro_check.py` (two clean builds must be byte-identical). Then it builds
   the wheel and sdist with `SOURCE_DATE_EPOCH` set to the commit time, writes `sbom.spdx.json`, and
   writes `SHA256SUMS.json`.
2. **attest-and-sign**: records SLSA build provenance for the wheel, sdist, and SBOM, and signs each
   with Sigstore keyless signing (`<file>.sigstore.json` bundles).
3. **draft-release**: creates a **draft** GitHub release with all files. Rc, alpha, and beta tags are
   marked pre-release. Nothing is public until the operator reviews the draft and clicks Publish.
4. **pypi**: skipped unless the repository variable `SAGE_PYPI_ENABLED` is `true`. It uses PyPI trusted
   publishing from the `pypi` environment, so no token is stored. Add a required reviewer on that
   environment before enabling it.

To check reproducibility locally before tagging:

```bash
python scripts/repro_check.py
```

## Verify a release

Download every file from the GitHub release into one directory, then:

```bash
pip install sigstore          # for the signature check
python scripts/verify_release.py <download dir> --tag vX.Y.Z
```

| Check | Needs | Proves |
|-------|-------|--------|
| `checksums` | nothing | Every file matches `SHA256SUMS.json` |
| `sigstore` | `pip install sigstore` | Each file was signed by this repository's `release.yml` for that tag |
| `provenance` | GitHub CLI `gh` | Each wheel and sdist has SLSA provenance from this repository's `release.yml` |

A missing tool exits 2 rather than skipping. `--skip sigstore` or `--skip provenance` skips a check
on purpose; the report lists it as `skipped`, never as passed. Exit 0 means every requested check passed.

## PyPI

The package is not published on PyPI. Do not document `pip install sage-incident-bundles` as an
install route until it is. Publishing goes through the gated `pypi` job above; do not upload by hand.

## Do not ship

- Private keys, `.sage/` local state, `pod_export/`, `artifacts/`, `demo-runs/`, soak logs
- Research models as “forensic” claims
