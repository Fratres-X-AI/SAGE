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

`release.yml` builds sdist/wheel + SBOM artifact on `v*` tags. A release candidate (`rcN`) tag is a
candidate, not a supported release; do not tag or publish without the operator's decision.

## PyPI (optional, when you have credentials)

The package is not published on PyPI. Do not document `pip install sage-incident-bundles` as an
install route until it is.

```bash
python -m build
python -m twine check dist/*
# twine upload dist/*
```

## Do not ship

- Private keys, `.sage/` local state, `pod_export/`, `artifacts/`, `demo-runs/`, soak logs
- Research models as “forensic” claims
