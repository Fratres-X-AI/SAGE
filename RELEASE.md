# Release checklist (SAGE 2.x)

No outside services required for this gate. Run before tagging.

## Preflight

```bash
pip install -e ".[dev]"
python scripts/release_check.py
pytest -q --ignore=tests/test_attribution.py
python examples/security_verify_loop.py
python examples/auditor_kit.py
python scripts/ci_smoke.py
sage doctor
```

## Version sync

Must match across:

- `pyproject.toml` `[project].version`
- `src/sage/version.py` `__version__`
- `CHANGELOG.md` top section
- `README.md` current release line
- `SECURITY.md` supported versions table

## Tag + GitHub release

```bash
git tag -a "v2.1.1" -m "SAGE 2.1.1"
git push origin "v2.1.1"
```

`release.yml` builds sdist/wheel + SBOM artifact on `v*` tags.

## PyPI (optional, when you have credentials)

1. Set real `Homepage` / `Repository` / `Issues` in `pyproject.toml` `[project.urls]`.
2. Optionally set `SAGE_SBOM_NAMESPACE` to your repo URL for SBOM docs.

```bash
python -m build
python -m twine check dist/*
# twine upload dist/*
```

## Do not ship

- Private keys, `.sage/` local state, `pod_export/`, `artifacts/`, soak logs
- Research models as “forensic” claims
