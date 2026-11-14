# Pilot onboarding (SAGE 2.3.0)

Send this page—or the commands below—to a design partner. No repository access required.

## Install

1. Download from [SAGE 2.3.0](https://github.com/Fratres-X-AI/SAGE/releases/tag/v2.3.0):
   - `sage_incident_bundles-2.3.0-py3-none-any.whl` (producer or auditor with `sage` CLI)
   - Optional: `sage-verify-2.3.0.pyz` (recipient with Python only)
   - Optional: `SHA256SUMS.json` + Sigstore bundles for supply-chain verification (`scripts/verify_release.py` in the repo)

2. Create a venv (Python 3.10 or newer) and install:

   ```bash
   python -m pip install "sage_incident_bundles-2.3.0-py3-none-any.whl[sign]"
   sage doctor
   ```

## Five-minute proof

Full steps match [README.md](../README.md) (Five-minute pilot demonstration). Short path if you have the repo:

```bash
pip install -e ".[langchain,sign]"
python examples/consultancy_demo.py --scenario tool-error --mode sync --out demo-runs/pilot-01
sage scan demo-runs/pilot-01/handoff/evidence.sage.tar.gz
sage handoff verify demo-runs/pilot-01/handoff --hmac-key-file demo-runs/pilot-01/keys/hmac.key --public-key-file demo-runs/pilot-01/keys/ed25519.public.txt
```

Without a checkout: use the demo kit you received from the producer and follow `HANDOFF.md` inside it.

## LangGraph shops

See [LANGGRAPH_PILOT.md](LANGGRAPH_PILOT.md) for what CI validates and how to attach the handler.

## What SAGE does not claim

See README **Explicit non-claims**. SAGE verifies **artifact integrity**, not model truth or completeness of uninstrumented code.