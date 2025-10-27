# SafeFixK8s

A four-layer pipeline to detect Kubernetes misconfigurations, normalize findings, generate safe fixes with multiple LLMs, and validate them through progressive gates.

## Layers at a glance

- Detection (`Detection/`)
  - Runs a suite of scanners (kubeconform, kubescape, trivy, kubelinter, kube-score, polaris, kubeaudit, yamllint, checkov, gitleaks, pluto, rbac-police, conftest)
  - Writes raw results to `Detection/output/raw/`
- Normalizer (`Normalizer/`)
  - Converts raw scanner outputs into a compact LLM payload
  - Writes `output/llm_payload.json` (+ optional `output/normalized_findings.json`)
- LLMs (`LLMs/`)
  - Multi-model orchestrator with strict JSON schema and unified-diff enforcement
  - Applies and YAML-validates patches in-memory; emits `output/patch_sandbox/`
  - Writes decisions to `output/llm_decisions.json`
- Validations (`Validations/`)
  - 7 gates: schema, policy, dryrun, sandbox, health, network, e2e
  - Produces signed proof: `Validations/safe_fix_proof.json`, plus per-file reports/evidence

## End-to-end flow

1) Detection

```powershell
cd .\Detection
. .\detectors.ps1
# Fast core or extended
Det-RunLean -Path ..\tests
# or
Det-RunExtended -Path ..\tests
```

2) Normalizer

```powershell
# From repo root
python .\Normalizer\normalize.py --raw Detection\output\raw --out output --emit-normalized 1
```

3) LLM Orchestrator

```powershell
# Set provider keys first: GROQ_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY
python .\LLMs\multi_llm_orchestrator.py --models groq,openrouter,gemini --validate yaml --apply-dir output\patch_sandbox
```

4) Validations

```powershell
# Minimal gates (no cluster needed for schema/policy; kubectl needed for dryrun)
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy,dryrun

# Full (requires current kube-context)
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -EnableSandbox -TimeoutSec 90
```

## Outputs and artifacts

- Detection: `Detection/output/raw/*.json`
- Normalizer: `output/llm_payload.json`, `output/normalized_findings.json`
- LLMs: `output/llm_decisions.json`, `output/patch_sandbox/**`
- Validations: `Validations/reports/*.json`, `Validations/evidence/**`, `Validations/safe_fix_proof.json`

## Requirements

- Windows PowerShell (5.1 or PowerShell 7)
- Python 3.10+
- Python packages: httpx, jsonschema, PyYAML
- For Validations:
  - kubeconform (Gate 1), conftest (Gate 2), kubectl (Gates 3–7), and a kube-context for sandbox gates

## Housekeeping

- Clean outputs before a new run:
  - Use the helper script `./clean-outputs.ps1` (see Commands sheet), or remove the relevant folders manually.

For detailed per-layer docs, see: `Detection/README.md`, `Normalizer/README.md`, `LLMs/README.md`, and `Validations/README.md`.
