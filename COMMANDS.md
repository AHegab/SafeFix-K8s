# SafeFixK8s Commands (Windows PowerShell)

Copy-paste friendly commands to run the pipeline end-to-end.

## Setup

```powershell
# Optional: create/update Python venv
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install httpx jsonschema PyYAML

# Provider keys (export to current session)
$env:GROQ_API_KEY = '...'
$env:OPENROUTER_API_KEY = '...'
$env:GEMINI_API_KEY = '...'
```

Tools (optional but recommended for validations):
- kubeconform, conftest, kubectl

## Detection

```powershell
cd .\Detection
. .\detectors.ps1
# Choose one of:
Det-RunLean -Path ..\tests
Det-RunExtended -Path ..\tests
cd ..
```

## Normalizer

```powershell
python .\Normalizer\normalize.py --raw Detection\output\raw --out output --emit-normalized 1
```

## LLM Orchestrator

```powershell
# Adjust model list as needed
python .\LLMs\multi_llm_orchestrator.py --models groq,openrouter,gemini --validate yaml --apply-dir output\patch_sandbox
```

## Validations

```powershell
# Minimal validations
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy,dryrun

# Full validations (requires a kube-context)
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -EnableSandbox -TimeoutSec 90
```

## Housekeeping

```powershell
# Clean all generated outputs (helper)
.\clean-outputs.ps1
```

## Troubleshooting

- Missing kube-context during dryrun:
  - Run `kubectl config get-contexts` and set one with `kubectl config use-context <name>`
- kubeconform or conftest not found:
  - Install them and ensure they are on PATH, then re-run Validations
- LLM providers return `needs_review`:
  - Ensure keys are set and models are available; reduce `--models` to a subset if rate limited
