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
- Docker (optional; used as a fallback for kubeconform/conftest if not installed)

Install via Scoop (optional):
```powershell
scoop install kubeconform conftest kubectl
```
or Chocolatey:
```powershell
choco install -y kubeconform conftest kubectl
```

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
# Adjust model list as needed; --hygiene adds conservative securityContext hardening
python .\LLMs\multi_llm_orchestrator.py --models groq,openrouter,gemini --validate yaml --apply-dir output\patch_sandbox --hygiene

# Optional flags:
#   --limit 10         # process first 10 findings only
#   --autofix          # flip privileged:true/allowPrivilegeEscalation:true to false if still present
```

## Validations

```powershell
# Minimal validations
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy,dryrun

# Full validations (requires a kube-context)
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -EnableSandbox -TimeoutSec 90

# Run both gates (Schema + Policy) only
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy

# Prefer Detection's kubeconform JSON (faster, avoids rerun)
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy -DetectionRawKubeconform .\detection\output\raw\kubeconform_raw.json

# Pin Kubernetes version for kubeconform (optional)
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy -KubeVersion 1.29.0
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
  - Install them and ensure they are on PATH, then re-run Validations. If not installed, the script will try Scoop/Chocolatey, and finally Docker fallbacks for each tool when Docker is available.
- LLM providers return `needs_review`:
  - Ensure keys are set and models are available; reduce `--models` to a subset if rate limited
- No YAML in `output\patch_sandbox`:
  - Re-run the LLM orchestrator first (see "LLM Orchestrator" above).
