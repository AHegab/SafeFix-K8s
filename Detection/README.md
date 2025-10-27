# Detection

Purpose: Run Kubernetes security and quality scanners over manifests to produce raw findings.

Key tools (extended set):
- kubeconform, kubeaudit, kubelinter, kube-score, kubescape, trivy, polaris, conftest, yamllint, pluto, gitleaks, checkov, rbac-police

Inputs:
- Target path containing Kubernetes YAML/YML manifests.

Outputs:
- detection/output/raw/*.json for each scanner
- detection/output/logs/*.txt (logs) (if enabled)

Policies and rules:
- Checkov custom checks: `Detection/policies/checkov/`
- Gitleaks rules: `Detection/policies/gitleaks-rules.toml`
- Default OPA policies for conftest live under `Validations/policies/opa/`

Common commands (Windows PowerShell):
- Lean run (fast core):
  - `cd .\Detection; . .\detectors.ps1; Det-RunLean -Path ..\tests`
- Extended run (more scanners):
  - `cd .\Detection; . .\detectors.ps1; Det-RunExtended -Path ..\tests`

Notes:
- The extended run writes JSON under `Detection/output/raw/`. These are then consumed by the Normalizer.
- Some scanners require Docker or external binaries; see `install-*.ps1` helpers for convenience.
