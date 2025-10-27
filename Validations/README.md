# SafeFixK8s Validation Layer (7 Gates)

This module validates LLM-generated Kubernetes fixes before they can be accepted.

It implements a progressive set of gates and produces signed, auditable evidence.

- Gate 1: Schema Validation (kubeconform)
- Gate 2: Policy Validation (OPA via Conftest, using `policies/opa`)
- Gate 3: Dry Run (kubectl `--dry-run=server`)
- Gate 4: Sandbox Deploy (kind/minikube or any reachable cluster)
- Gate 5: Health Check (rollout status + readiness)
- Gate 6: Network Check (service presence; stub for deeper tests)
- Gate 7: E2E Smoke Test (pluggable hook)

Artifacts:
- `Validations/reports/<file-id>.json` per file
- `Validations/evidence/**` gate-specific raw outputs
- `Validations/safe_fix_proof.json` aggregate signed proof

## Prerequisites

- Windows PowerShell (v5.1 or newer works; PowerShell 7 recommended)
- Tools (install what you need):
  - `kubeconform` for Gate 1
  - `conftest` for Gate 2 (uses `policies/opa` in the repo)
  - `kubectl` for Gates 3–7
  - A working Kubernetes context for sandbox gates (4–7). kind/minikube are fine.

## Quick start

Minimal validations (no cluster needed):

```powershell
# From repo root
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy,dryrun
```

Full run against current kube-context (if available):

```powershell
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -EnableSandbox -TimeoutSec 90
```

Sign the proof with an HMAC key:

```powershell
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -EnableSandbox -SigningKey (Get-Content .\.signing_key)
```

Optional E2E hook: create `Validations/e2e_smoke.ps1` and return non-error for PASS.

## Proof format

`safe_fix_proof.json` contains:

- `files[]` with per-file gate results and overall PASS/FAIL
- `summary` counts
- `tools` versions where detected
- `signature` object

`overall` is PASS only when Gates 1–3 are PASS and there are no FAIL statuses in any gate.

## Integrating with the LLM pipeline

After running the orchestrator to write patched files into `output/patch_sandbox`, run this validator:

```powershell
# Example
.\Validations\validate-gates.ps1 -InputDir .\output\patch_sandbox -Gates schema,policy,dryrun
```

You can then review per-file reports in `Validations/reports/` and the aggregate proof at `Validations/safe_fix_proof.json`.

## Notes

- The current implementation includes stubs for deeper network/E2E checks that you can extend.
- Gate 2 leverages existing OPA policies under `policies/opa` (edit or add more as needed).
- To run policy checks with Kyverno instead, wire it similarly or add a new gate.
