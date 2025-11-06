# SafeFix-K8s CLI Guide

## Overview

The SafeFix-K8s CLI provides a unified, user-friendly interface for the complete security remediation pipeline with:
- ✅ **Rich colored output** with tables and progress bars
- ✅ **Interactive wizards** for onboarding and review
- ✅ **Dry-run mode** for safe exploration
- ✅ **Shell completion** support (bash, zsh, PowerShell)
- ✅ **Consistent commands** across all pipeline stages
- ✅ **Built-in help** with examples

## Installation

### Quick Install
```bash
# Install CLI dependencies
pip install -r requirements-cli.txt

# Verify installation
python cli.py --help
```

### Shell Completion (Optional)
```bash
# Bash
python cli.py --install-completion bash
source ~/.bashrc

# Zsh
python cli.py --install-completion zsh
source ~/.zshrc

# PowerShell
python cli.py --install-completion powershell
```

## Quick Start

### First-Time Setup
```bash
# Run interactive onboarding wizard
python cli.py start

# This will:
# - Check prerequisites (Docker, Python, PowerShell)
# - Create .env file with API key templates
# - Show suggested first steps
# - Optionally run first scan
```

## Commands Reference

### 1. `scan` - Security Scanning

Scan Kubernetes manifests for security issues using multiple tools.

**Default Mode:** EXTENDED (13 tools) - includes all security scanners for comprehensive analysis.

**Basic Usage:**
```bash
# Scan tests folder (EXTENDED mode - 13 tools) - DEFAULT
python cli.py scan

# Scan with LEAN mode (10 tools only)
python cli.py scan --lean

# Scan specific path
python cli.py scan --path /path/to/manifests

# Dry-run (show what would be executed)
python cli.py scan --dry-run
```

**Options:**
- `--path, -p TEXT` - Path to scan (default: tests)
- `--mode, -m TEXT` - Scan mode: lean or extended (default: extended)
- `--extended/--lean, -e/-l` - Use extended (13 tools) or lean (10 tools) mode (default: extended)
- `--dry-run` - Show command without executing
- `--output, -o TEXT` - Custom output directory

**Tools Included:**

*LEAN Mode (10 tools):*
- kubeconform, kube-linter, polaris, checkov, trivy, kubescape, kube-score, yamllint, kubeaudit, conftest

*EXTENDED Mode (13 tools - DEFAULT):*
- All LEAN tools + rbac-police, pluto, gitleaks

**Output:**
- Raw findings: `Detection/output/raw/*.json`
- Summary table with tool breakdown
- Next step suggestions

**Example Output:**
```
╔═══════════════════════════════════════════════════════════╗
║          SafeFix-K8s Security Remediation Pipeline        ║
╚═══════════════════════════════════════════════════════════╝

Scanning: C:\...\SafeFixK8s\tests
Mode: EXTENDED (13 tools)
Started: 2025-11-04 10:30:00

┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Metric           ┃   Value ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ Total Findings   │     175 │
│ Tools Run        │      13 │
│ Files Scanned    │      15 │
│ Elapsed Time     │   24.5s │
└──────────────────┴─────────┘

Next Steps:
  1. python cli.py normalize --raw Detection/output/raw --out output
  2. Review raw findings in Detection/output/raw/
  3. Run with --extended for comprehensive scanning (13 tools)
```

---

### 2. `normalize` - Normalize Findings

Aggregate and normalize raw findings into a unified schema.

**Basic Usage:**
```bash
# Normalize with defaults
python cli.py normalize

# Custom paths
python cli.py normalize --raw Detection/output/raw --out output

# Set minimum tool agreement
python cli.py normalize --min-support 2

# Dry-run
python cli.py normalize --dry-run
```

**Options:**
- `--raw, -r TEXT` - Raw detection output directory (default: Detection/output/raw)
- `--out, -o TEXT` - Output directory (default: output)
- `--min-support INT` - Minimum tool agreement (default: 1)
- `--only-security` - Filter only security findings (default: True)
- `--dry-run` - Show command without executing

**Output:**
- `output/normalized_findings.json` - Full normalized data
- `output/llm_payload.json` - LLM-ready items
- Summary with severity distribution

---

### 3. `llm run` - LLM Orchestration

Generate security patches using multiple LLM providers.

**Basic Usage:**
```bash
# Run with defaults (groq, openrouter, gemini)
python cli.py llm run

# Specify models
python cli.py llm run --models groq,openrouter

# Disable autofix/hygiene
python cli.py llm run --no-autofix --no-hygiene

# Limit processing
python cli.py llm run --limit 10

# Dry-run
python cli.py llm run --dry-run
```

**Options:**
- `--models, -m TEXT` - Comma-separated model list (default: groq,openrouter,gemini)
- `--autofix/--no-autofix` - Enable automatic fixes (default: enabled)
- `--hygiene/--no-hygiene` - Enable security hygiene (default: enabled)
- `--limit, -l INT` - Limit items to process (0=all)
- `--timeout, -t INT` - Timeout per model in seconds (default: 25)
- `--dry-run` - Show command without executing

**Output:**
- `output/llm_decisions.json` - Model votes and patches
- Summary with fix statistics

**Requirements:**
- Valid API keys in `.env` file
- Ollama running locally (if using ollama model)

---

### 4. `combine` - Patch Combination

Combine multiple patches into a single secured manifest.

**Basic Usage:**
```bash
# Combine patches for a file
python cli.py combine tests/13.nginx_privileged_deployment.yaml

# Specify models
python cli.py combine tests/file.yaml --models groq,openrouter

# Disable hygiene
python cli.py combine tests/file.yaml --no-hygiene

# Dry-run
python cli.py combine tests/file.yaml --dry-run
```

**Arguments:**
- `FILE` - Target file to combine patches for (required)

**Options:**
- `--models, -m TEXT` - Comma-separated model list
- `--autofix/--no-autofix` - Enable automatic fixes
- `--hygiene/--no-hygiene` - Enable security hygiene
- `--output, -o TEXT` - Custom output directory
- `--dry-run` - Show command without executing

**Output:**
- `output/combined_patches/SECURED_<filename>` - Final secured manifest
- `output/combined_patches/DECISIONS_<filename>.json` - Patch decisions log

---

### 5. `validate` - Validation Gates

Validate secured manifests through 7-gate validation framework.

**Gates:**
1. **Schema Validation** - kubeconform schema checks
2. **Policy Validation** - conftest/OPA policy checks
3. **Dry-Run Apply** - kubectl server-side validation
4. **Sandbox Deploy** - Deploy to test namespace
5. **Health Checks** - Readiness/liveness probes
6. **Network Validation** - NetworkPolicy checks
7. **E2E Smoke Tests** - End-to-end functionality tests

**Basic Usage:**
```bash
# Run gates 1-2 (offline gates)
python cli.py validate output/combined_patches/SECURED_*.yaml --gates 1,2

# Run gates 1-5 with sandbox
python cli.py validate output/combined_patches/SECURED_*.yaml --gates 1,2,3,4,5 --sandbox

# Dry-run
python cli.py validate output/combined_patches/SECURED_*.yaml --dry-run
```

**Arguments:**
- `FILE` - File to validate (required)

**Options:**
- `--gates, -g TEXT` - Comma-separated gate numbers 1-7 (default: 1,2)
- `--sandbox, -s` - Enable sandbox deployment for gates 3-7
- `--dry-run` - Show command without executing

**Output:**
- `Validations/evidence/` - Per-gate evidence files
- `Validations/safe_fix_proof.json` - Validation proof

**Requirements:**
- Gates 1-2: None (offline)
- Gates 3-7: Kubernetes cluster access (minikube/kind)

---

### 6. `review` - Interactive Review

Interactive review of secured manifests with side-by-side diff.

**Basic Usage:**
```bash
# Review secured file
python cli.py review output/combined_patches/SECURED_tests_13.nginx_privileged_deployment.yaml

# Skip diff display
python cli.py review output/combined_patches/SECURED_*.yaml --no-diff
```

**Arguments:**
- `FILE` - Secured file to review (required)

**Options:**
- `--show-diff/--no-diff` - Show diff with original (default: enabled)

**Interactive Options:**
1. Apply to cluster (kubectl apply)
2. Save to different location
3. Run validation gates
4. Exit

---

### 7. `pipeline` - Complete End-to-End Pipeline

Run the complete SafeFix-K8s pipeline from scan to validation in one command.

**Pipeline Steps:**
1. **SCAN** - Run all 13 security tools on manifests
2. **NORMALIZE** - Aggregate and deduplicate findings
3. **LLM** - Generate fixes using AI consensus
4. **COMBINE** - Apply patches to manifests
5. **VALIDATE** - Run 7-gate validation (optional)

**Basic Usage:**
```bash
# Run complete pipeline
python cli.py pipeline --path tests

# Run pipeline on specific file
python cli.py pipeline --path tests --target tests/13.nginx_privileged_deployment.yaml

# Resume from LLM step (skip scan/normalize if already done)
python cli.py pipeline --skip-scan --skip-normalize

# Skip validation step
python cli.py pipeline --path tests --no-validate

# Preview pipeline steps
python cli.py pipeline --dry-run
```

**Options:**
- `--path, -p TEXT` - Path to scan (default: tests)
- `--target, -t TEXT` - Specific file to patch (optional, otherwise patches all files from LLM output)
- `--skip-scan` - Skip scan if already completed
- `--skip-normalize` - Skip normalization if already completed
- `--skip-llm` - Skip LLM analysis if already completed
- `--validate/--no-validate` - Run validation after patching (default: enabled)
- `--dry-run` - Show pipeline steps without executing

**Output:**
- Complete pipeline summary with timing
- All intermediate outputs (normalized findings, LLM decisions, patches)
- Final secured manifests in `output/combined_patches/`

**Example:**
```bash
# Full pipeline in one command
python cli.py pipeline --path tests

# Resume interrupted pipeline
python cli.py pipeline --skip-scan --skip-normalize --path tests

# Patch only one file
python cli.py pipeline --path tests --target tests/nginx.yaml --skip-scan
```

---

### 8. `completion` - Shell Completion

Generate shell completion scripts.

**Basic Usage:**
```bash
# Generate bash completion
python cli.py completion bash > ~/.bash_completion.d/safefix-k8s
source ~/.bashrc

# Generate zsh completion
python cli.py completion zsh > ~/.zsh/completions/_safefix-k8s
source ~/.zshrc

# Generate PowerShell completion
python cli.py completion powershell > safefix-k8s-completion.ps1
. .\safefix-k8s-completion.ps1
```

---

### 8. `completion` - Shell Completion

Generate shell completion scripts.

**Basic Usage:**
```bash
# Generate bash completion
python cli.py completion bash > ~/.bash_completion.d/safefix-k8s
source ~/.bashrc

# Generate zsh completion
python cli.py completion zsh > ~/.zsh/completions/_safefix-k8s
source ~/.zshrc

# Generate PowerShell completion
python cli.py completion powershell > safefix-k8s-completion.ps1
. .\safefix-k8s-completion.ps1
```

---

### 9. `start` - Onboarding Wizard

Interactive setup wizard for first-time users.

**Basic Usage:**
```bash
python cli.py start
```

**Features:**
- Checks prerequisites (Docker, Python, PowerShell)
- Creates `.env` file with API key templates
- Shows suggested workflow
- Optionally runs first scan

---

## Complete Pipeline Example

### Method 1: Using the Pipeline Command (Fastest)
```bash
# Run entire pipeline in one command
python cli.py pipeline --path tests

# This automatically executes:
# 1. Scan (13 tools)
# 2. Normalize findings
# 3. LLM patch generation
# 4. Combine patches
# 5. Validate secured files
```

### Method 2: Step-by-Step Manual Flow
```bash
# 1. First-time setup
python cli.py start

# 2. Scan for issues (EXTENDED mode - default)
python cli.py scan --path tests

# 3. Normalize findings
python cli.py normalize

# 4. Generate patches with LLMs
python cli.py llm run --autofix --hygiene

# 5. Combine patches for target file
python cli.py combine tests/13.nginx_privileged_deployment.yaml

# 6. Validate secured file (gates 1-2)
python cli.py validate output/combined_patches/SECURED_tests_13.nginx_privileged_deployment.yaml --gates 1,2

# 7. Review interactively
python cli.py review output/combined_patches/SECURED_tests_13.nginx_privileged_deployment.yaml
```

### Method 3: Resume Interrupted Pipeline
```bash
# Already scanned and normalized, resume from LLM
python cli.py pipeline --skip-scan --skip-normalize --path tests

# Already have LLM decisions, just patch and validate
python cli.py pipeline --skip-scan --skip-normalize --skip-llm --path tests
```

### With Dry-Run Safety
```bash
# Test pipeline first
python cli.py pipeline --dry-run --path tests

# Test individual steps
python cli.py scan --dry-run
python cli.py normalize --dry-run
python cli.py llm run --dry-run
python cli.py combine tests/13.nginx_privileged_deployment.yaml --dry-run
python cli.py validate output/combined_patches/SECURED_*.yaml --dry-run

# Then run for real (remove --dry-run)
```

---

## Advanced Features

### Exit Codes
- `0` - Success
- `1` - Error (check console output)

### Machine-Readable Output
```bash
# Use existing scripts for JSON output
python Normalizer/normalize.py --raw Detection/output/raw --out output
# Outputs: output/normalized_findings.json, output/llm_payload.json
```

### Environment Variables
```bash
# Set custom paths
export SAFEFIX_OUTPUT_DIR=/custom/output
export SAFEFIX_DETECTION_DIR=/custom/detection

# Use in commands
python cli.py scan --output $SAFEFIX_OUTPUT_DIR
```

### Logging
All commands print to stdout with colored formatting. To save logs:
```bash
python cli.py scan 2>&1 | tee scan.log
```

---

## Troubleshooting

### Common Issues

**1. "Required packages not installed"**
```bash
pip install -r requirements-cli.txt
```

**2. "Path not found"**
- Run commands from repo root
- Use absolute paths: `--path /full/path/to/tests`

**3. "LLM orchestration failed"**
- Check API keys in `.env`
- Ensure Ollama is running (if using ollama)
- Check network connectivity

**4. "Validation failed"**
- For gates 3-7, ensure cluster access: `kubectl cluster-info`
- Check kubeconfig context

### Debug Mode
```bash
# Enable verbose output (add to scripts)
export SAFEFIX_DEBUG=1
python cli.py scan
```

---

## Comparison: Old vs New CLI

| Feature | Old Method | New CLI |
|---------|-----------|---------|
| **Scan** | `cd Detection && . .\detectors.ps1 && Det-RunExtended` | `python cli.py scan` |
| **Normalize** | `python Normalizer/normalize.py --raw ... --out ...` | `python cli.py normalize` |
| **LLM** | `python LLMs/multi_llm_orchestrator.py --models ... --autofix --hygiene` | `python cli.py llm run` |
| **Combine** | `python LLMs/combine_patches.py --file ... --models ... --autofix --hygiene` | `python cli.py combine <file>` |
| **Validate** | `cd Validations && .\validate-gates.ps1 -FilePath ...` | `python cli.py validate <file>` |
| **Full Pipeline** | Run 5+ separate commands manually | `python cli.py pipeline` |
| **Help** | Read multiple READMEs | `python cli.py <command> --help` |
| **Output** | Plain text | Rich colored tables + progress |
| **Safety** | Manual confirmation | Built-in `--dry-run` |
| **Onboarding** | Read docs | `python cli.py start` |
| **Default Mode** | LEAN (10 tools) | EXTENDED (13 tools) |
| **Commands to Learn** | 5 different script syntaxes | 9 unified commands |

**Key Improvements:**
- ✅ **80% reduction** in command complexity
- ✅ **One-command pipeline** execution
- ✅ **Rich visual feedback** with colors and tables
- ✅ **Extended mode by default** for maximum security coverage
- ✅ **Consistent interface** across all stages
- ✅ **Built-in safety** with dry-run mode everywhere

---

## Next Steps

1. **Try the wizard**: `python cli.py start`
2. **Run complete pipeline**: `python cli.py pipeline --path tests`
3. **Or go step-by-step**: Start with `python cli.py scan`
4. **Enable completion**: `python cli.py --install-completion bash`
5. **Customize** by editing `cli.py` for your needs

**Quick Reference:**
```bash
# One-command full pipeline
python cli.py pipeline --path tests

# Step-by-step approach
python cli.py scan           # 13 tools (extended mode)
python cli.py normalize      # Aggregate findings
python cli.py llm run        # Generate patches
python cli.py combine <file> # Apply patches
python cli.py validate <file> # Validate result
```

For more details, see:
- [Main README](README.md)
- [Detection Guide](Detection/README.md)
- [Validation Guide](Validations/README.md)
- [CLI Implementation Summary](CLI_IMPLEMENTATION_SUMMARY.md)
