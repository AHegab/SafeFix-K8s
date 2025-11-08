# 🚀 SafeFixK8s - Complete Pipeline Guide

## Overview

SafeFixK8s is an automated Kubernetes security remediation pipeline with 5 main stages:

```
┌──────────┐    ┌───────────┐    ┌─────┐    ┌─────────┐    ┌──────────┐
│   SCAN   │ -> │ NORMALIZE │ -> │ LLM │ -> │ COMBINE │ -> │ VALIDATE │
└──────────┘    └───────────┘    └─────┘    └─────────┘    └──────────┘
  13 tools      Unify schema    AI fixes   Apply patch   7-gate check
```

---

## 🎯 Quick Start - Run the Entire Pipeline

### Option 1: One Command (Recommended)

```bash
python cli.py pipeline --path tests
```

This runs all 5 stages automatically:
1. ✅ Scans manifests with 13 security tools
2. ✅ Normalizes findings into unified schema
3. ✅ Generates fixes using multi-LLM consensus
4. ✅ Combines patches into secured manifests
5. ✅ Validates fixes through 7 security gates

### Option 2: Interactive Wizard (First-time users)

```bash
python cli.py start
```

This launches an interactive onboarding wizard that guides you through:
- Setting up API keys
- Choosing scan targets
- Configuring validation gates
- Running your first scan

---

## 📋 Pipeline Stages Explained

### Stage 1: SCAN (Detection)

**Purpose:** Scan Kubernetes manifests with 13 security tools

**Command:**
```bash
python cli.py scan --path tests --mode extended
```

**Options:**
- `--path` / `-p`: Directory or file to scan (default: `tests`)
- `--mode` / `-m`: `extended` (13 tools) or `lean` (10 tools)
- `--extended` / `--lean`: Flag-based mode selection
- `--dry-run`: Preview without executing

**What happens:**
- Runs 13 security scanners in parallel/sequential mode
- Tools: kubeconform, kube-linter, polaris, checkov, trivy, kubescape, kube-score, yamllint, kubeaudit, conftest, rbac-police, pluto, gitleaks
- Outputs raw JSON/text results to `output/detection/raw/`

**Example:**
```bash
# Scan tests folder with all 13 tools (extended mode)
python cli.py scan --path tests

# Scan with only 10 core tools (lean mode)
python cli.py scan --path tests --lean

# Dry run to preview
python cli.py scan --path tests --dry-run
```

**Output:** `output/detection/raw/*.json`

---

### Stage 2: NORMALIZE

**Purpose:** Unify findings from 13 different tools into a single schema

**Command:**
```bash
python cli.py normalize --raw output/detection/raw --out output/normalization
```

**Options:**
- `--raw`: Input directory with raw detection results
- `--out`: Output directory for normalized findings
- `--tools`: Specific tools to normalize (comma-separated)

**What happens:**
- Parses tool-specific JSON formats
- Extracts: file path, line number, rule ID, severity, message
- Deduplicates identical findings across tools
- Maps severities to consistent levels (CRITICAL, HIGH, MEDIUM, LOW)
- Groups findings by file and vulnerability type

**Example:**
```bash
# Normalize all findings
python cli.py normalize

# Normalize specific tools only
python cli.py normalize --tools kubescape,trivy,checkov
```

**Output:** `output/normalization/normalized_findings.json`

**Schema:**
```json
{
  "findings": [
    {
      "tool": "kubescape",
      "file": "/scan/tests/job.yaml",
      "line": 15,
      "rule": "C-0034",
      "severity": "CRITICAL",
      "message": "Container runs as root user",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

---

### Stage 3: LLM (AI Remediation)

**Purpose:** Generate security patches using multi-LLM consensus

**Command:**
```bash
python cli.py run --models groq,openrouter,anthropic --autofix --hygiene
```

**Options:**
- `--models`: Comma-separated LLM providers (groq, openrouter, anthropic, google, openai)
- `--autofix`: Auto-apply conservative fixes without LLM
- `--hygiene`: Add hygiene fixes (labels, resource limits)
- `--concurrency`: Parallel LLM requests (default: 3)
- `--shard-models`: Round-robin model assignment per vulnerability

**What happens:**
1. Reads normalized findings
2. Groups vulnerabilities by file
3. For each finding:
   - Queries 2-3 LLMs in parallel
   - Collects proposed patches
   - Uses consensus voting (2/3 agreement)
4. Generates YAML patches with line-level changes
5. Saves decisions to `output/llm/llm_decisions.json`

**Example:**
```bash
# Run with 3 LLMs and consensus
python cli.py run --models groq,openrouter,anthropic --autofix

# Fast mode - round-robin sharding (1 LLM per vulnerability)
python cli.py run --models groq,openrouter,anthropic --shard-models --concurrency 6

# Conservative only (no LLM calls)
python cli.py run --autofix --hygiene
```

**Output:** 
- `output/llm/llm_decisions.json` (consensus decisions)
- `output/llm/llm_payload.json` (raw LLM responses)

**LLM Decision Schema:**
```json
{
  "findings": [
    {
      "finding_id": "job.yaml_C-0034",
      "file": "tests/job.yaml",
      "rule": "C-0034",
      "consensus": {
        "decision": "patch",
        "votes": {"patch": 2, "skip": 1},
        "yaml_patch": "...",
        "confidence": 0.67
      }
    }
  ]
}
```

---

### Stage 4: COMBINE (Patch Application)

**Purpose:** Apply all patches to create secured manifests

**Command:**
```bash
python cli.py combine --file tests/job.yaml
```

**Options:**
- `--file`: Specific file to patch (optional - patches all if omitted)
- `--output`: Custom output directory

**What happens:**
1. Loads original YAML manifest
2. Retrieves all patches for the file from LLM decisions
3. Applies patches sequentially:
   - Sorts by line number (descending)
   - Applies YAML transformations
   - Validates YAML syntax after each patch
4. Generates `SECURED_<original_name>.yaml`

**Example:**
```bash
# Combine patches for specific file
python cli.py combine --file tests/job.yaml

# Combine patches for all files
python cli.py combine
```

**Output:** `output/combination/SECURED_*.yaml`

**Patching Logic:**
- Conservative merging (preserves user intent)
- Conflict resolution (most restrictive wins)
- Syntax validation at each step
- Rollback on errors

---

### Stage 5: VALIDATE (7-Gate Validation)

**Purpose:** Verify patches through 7 security gates

**Command:**
```bash
python cli.py validate --file output/combination/SECURED_*.yaml --gates 1,2,3,4,5,6,7
```

**Options:**
- `--file`: Path to secured manifest(s)
- `--gates`: Comma-separated gate IDs (1-7, default: all)
- `--strict`: Fail fast on first gate failure

**The 7 Validation Gates:**

| Gate | Check | Description |
|------|-------|-------------|
| **1** | **Syntax Valid** | YAML parses correctly, no syntax errors |
| **2** | **Schema Valid** | Kubernetes API schema compliance |
| **3** | **Deployable** | Can be applied to cluster (dry-run) |
| **4** | **Issues Reduced** | Fewer security findings vs original |
| **5** | **No New Issues** | No regressions introduced |
| **6** | **Semantic Valid** | Preserves workload functionality |
| **7** | **Safe to Apply** | All gates passed, ready for production |

**Example:**
```bash
# Validate all gates
python cli.py validate --file output/combination/SECURED_job.yaml

# Validate specific gates only
python cli.py validate --file output/combination/SECURED_*.yaml --gates 1,2,3,4

# Strict mode (fail fast)
python cli.py validate --file output/combination/SECURED_*.yaml --strict
```

**Output:**
- `output/validation/validation_report.json` (structured results)
- `output/validation/safe_fix_proof.json` (SafeFix proof)
- Terminal: Colored pass/fail indicators

**Validation Report Schema:**
```json
{
  "file": "SECURED_job.yaml",
  "timestamp": "2025-11-07T10:30:00Z",
  "gates": {
    "gate_1_syntax": {"passed": true, "message": "Valid YAML"},
    "gate_2_schema": {"passed": true, "message": "Schema compliant"},
    "gate_3_deployable": {"passed": true, "message": "Dry-run successful"},
    "gate_4_reduced": {"passed": true, "delta": -15},
    "gate_5_no_new": {"passed": true, "new_issues": 0},
    "gate_6_semantic": {"passed": true, "message": "Functionality preserved"},
    "gate_7_safe": {"passed": true, "message": "Ready for production"}
  },
  "overall": "PASSED",
  "safe_to_deploy": true
}
```

---

## 🔄 Running Individual Stages

You can run stages independently for debugging or resuming:

### 1. Scan only:
```bash
python cli.py scan --path tests
```

### 2. Normalize only (use existing scan):
```bash
python cli.py normalize --raw output/detection/raw
```

### 3. LLM only (use existing normalized findings):
```bash
python cli.py run --models groq,openrouter --autofix
```

### 4. Combine only (use existing LLM decisions):
```bash
python cli.py combine --file tests/job.yaml
```

### 5. Validate only (use existing secured manifest):
```bash
python cli.py validate --file output/combination/SECURED_job.yaml
```

---

## 🎛️ Advanced Pipeline Options

### Resume from Specific Stage

```bash
# Skip scan and normalize, resume from LLM
python cli.py pipeline --skip-scan --skip-normalize --path tests

# Skip scan, normalize, and LLM
python cli.py pipeline --skip-scan --skip-normalize --skip-llm --path tests
```

### Target Specific File

```bash
# Run pipeline for single file only
python cli.py pipeline --path tests --target tests/13.nginx_privileged_deployment.yaml
```

### Dry Run (Preview)

```bash
# Show what would happen without executing
python cli.py pipeline --path tests --dry-run
```

### Skip Validation

```bash
# Run scan -> normalize -> LLM -> combine (no validation)
python cli.py pipeline --path tests --no-validate
```

---

## 📊 Understanding Output

### Directory Structure

```
output/
├── detection/
│   ├── raw/                    # Raw tool outputs (JSON)
│   │   ├── kubescape_raw.json
│   │   ├── trivy_config_raw.json
│   │   ├── checkov_raw.json
│   │   └── ... (13 files)
│   └── logs/                   # Detection logs
│
├── normalization/
│   └── normalized_findings.json  # Unified schema
│
├── llm/
│   ├── llm_decisions.json      # Consensus decisions
│   ├── llm_payload.json        # Raw LLM responses
│   └── patch_sandbox/          # Individual patches
│
├── combination/
│   ├── SECURED_job.yaml        # Patched manifests
│   └── SECURED_*.yaml
│
└── validation/
    ├── validation_report.json  # Gate results
    ├── safe_fix_proof.json     # SafeFix proof
    └── evidence/               # Before/after comparisons
```

---

## 🛠️ Troubleshooting

### Issue: "No findings detected"

**Cause:** Clean manifests or tools not running
**Fix:**
```bash
# Verify scan ran
ls output/detection/raw/

# Check if files have issues
python cli.py scan --path tests --dry-run
```

### Issue: "LLM API key not found"

**Cause:** Missing environment variables
**Fix:**
```bash
# Set API keys (Windows)
set GROQ_API_KEY=gsk_...
set OPENROUTER_API_KEY=sk-or-v1-...

# Or use .env file
echo GROQ_API_KEY=gsk_... > .env
```

### Issue: "Validation gate failed"

**Cause:** Patch introduced regression
**Fix:**
```bash
# Review specific gate
python cli.py validate --file output/combination/SECURED_*.yaml --gates 4

# Check what changed
python cli.py review --file output/combination/SECURED_job.yaml
```

### Issue: "Docker not found"

**Cause:** Detection tools need Docker
**Fix:**
```bash
# Verify Docker running
docker ps

# Or use native tools (if installed)
kubescape scan tests/
trivy config tests/
```

---

## 📝 Example Workflows

### Workflow 1: Quick Security Scan

```bash
# Run full pipeline on test manifests
python cli.py pipeline --path tests
```

**Result:** Secured manifests in `output/combination/`

---

### Workflow 2: Incremental Development

```bash
# 1. Initial scan
python cli.py scan --path my-app/k8s

# 2. Review findings
cat output/normalization/normalized_findings.json

# 3. Generate fixes
python cli.py run --models groq,openrouter --autofix

# 4. Apply to specific deployment
python cli.py combine --file my-app/k8s/deployment.yaml

# 5. Validate
python cli.py validate --file output/combination/SECURED_deployment.yaml
```

---

### Workflow 3: Production Deployment

```bash
# 1. Scan production manifests
python cli.py scan --path production/k8s --mode extended

# 2. Generate conservative fixes only (no LLM)
python cli.py run --autofix --hygiene

# 3. Validate with strict mode
python cli.py validate --file output/combination/SECURED_*.yaml --strict

# 4. Review before deploy
python cli.py review --file output/combination/SECURED_deployment.yaml

# 5. Apply to cluster
kubectl apply -f output/combination/SECURED_deployment.yaml --dry-run=server
kubectl apply -f output/combination/SECURED_deployment.yaml
```

---

### Workflow 4: CI/CD Integration

```yaml
# .github/workflows/k8s-security.yml
name: Kubernetes Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SafeFixK8s Pipeline
        run: |
          python cli.py pipeline --path k8s/ --no-validate
      
      - name: Upload Secured Manifests
        uses: actions/upload-artifact@v3
        with:
          name: secured-manifests
          path: output/combination/SECURED_*.yaml
      
      - name: Validate Gates
        run: |
          python cli.py validate --file output/combination/SECURED_*.yaml --strict
```

---

## 🔐 API Keys Setup

### Required for LLM Stage

Create `.env` file in project root:

```bash
# Groq (Fast, free tier available)
GROQ_API_KEY=gsk_...

# OpenRouter (Multi-model access)
OPENROUTER_API_KEY=sk-or-v1-...

# Anthropic (Claude models)
ANTHROPIC_API_KEY=sk-ant-...

# Google AI (Gemini)
GOOGLE_API_KEY=AIza...

# OpenAI (GPT models)
OPENAI_API_KEY=sk-...
```

Or set as environment variables:

**Windows (CMD):**
```cmd
set GROQ_API_KEY=gsk_...
set OPENROUTER_API_KEY=sk-or-v1-...
```

**Windows (PowerShell):**
```powershell
$env:GROQ_API_KEY="gsk_..."
$env:OPENROUTER_API_KEY="sk-or-v1-..."
```

**Linux/Mac:**
```bash
export GROQ_API_KEY="gsk_..."
export OPENROUTER_API_KEY="sk-or-v1-..."
```

---

## 📚 Additional Resources

- **Detection Tools:** See `Detection/README.md` for tool-specific docs
- **Normalizer:** See `Normalizer/README.md` for schema details
- **LLM Orchestrator:** See `LLMs/README.md` for model configuration
- **Validation:** See `Validations/README.md` for gate details

---

## 🎓 Best Practices

1. **Always start with extended scan** - More tools = better coverage
2. **Use consensus mode** - 2-3 LLMs for production fixes
3. **Review before applying** - Use `cli.py review` for critical workloads
4. **Test in staging first** - Run validation gates before production
5. **Keep API keys secure** - Never commit `.env` to git
6. **Check gate 4 delta** - Ensure issues actually reduced
7. **Backup original manifests** - SafeFix creates new files but be safe

---

## 🚀 Ready to Go!

Run your first complete pipeline:

```bash
python cli.py pipeline --path tests
```

Or start with the interactive wizard:

```bash
python cli.py start
```

**Happy Securing! 🔒**
