# SafeFixK8s - Usage Guide

## Quick Start

### Option 1: Use the Launcher (Easiest)

**Windows:**
```cmd
run_pipeline.bat
```

**Linux/Mac:**
```bash
./run_pipeline.sh
```

### Option 2: Use Python Directly

```bash
python pipeline.py --input tests/ --output results/
```

### Option 3: Use Individual Stages

```bash
# Stage 1: Detection
python pipeline.py --stage detection --input tests/

# Stage 2: Normalization
python pipeline.py --stage normalize --raw output/detection/raw --tests tests/

# Stage 3: Repair
python pipeline.py --stage repair --payload output/normalization/llm_payload.json

# Stage 4: Validation
python pipeline.py --stage validate --tests tests/ --fixed output/repair/
```

---

## Full Pipeline Command Reference

### Basic Usage
```bash
python pipeline.py --input <input_dir> --output <output_dir>
```

### Common Options

```bash
# Use specific LLM models
python pipeline.py --input tests/ --models groq,gemini

# Increase concurrency (faster but more API calls)
python pipeline.py --input tests/ --concurrency 10

# Lean mode (10 tools instead of 13)
python pipeline.py --input tests/ --detection-mode lean

# Strict validation
python pipeline.py --input tests/ --strict

# Verbose logging
python pipeline.py --input tests/ --verbose

# Quiet mode
python pipeline.py --input tests/ --quiet
```

---

## Understanding the Output

After running the pipeline, you'll find:

```
results/
├── detection/
│   ├── raw/                      # Raw JSON from 13 tools
│   │   ├── checkov_raw.json
│   │   ├── trivy_config_raw.json
│   │   ├── kubescape_raw.json
│   │   └── ... (9 more tools)
│   └── logs/                     # Execution logs
│
├── normalization/
│   ├── llm_payload.json          # ⭐ Unified findings for LLM
│   ├── normalized_findings.json
│   └── buckets.csv               # Summary by category
│
├── repair/
│   ├── SECURED_*.yaml            # ✅ Your fixed manifests!
│   ├── EXPLANATION_*.md          # What was fixed
│   ├── DIFF_*.diff               # Changes made
│   └── llm_decisions.json        # LLM fix decisions
│
└── validation/
    ├── SUMMARY_VALIDATION.csv    # ⭐ Validation results
    └── REPORT_VALIDATE_*.json    # Detailed reports
```

### Key Files You Need

1. **`SECURED_*.yaml`** - Deploy these to your Kubernetes cluster
2. **`EXPLANATION_*.md`** - Read these to understand what was fixed
3. **`SUMMARY_VALIDATION.csv`** - Check which fixes passed validation

---

## Stage-by-Stage Breakdown

### Stage 1: Detection (~2-5 minutes)

**What it does:** Scans your YAML files with 13 security tools

**Tools used:**
- KubeConform, KubeLinter, Polaris, Checkov, TrivyConfig
- Kubescape, KubeScore, Yamllint, KubeAudit, Conftest
- RBACPolice, Pluto, Gitleaks (extended mode)

**Output:** `output/detection/raw/*.json`

**Command:**
```bash
python pipeline.py --stage detection --input tests/
```

---

### Stage 2: Normalization (~10 seconds)

**What it does:** Unifies findings from 13 different formats into one schema

**Features:**
- Deduplication across tools
- Category mapping (8 security families)
- Aggregation and support counting

**Output:** `output/normalization/llm_payload.json`

**Command:**
```bash
python pipeline.py --stage normalize \
  --raw output/detection/raw \
  --tests tests/
```

---

### Stage 3: Repair (~1-5 minutes)

**What it does:** Uses AI (multiple LLMs) to generate fixes

**LLM Providers:**
- Groq (free, fast)
- Gemini (free, good quality)
- OpenRouter (paid, high quality)
- OpenAI (paid, GPT-4)

**Fix Strategies:**
1. **Deterministic** - Template-based (instant)
2. **Template** - Simple patterns
3. **LLM-Guided** - Complex reasoning

**Output:** `output/repair/SECURED_*.yaml`

**Command:**
```bash
python pipeline.py --stage repair \
  --payload output/normalization/llm_payload.json \
  --models groq,gemini
```

---

### Stage 4: Validation (~1-3 minutes)

**What it does:** Validates fixes with 7-gate framework

**Validation Gates:**
1. ✓ Schema Validation (kubeconform)
2. ✓ Policy Validation (conftest/OPA)
3. ✓ Dry-run Apply (kubectl)
4. ✓ Sandbox Deploy
5. ✓ Health Checks
6. ✓ Network Validation
7. ✓ E2E Smoke Tests

**Output:** `output/validation/SUMMARY_VALIDATION.csv`

**Command:**
```bash
python pipeline.py --stage validate \
  --tests tests/ \
  --fixed output/repair/ \
  --payload output/normalization/llm_payload.json
```

---

## Customization Examples

### Example 1: Scan Custom Directory

```bash
# Scan your own manifests
python pipeline.py \
  --input /path/to/my/k8s/manifests/ \
  --output my-results/
```

### Example 2: Use Only Free LLMs

```bash
python pipeline.py \
  --input tests/ \
  --models groq,gemini \
  --concurrency 15
```

### Example 3: Fast Mode (Lean + High Concurrency)

```bash
python pipeline.py \
  --input tests/ \
  --detection-mode lean \
  --models groq \
  --concurrency 20
```

### Example 4: Maximum Quality Mode

```bash
python pipeline.py \
  --input tests/ \
  --detection-mode extended \
  --models groq,openrouter,gemini,openai \
  --concurrency 5 \
  --strict
```

### Example 5: Re-run Only Repair with Different Models

```bash
# Detection and normalization already done
python pipeline.py \
  --stage repair \
  --payload results/normalization/llm_payload.json \
  --tests tests/ \
  --models openai,gemini \
  --output results/
```

---

## Troubleshooting

### Detection Stage Issues

**Problem:** "Docker not found"
```bash
# Solution: Install Docker Desktop and ensure it's running
docker --version
docker ps
```

**Problem:** "PowerShell execution policy"
```powershell
# Solution: Allow script execution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

---

### LLM/Repair Stage Issues

**Problem:** "API key not found"
```bash
# Solution: Check .env file
cat .env

# Should contain:
# GROQ_API_KEY=gsk_...
# GEMINI_API_KEY=AIza...
# OPENROUTER_API_KEY=sk-or-v1-...
# OPENAI_API_KEY=sk-proj-...
```

**Problem:** "Rate limit exceeded"
```bash
# Solution: Reduce concurrency
python pipeline.py --input tests/ --concurrency 3

# Or use fewer models
python pipeline.py --input tests/ --models groq
```

**Problem:** "Connection timeout"
```bash
# Solution: Check internet connection and try again
# Or use different LLM provider
python pipeline.py --input tests/ --models gemini
```

---

### Validation Stage Issues

**Problem:** "kubeconform not found"
```bash
# Solution: Install kubeconform (optional)
# Or run without strict validation
python pipeline.py --input tests/
```

**Problem:** "kubectl not found"
```bash
# Solution: Some gates require kubectl
# Install from: https://kubernetes.io/docs/tasks/tools/
```

---

## Performance Tips

### Faster Execution

1. **Use Lean Mode** (10 tools instead of 13)
   ```bash
   python pipeline.py --input tests/ --detection-mode lean
   ```

2. **Increase Concurrency**
   ```bash
   python pipeline.py --input tests/ --concurrency 15
   ```

3. **Use Single Fast LLM**
   ```bash
   python pipeline.py --input tests/ --models groq
   ```

4. **Skip Validation** (not recommended)
   ```bash
   # Run only detection + normalization + repair
   python pipeline.py --stage detection --input tests/
   python pipeline.py --stage normalize --raw output/detection/raw --tests tests/
   python pipeline.py --stage repair --payload output/normalization/llm_payload.json
   ```

### Better Quality Results

1. **Use All Tools**
   ```bash
   python pipeline.py --input tests/ --detection-mode extended
   ```

2. **Use Multiple LLMs** (consensus voting)
   ```bash
   python pipeline.py --input tests/ --models groq,openrouter,gemini,openai
   ```

3. **Strict Validation**
   ```bash
   python pipeline.py --input tests/ --strict
   ```

---

## What Each Tool Detects

| Tool | Specialization | Example Issues Found |
|------|---------------|---------------------|
| **Checkov** | Best practices, misconfigs | Missing resource limits, privileged containers |
| **Trivy** | CVE scanning, config issues | Vulnerable images, insecure configs |
| **Kubescape** | RBAC, network policies | Overly permissive roles, missing network policies |
| **Polaris** | Best practices | Missing probes, image pull policies |
| **KubeLinter** | Operational best practices | Deprecated APIs, anti-patterns |
| **KubeScore** | Production readiness | Missing labels, pod disruption budgets |
| **KubeAudit** | Security auditing | Privilege escalation, host access |
| **Conftest** | Policy enforcement | Custom OPA policy violations |
| **Kubeconform** | Schema validation | Invalid YAML structure |
| **Yamllint** | YAML syntax | Formatting issues, syntax errors |
| **RBACPolice** | RBAC analysis | Over-privileged roles |
| **Pluto** | Deprecated APIs | Old API versions |
| **Gitleaks** | Secret detection | Hardcoded passwords, API keys |

---

## Environment Variables

Set these in your `.env` file:

```bash
# LLM API Keys (at least one required for repair stage)
GROQ_API_KEY=gsk_...                    # Free, fast
GEMINI_API_KEY=AIza...                  # Free, good quality
OPENROUTER_API_KEY=sk-or-v1-...         # Paid, high quality
OPENAI_API_KEY=sk-proj-...              # Paid, GPT-4

# Optional: Customize LLM models
OPENAI_MODEL=gpt-4o-mini
GROQ_MODEL=llama-3.1-8b-instant
GEMINI_MODEL=gemini-2.0-flash-exp
OPENROUTER_MODEL=x-ai/grok-vision-beta

# Optional: Custom output directory
SAFEFIX_OUTPUT_ROOT=/path/to/custom/output

# Optional: Enable debug mode
DEBUG_PATCHES=true
```

---

## Next Steps After Running Pipeline

1. ✅ **Review Results**
   - Check `results/validation/SUMMARY_VALIDATION.csv`
   - Review `SECURED_*.yaml` files

2. 📖 **Understand Fixes**
   - Read `EXPLANATION_*.md` files
   - Review `DIFF_*.diff` to see changes

3. ✔️ **Validate Manually**
   - Test secured manifests in dev environment
   - Verify application still works

4. 🚀 **Deploy**
   ```bash
   kubectl apply -f results/repair/SECURED_*.yaml
   ```

5. 📊 **Monitor**
   - Check if security policies pass
   - Verify no regressions

---

## Getting Help

```bash
# Show all options
python pipeline.py --help

# Show version
python pipeline.py --version  # (if implemented)

# Enable verbose logging
python pipeline.py --input tests/ --verbose
```

For more information:
- **Full Documentation**: `README.md`
- **Quick Start**: `QUICKSTART.md`
- **This File**: `USAGE.md`
