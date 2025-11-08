# 🚀 SafeFixK8s - Quick Start Guide

## 1-Minute Setup

### Prerequisites
- Python 3.8+
- Docker (for detection tools)
- Git

### Installation
```bash
cd SafeFixK8s
pip install -r requirements.txt
```

---

## Run the Entire Pipeline (One Command)

```bash
python cli.py pipeline --path tests
```

**That's it!** 🎉 This runs all 5 stages:
1. ✅ Scans with 13 tools
2. ✅ Normalizes findings
3. ✅ Generates AI fixes
4. ✅ Applies patches
5. ✅ Validates through 7 gates

**Results:** `output/combination/SECURED_*.yaml`

---

## Alternative: Interactive Wizard

```bash
python cli.py start
```

---

## Common Commands

### Scan Only
```bash
python cli.py scan --path tests
```

### Generate Fixes (with LLMs)
```bash
# Set API keys first
set GROQ_API_KEY=gsk_...
set OPENROUTER_API_KEY=sk-or-v1-...

python cli.py run --models groq,openrouter --autofix
```

### Validate Secured Manifest
```bash
python cli.py validate --file output/combination/SECURED_job.yaml
```

### Review Changes
```bash
python cli.py review --file output/combination/SECURED_job.yaml
```

---

## Output Locations

| Stage | Output |
|-------|--------|
| Scan | `output/detection/raw/*.json` |
| Normalize | `output/normalization/normalized_findings.json` |
| LLM | `output/llm/llm_decisions.json` |
| Combine | `output/combination/SECURED_*.yaml` |
| Validate | `output/validation/validation_report.json` |

---

## CLI Commands Cheat Sheet

```bash
# Full pipeline
python cli.py pipeline --path <dir>

# Individual stages
python cli.py scan --path <dir>
python cli.py normalize
python cli.py run --models groq,openrouter
python cli.py combine --file <file>
python cli.py validate --file <file>

# Options
--dry-run              # Preview without executing
--skip-scan            # Resume from normalization
--skip-normalize       # Resume from LLM
--no-validate          # Skip validation
--target <file>        # Process single file
```

---

## Need Help?

```bash
python cli.py --help
python cli.py <command> --help
```

See [PIPELINE_GUIDE.md](./PIPELINE_GUIDE.md) for detailed documentation.

---

## Example: Quick Security Fix

```bash
# 1. Run pipeline
python cli.py pipeline --path my-k8s-manifests/

# 2. Check results
ls output/combination/

# 3. Apply to cluster
kubectl apply -f output/combination/SECURED_deployment.yaml --dry-run=server
kubectl apply -f output/combination/SECURED_deployment.yaml
```

**Done! Your manifests are now secured! 🔒**
