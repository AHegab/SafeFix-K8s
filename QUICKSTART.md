# SafeFixK8s - Quick Start Guide

## One-Command Full Pipeline

```bash
python pipeline.py --input tests/ --output output/
```

That's it! This will:
1. ✓ Scan all YAML files in `tests/` with 13 security tools
2. ✓ Normalize findings into unified schema
3. ✓ Generate fixes using multi-LLM consensus
4. ✓ Validate fixes with 7-gate framework

Results will be in `output/` directory.

---

## Prerequisites Check

```bash
# 1. Check Python
python --version  # Should be 3.8+

# 2. Check Docker (required for detection)
docker --version

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Set API keys in .env file
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk_...
GEMINI_API_KEY=AIza...
OPENROUTER_API_KEY=sk-or-v1-...
```

---

## Common Use Cases

### 1. Full Pipeline (Default)
```bash
python pipeline.py --input tests/ --output results/
```

### 2. Fast Mode (Fewer Tools)
```bash
python pipeline.py --input tests/ --detection-mode lean
```

### 3. Different LLM Models
```bash
python pipeline.py --input tests/ --models groq,gemini
```

### 4. High Concurrency (Faster)
```bash
python pipeline.py --input tests/ --concurrency 15
```

### 5. Strict Validation
```bash
python pipeline.py --input tests/ --strict
```

---

## Run Individual Stages

### Stage 1: Detection Only
```bash
python pipeline.py --stage detection --input tests/
```
**Output**: `output/detection/raw/*.json`

### Stage 2: Normalization Only
```bash
python pipeline.py --stage normalize \
  --raw output/detection/raw \
  --tests tests/
```
**Output**: `output/normalization/llm_payload.json`

### Stage 3: Repair Only
```bash
python pipeline.py --stage repair \
  --payload output/normalization/llm_payload.json \
  --tests tests/
```
**Output**: `output/repair/SECURED_*.yaml`

### Stage 4: Validation Only
```bash
python pipeline.py --stage validate \
  --tests tests/ \
  --fixed output/repair/ \
  --payload output/normalization/llm_payload.json
```
**Output**: `output/validation/SUMMARY_VALIDATION.csv`

---

## Understanding the Output

After running the pipeline, check these files:

```
output/
├── detection/raw/               # Raw findings from 13 tools
├── normalization/
│   └── llm_payload.json        # 📄 Unified findings
├── repair/
│   ├── SECURED_*.yaml          # ✅ Fixed manifests
│   └── EXPLANATION_*.md        # 📝 What was fixed
└── validation/
    └── SUMMARY_VALIDATION.csv  # 📊 Validation results
```

**Key Files**:
- `SECURED_*.yaml` - Your secured Kubernetes manifests (deploy these!)
- `EXPLANATION_*.md` - Explains what was fixed and why
- `SUMMARY_VALIDATION.csv` - Shows which fixes passed validation

---

## Troubleshooting

### "Docker not found"
```bash
# Install Docker Desktop
# Windows: https://www.docker.com/products/docker-desktop
# Then ensure it's running
```

### "API key not found"
```bash
# Check .env file exists and has your keys
cat .env

# Should contain:
# GROQ_API_KEY=gsk_...
# GEMINI_API_KEY=AIza...
# etc.
```

### "PowerShell execution policy"
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

### Rate limit errors
```bash
# Reduce concurrency
python pipeline.py --input tests/ --concurrency 3
```

---

## Quick Examples

### Example 1: Scan One File
```bash
# Put your YAML in tests/ folder
cp my-deployment.yaml tests/

# Run pipeline
python pipeline.py --input tests/ --output my-results/

# Check fixed version
cat my-results/repair/SECURED_my-deployment.yaml
```

### Example 2: Use Only Free LLMs
```bash
# Groq and Gemini are free
python pipeline.py --input tests/ --models groq,gemini
```

### Example 3: Re-run Repair with Different Models
```bash
# Detection + normalization already done
python pipeline.py --stage repair \
  --payload output/normalization/llm_payload.json \
  --tests tests/ \
  --models openai,groq
```

---

## Performance Tips

**Faster Execution**:
```bash
# Use lean mode (10 tools instead of 13)
python pipeline.py --input tests/ --detection-mode lean

# Increase concurrency
python pipeline.py --input tests/ --concurrency 20

# Use fewer LLM models
python pipeline.py --input tests/ --models groq
```

**Better Results**:
```bash
# Use all tools (extended mode)
python pipeline.py --input tests/ --detection-mode extended

# Use all LLM models for consensus
python pipeline.py --input tests/ --models groq,openrouter,gemini,openai

# Enable strict validation
python pipeline.py --input tests/ --strict
```

---

## Getting Help

```bash
# Show all options
python pipeline.py --help

# Verbose mode (see what's happening)
python pipeline.py --input tests/ --verbose

# Quiet mode (only errors)
python pipeline.py --input tests/ --quiet
```

---

## What Each Stage Does

| Stage | What It Does | Time | Free? |
|-------|-------------|------|-------|
| **Detection** | Scans YAML with 13 tools | ~2-5 min | ✅ Yes |
| **Normalization** | Unifies findings | ~10 sec | ✅ Yes |
| **Repair** | Generates fixes via AI | ~1-5 min | ⚠️ Needs API keys |
| **Validation** | Tests fixes work | ~1-3 min | ✅ Yes |

**Total Time**: 5-15 minutes for typical workload

---

## Next Steps

1. ✅ Run the full pipeline on your test manifests
2. 📖 Review `SECURED_*.yaml` files
3. 📝 Read `EXPLANATION_*.md` to understand fixes
4. ✔️ Check `SUMMARY_VALIDATION.csv` for validation status
5. 🚀 Deploy secured manifests to your cluster!

---

## Support

- **Full Documentation**: See `README.md`
- **Pipeline Source**: See `pipeline.py`
- **Issues**: [Your GitHub Issues URL]
