# 🎯 SafeFix-K8s Normalizer - Perfect Edition v9.0

## Quick Start

```bash
# Run normalizer (from workspace root)
python Normalizer/normalize.py

# Validate output quality
python Normalizer/validate_output.py output/llm_payload.json
```

## What Makes It Perfect?

### ✅ Comprehensive Processing
- **Input**: 13 security tool outputs (1,336 raw findings)
- **Processing**: Intelligent aggregation & deduplication
- **Output**: 131 LLM-ready security items (10:1 compression)

### ✅ 4-Tier Severity System
- 🔴 **CRITICAL** (29%): privileged, hostPath, dangerous capabilities
- 🟠 **HIGH** (45%): root users, writable filesystem, missing hardening  
- 🟡 **MEDIUM** (26%): image tags, namespaces, network policies
- 🔵 **LOW** (0%): quality checks (filtered by default)

### ✅ Multi-Tool Correlation
- 36% of findings confirmed by 2+ tools
- Cross-tool validation reduces false positives
- Aggregated rule IDs from all sources

## Usage

### Basic Command
```bash
python Normalizer/normalize.py \
  --raw Detection/output/raw \
  --out output
```

### Advanced Options
```bash
python Normalizer/normalize.py \
  --raw Detection/output/raw \
  --out output \
  --min-support 2 \          # Require 2+ tools to agree
  --only-security 1 \         # Skip quality-only findings (default)
  --emit-normalized 1         # Generate debug output
```

### Validation
```bash
# Validate output quality and get statistics
python Normalizer/validate_output.py output/llm_payload.json
```

## Output Structure

### llm_payload.json
```json
{
  "generated_at": "2025-11-03T10:57:17Z",
  "version": "sfk-v9.0-perfect",
  "metadata": {
    "raw_findings_count": 1336,
    "aggregated_count": 234,
    "llm_items_count": 131,
    "severity_distribution": {
      "CRITICAL": 57,
      "HIGH": 84,
      "MEDIUM": 49
    }
  },
  "items": [
    {
      "file": "tests/nginx_deployment.yaml",
      "category": "PRIVILEGED",
      "severity": "CRITICAL",
      "tools": ["Checkov", "Trivy", "Kubescape"],
      "support_count": 3,
      "rule_ids": ["CKV_K8S_22", "C-0057"],
      "hints": ["Container runs privileged"],
      "resource": {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "nginx-deployment"}
      },
      "snippet": "securityContext:\n  privileged: true",
      "span": {"start_line": 10, "end_line": 12},
      "jsonpath": "$.spec.template.spec.containers[0].securityContext"
    }
  ]
}
```

## Latest Run Statistics

- **Processing Time**: ~2 seconds
- **Unique Files**: 16 YAML manifests
- **Tool Coverage**: Checkov (58), KubeAudit (58), Conftest (30), Trivy (29), Gitleaks (3)
- **Top Categories**: CAP_SYS_ADMIN (17), NO_SECCOMP (17), READONLY_ROOTFS_FALSE (17)

## Files in This Directory

- **normalize.py** - Main normalizer engine (v9.0)
- **validate_output.py** - Output quality validator
- **PERFECT_NORMALIZER.md** - Comprehensive technical documentation
- **README.md** - This file

## Integration

The normalizer bridges Detection → LLM layers:

1. **Detection** generates raw tool outputs → `Detection/output/raw/*.json`
2. **Normalizer** aggregates and enriches → `output/llm_payload.json`
3. **LLM Orchestrator** consumes payload → generates patches

## See Also

- [PERFECT_NORMALIZER.md](PERFECT_NORMALIZER.md) - Complete technical documentation
- [../Detection/README.md](../Detection/README.md) - How to run detection tools
- [../LLMs/README.md](../LLMs/README.md) - LLM orchestration layer

---

**Made Perfect for SafeFix-K8s BSc Thesis** ✨
