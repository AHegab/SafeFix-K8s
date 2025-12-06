# SafeFixK8s Pipeline

Automated Kubernetes security remediation pipeline using multi-tool detection and multi-LLM consensus-based repair.

## Overview

SafeFixK8s is a 4-stage pipeline that:
1. **Detects** security issues using 13 different scanners
2. **Normalizes** findings into a unified schema
3. **Repairs** issues using AI-powered multi-LLM consensus
4. **Validates** fixes with a 7-gate validation framework

## Prerequisites

### Required
- **Python 3.8+** with packages from `requirements.txt`
- **PowerShell** (for detection stage)
- **Docker** (for running security scanners)
- **API Keys** for LLM providers (set in `.env` file):
  - `OPENAI_API_KEY`
  - `GROQ_API_KEY`
  - `GEMINI_API_KEY`
  - `OPENROUTER_API_KEY`

### Optional
- `kubeconform` (for validation schema checks)
- `kubectl` (for advanced validation gates)

## Installation

```bash
# Clone repository
git clone <repo-url>
cd SafeFixK8s

# Install Python dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env and add your API keys
```

## Quick Start

### Run Full Pipeline

```bash
# Basic usage - runs all 4 stages
python pipeline.py --input tests/ --output output/

# With custom LLM models
python pipeline.py --input tests/ --models groq,gemini --concurrency 10

# Strict validation mode
python pipeline.py --input tests/ --strict
```

### Run Individual Stages

```bash
# Stage 1: Detection only
python pipeline.py --stage detection --input tests/

# Stage 2: Normalization only
python pipeline.py --stage normalize --raw output/detection/raw --tests tests/

# Stage 3: Repair only
python pipeline.py --stage repair --payload output/normalization/llm_payload.json

# Stage 4: Validation only
python pipeline.py --stage validate --tests tests/ --fixed output/repair/
```

## Pipeline Stages

### Stage 1: Detection (PowerShell)
**File**: `Detection/detectors.ps1`

Runs 13 security scanning tools:
- **LEAN Mode (10 tools)**: KubeConform, KubeLinter, Polaris, Checkov, TrivyConfig, Kubescape, KubeScore, Yamllint, KubeAudit, Conftest
- **EXTENDED Mode (+3)**: Adds RBACPolice, Pluto, Gitleaks

**Output**: `output/detection/raw/*.json`

### Stage 2: Normalization (Python)
**File**: `Normalizer/normalizer.py`

Unifies findings from 13 different tool formats into a single schema.

**Features**:
- Category taxonomy (8 security families)
- Tool mapping and deduplication
- Aggregation and support counting

**Output**: `output/normalization/llm_payload.json`

### Stage 3: Repair (Python)
**File**: `LLMs/multi_llm_orchestrator.py`

Generates fixes using multi-LLM consensus voting.

**Features**:
- 3 fix strategies: Deterministic, Template, LLM-Guided
- Multi-provider support: OpenAI, Groq, Gemini, OpenRouter
- Security hardening (4 controls applied together)
- Retry logic and fallback providers

**Output**: `output/repair/SECURED_*.yaml`

### Stage 4: Validation (Python)
**File**: `Validations/validation_gates_improved.py`

Validates fixes with comprehensive 7-gate framework.

**Gates**:
1. Schema Validation (kubeconform)
2. Policy Validation (conftest/OPA)
3. Dry-run Apply (kubectl)
4. Sandbox Deploy
5. Health Checks
6. Network Validation
7. E2E Smoke Tests

**Output**: `output/validation/SUMMARY_VALIDATION.csv`

## Command-Line Options

```
usage: pipeline.py [-h] [--input INPUT] [--output OUTPUT]
                   [--stage {detection,normalize,repair,validate,all}]
                   [--detection-mode {lean,extended}] [--raw RAW]
                   [--tests TESTS] [--payload PAYLOAD] [--models MODELS]
                   [--concurrency CONCURRENCY] [--fixed FIXED] [--strict]
                   [--verbose] [--quiet]

Options:
  --input, -i           Input directory (test YAML manifests)
  --output, -o          Output directory (default: output/)
  --stage               Run specific stage (default: all)
  --detection-mode      Detection mode: lean or extended (default: extended)
  --models              Comma-separated LLM models (default: groq,openrouter,gemini)
  --concurrency         Number of concurrent LLM requests (default: 5)
  --strict              Enable strict validation mode
  --verbose, -v         Enable verbose logging
  --quiet, -q           Quiet mode (errors only)
```

## Output Structure

After running the full pipeline:

```
output/
├── detection/
│   ├── raw/                    # Raw findings from 13 tools
│   │   ├── checkov_raw.json
│   │   ├── trivy_raw.json
│   │   └── ... (11 more)
│   └── logs/                   # Execution logs
│
├── normalization/
│   ├── llm_payload.json        # Input for LLM stage
│   ├── normalized_findings.json
│   └── buckets.csv
│
├── repair/
│   ├── SECURED_*.yaml          # Fixed manifests
│   ├── EXPLANATION_*.md        # Fix explanations
│   └── llm_decisions.json
│
└── validation/
    ├── SUMMARY_VALIDATION.csv  # Validation summary
    └── REPORT_VALIDATE_*.json  # Detailed reports
```

## Examples

### Example 1: Full Pipeline with Custom Settings

```bash
python pipeline.py \
  --input tests/ \
  --output results/ \
  --detection-mode extended \
  --models groq,openrouter \
  --concurrency 10 \
  --strict
```

### Example 2: Re-run Repair with Different Models

```bash
# Detection and normalization already done
python pipeline.py \
  --stage repair \
  --payload output/normalization/llm_payload.json \
  --tests tests/ \
  --models openai,gemini \
  --concurrency 3
```

### Example 3: Validate External Fixes

```bash
python pipeline.py \
  --stage validate \
  --tests tests/ \
  --fixed my-fixed-manifests/ \
  --payload output/normalization/llm_payload.json
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     pipeline.py (CLI)                        │
│  Unified interface for complete workflow orchestration      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 1: DETECTION (Detection/detectors.ps1)               │
│  • 13 tools scan K8s manifests via Docker                   │
│  • Output: Raw JSON per tool                                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 2: NORMALIZATION (Normalizer/normalizer.py)          │
│  • Unify 13 tool formats → single schema                    │
│  • Deduplicate & aggregate findings                         │
│  • Output: llm_payload.json                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 3: REPAIR (LLMs/multi_llm_orchestrator.py)           │
│  • Multi-LLM consensus (Groq, OpenRouter, Gemini)           │
│  • 3 fix strategies: Deterministic, Template, LLM-Guided    │
│  • Output: SECURED_*.yaml                                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 4: VALIDATION (Validations/validation_gates_*.py)    │
│  • 7-gate validation framework                              │
│  • Schema → Policy → Deploy → Health → Network → E2E       │
│  • Output: SUMMARY_VALIDATION.csv                           │
└─────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Detection fails with "Docker not found"
Ensure Docker is installed and running: `docker --version`

### LLM stage fails with API errors
- Check API keys in `.env` file
- Verify API quotas haven't been exceeded
- Try reducing `--concurrency` to avoid rate limits

### Validation requires kubectl
Some validation gates require `kubectl`. Install from: https://kubernetes.io/docs/tasks/tools/

### PowerShell execution policy error
Run: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser`

## File Structure

```
SafeFixK8s/
├── pipeline.py                 ⭐ MAIN CLI (this orchestrator)
├── requirements.txt
├── .env                        (API keys)
│
├── Detection/
│   └── detectors.ps1          ⭐ Stage 1
│
├── Normalizer/
│   └── normalizer.py          ⭐ Stage 2
│
├── LLMs/
│   └── multi_llm_orchestrator.py  ⭐ Stage 3
│
├── Validations/
│   ├── validation_gates_improved.py  ⭐ Stage 4
│   └── validation_config.yaml
│
├── policies/                   (OPA, Conftest, Checkov policies)
│   ├── checkov/
│   ├── conftest/
│   ├── opa/
│   └── opa_minimal/
│
├── tests/                      (Vulnerable K8s manifests)
└── output/                     (Generated results)
```

## Dependencies

**Python** (`requirements.txt`):
```
pyyaml>=6.0.0
requests>=2.31.0
```

**External Tools** (via Docker):
- Checkov, Trivy, Kubescape, Polaris, KubeLinter, KubeScore, KubeAudit, Conftest, Kubeconform, Yamllint, Pluto, RBACPolice, Gitleaks

## License

[Your License Here]

## Author

SafeFixK8s - BSc Thesis Project
