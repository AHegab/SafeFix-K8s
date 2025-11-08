# SafeFix-K8s Single-Tool Orchestration System

## 🎯 Overview

This orchestration system enables **isolated, reproducible pipeline runs for individual detection tools**, allowing for comprehensive comparison of tool coverage, fix success rates, and validation results.

## 📂 Directory Structure

```
SafeFixK8s/
├── orchestrator/
│   ├── safefix_single_tool.py    # Single-tool pipeline orchestrator
│   └── batch_run_tools.py        # Batch runner for multiple tools
├── compare/
│   └── compare_runs.py           # Run comparison and CSV generation
├── runs/
│   ├── 2025-11-06__KubeLinter/
│   │   ├── detection/
│   │   │   ├── kubelinter_raw.json
│   │   │   └── logs/
│   │   ├── normalization/
│   │   │   ├── llm_payload.json
│   │   │   └── normalized_findings.json
│   │   ├── llm/
│   │   │   ├── llm_decisions.json
│   │   │   └── patch_sandbox/
│   │   ├── validation/
│   │   │   ├── evidence/
│   │   │   └── safe_fix_proof.json
│   │   └── metadata.json
│   ├── 2025-11-06__Checkov/
│   └── 2025-11-06__Trivy/
└── tests/
    ├── 27.Misconfiguration.yaml
    └── 27.Valid.yaml
```

## 🔄 Pipeline Flow

Each tool run follows this **isolated pipeline**:

```
1. DETECTION
   └─> Run single tool on test manifests
   └─> Output: detection/TOOL_raw.json

2. NORMALIZATION
   └─> Extract findings for this tool only
   └─> Output: normalization/llm_payload.json

3. LLM REPAIR
   └─> Generate patches via multi-LLM consensus
   └─> Output: llm/llm_decisions.json, llm/patch_sandbox/

4. VALIDATION
   └─> Run 7-gate validation on patches
   └─> Output: validation/safe_fix_proof.json

5. METADATA
   └─> Save run statistics and timings
   └─> Output: metadata.json
```

## 🚀 Quick Start

### Run Single Tool

```bash
# Basic run
python orchestrator/safefix_single_tool.py --tool kubelinter --path tests

# With specific gates
python orchestrator/safefix_single_tool.py --tool checkov --gates 1,2,3

# Skip validation (faster for testing)
python orchestrator/safefix_single_tool.py --tool trivy --skip-validate

# Dry run (preview what would execute)
python orchestrator/safefix_single_tool.py --tool kubescape --dry-run
```

### Run Multiple Tools

```bash
# Run specific tools
python orchestrator/batch_run_tools.py --tools kubelinter,checkov,trivy

# Run all available tools
python orchestrator/batch_run_tools.py --all

# Quick test (3 tools only)
python orchestrator/batch_run_tools.py --quick

# Custom settings
python orchestrator/batch_run_tools.py --all --path tests --gates 1,2 --skip-validate
```

### Compare Results

```bash
# Compare all runs
python compare/compare_runs.py --runs runs/

# Compare specific runs
python compare/compare_runs.py --runs "runs/2025-11-06*"

# Custom output directory
python compare/compare_runs.py --runs runs/ --output compare/results_2025-11-06

# List available runs
python compare/compare_runs.py --list-runs
```

## 📊 Comparison Outputs

The comparison tool generates these CSV matrices:

### 1. `detection_coverage.csv`
Shows what each tool detected per file/category:

| File | Category | KubeLinter | Checkov | Trivy | Total Tools |
|------|----------|------------|---------|-------|-------------|
| batch-checkjob.yaml | PRIVILEGED | ✓ | ✓ | ✓ | 3 |
| batch-checkjob.yaml | MISSING_CAP_DROP | | ✓ | ✓ | 2 |
| build-code.deployment.yaml | RUN_AS_NONROOT_FALSE | ✓ | ✓ | | 2 |

### 2. `fix_success_rate.csv`
Fix generation success rates per tool:

| Tool | Total Findings | LLM Processed | Fixes Generated | Needs Review | Fix Success Rate % |
|------|----------------|---------------|-----------------|--------------|-------------------|
| KubeLinter | 45 | 45 | 38 | 7 | 84.4 |
| Checkov | 67 | 67 | 52 | 15 | 77.6 |
| Trivy | 51 | 51 | 45 | 6 | 88.2 |

### 3. `validation_pass_rate.csv`
Validation gate pass rates:

| Tool | Gates Run | Passed | Failed | Pass Rate % | Files Validated |
|------|-----------|--------|--------|-------------|-----------------|
| KubeLinter | 3 | 3 | 0 | 100.0 | 38 |
| Checkov | 3 | 2 | 1 | 66.7 | 52 |
| Trivy | 3 | 3 | 0 | 100.0 | 45 |

### 4. `performance_comparison.csv`
Performance metrics per tool:

| Tool | Detection Time (s) | Normalization Time (s) | LLM Repair Time (s) | Validation Time (s) | Total Time (s) |
|------|-------------------|------------------------|---------------------|---------------------|----------------|
| KubeLinter | 12.3 | 1.2 | 145.7 | 34.2 | 193.4 |
| Checkov | 45.6 | 2.1 | 198.4 | 45.3 | 291.4 |
| Trivy | 23.1 | 1.5 | 156.8 | 38.9 | 220.3 |

### 5. `summary_report.md`
Comprehensive markdown report with all metrics and comparisons.

## 🔧 Available Tools

| Tool | Description | Detection Focus |
|------|-------------|-----------------|
| `kubelinter` | Static analysis for K8s YAMLs | Security + Best practices |
| `checkov` | Policy-as-code scanner | Security policies (CKV_K8S_*) |
| `trivy` | Vulnerability scanner | Misconfigurations (KSV*) |
| `kubeaudit` | Security auditor | RBAC + Security contexts |
| `kubescape` | CISA framework scanner | Controls (C-*) |
| `polaris` | Best practices validator | Polaris checks |
| `kubescore` | Static code analysis | Best practices scoring |
| `conftest` | OPA policy testing | Custom policies |
| `kubeconform` | Schema validation | YAML schema validation |
| `pluto` | Deprecated API finder | API deprecation |
| `gitleaks` | Secret detection | Hardcoded secrets |
| `rbacpolice` | RBAC analyzer | RBAC over-permissions |
| `yamllint` | YAML linter | Syntax + formatting |

## 📝 Command Reference

### `safefix_single_tool.py`

**Purpose:** Run complete pipeline for one tool

**Arguments:**
- `--tool TOOL` - Detection tool to run (required)
- `--path PATH` - Path to scan (default: tests)
- `--run-dir DIR` - Custom run directory
- `--gates GATES` - Validation gates (default: 1,2,3)
- `--models MODELS` - LLM models (default: groq,openrouter,gemini)
- `--skip-detection` - Skip detection step
- `--skip-normalize` - Skip normalization step
- `--skip-llm` - Skip LLM repair step
- `--skip-validate` - Skip validation step
- `--dry-run` - Preview without executing

**Examples:**
```bash
# Full pipeline
python orchestrator/safefix_single_tool.py --tool kubelinter --path tests

# Detection + normalization only
python orchestrator/safefix_single_tool.py --tool checkov --skip-llm --skip-validate

# Resume from LLM step
python orchestrator/safefix_single_tool.py --tool trivy --skip-detection --skip-normalize

# Custom run directory
python orchestrator/safefix_single_tool.py --tool kubescape --run-dir runs/custom_run
```

### `batch_run_tools.py`

**Purpose:** Run multiple tools in sequence

**Arguments:**
- `--tools TOOLS` - Comma-separated tool list
- `--all` - Run all available tools
- `--quick` - Run quick subset (kubelinter, checkov, trivy)
- `--path PATH` - Path to scan
- `--gates GATES` - Validation gates
- `--models MODELS` - LLM models
- `--skip-validate` - Skip validation for all tools
- `--skip-llm` - Skip LLM for all tools

**Examples:**
```bash
# Specific tools
python orchestrator/batch_run_tools.py --tools kubelinter,checkov,trivy

# All tools
python orchestrator/batch_run_tools.py --all

# Quick test (3 tools)
python orchestrator/batch_run_tools.py --quick

# Fast detection-only run
python orchestrator/batch_run_tools.py --all --skip-llm --skip-validate
```

### `compare_runs.py`

**Purpose:** Compare multiple tool runs and generate CSVs

**Arguments:**
- `--runs PATTERN` - Run directories to compare (glob or dir)
- `--output DIR` - Output directory (default: compare/results)
- `--list-runs` - List all available runs

**Examples:**
```bash
# Compare all runs
python compare/compare_runs.py --runs runs/

# Compare specific date
python compare/compare_runs.py --runs "runs/2025-11-06*"

# Custom output
python compare/compare_runs.py --runs runs/ --output compare/results_final

# List runs
python compare/compare_runs.py --list-runs
```

## 🎓 B.Sc. Thesis Use Cases

### 1. Tool Coverage Analysis

**Goal:** Compare what each tool detects

```bash
# Run all tools
python orchestrator/batch_run_tools.py --all --path tests

# Generate coverage matrix
python compare/compare_runs.py --runs runs/ --output compare/coverage_analysis

# Analyze detection_coverage.csv to see:
# - Which tools detect which categories
# - Tool overlap and unique detections
# - Coverage gaps per tool
```

### 2. Fix Quality Evaluation

**Goal:** Measure LLM fix success across tools

```bash
# Run tools with LLM enabled
python orchestrator/batch_run_tools.py --quick --path tests

# Compare fix rates
python compare/compare_runs.py --runs runs/ --output compare/fix_quality

# Analyze fix_success_rate.csv to see:
# - Which tool findings are easier to fix
# - Fix success rates per tool
# - Needs_review patterns
```

### 3. Validation Effectiveness

**Goal:** Test validation gates on different tool outputs

```bash
# Run with full validation
python orchestrator/batch_run_tools.py --tools kubelinter,checkov --gates 1,2,3,4,5

# Compare validation results
python compare/compare_runs.py --runs runs/ --output compare/validation_study

# Analyze validation_pass_rate.csv to see:
# - Which gates catch which issues
# - False positive rates per tool
# - Validation reliability
```

### 4. Performance Benchmarking

**Goal:** Compare tool performance and overhead

```bash
# Run performance test
python orchestrator/batch_run_tools.py --all --path tests

# Generate performance report
python compare/compare_runs.py --runs runs/ --output compare/performance

# Analyze performance_comparison.csv to see:
# - Detection time per tool
# - LLM overhead per tool
# - Total pipeline time
```

## 🔍 Deterministic & Isolated Runs

### Key Design Principles

1. **Timestamp-based directories** - Each run gets unique `YYYY-MM-DD__HH-MM-SS__TOOL` directory
2. **No shared state** - Each tool run is completely isolated
3. **Reproducible** - Same inputs always produce same structure
4. **Traceable** - Full metadata.json records all settings and results
5. **Comparable** - Consistent output format enables automated comparison

### Run Metadata Structure

Each run's `metadata.json` contains:

```json
{
  "tool": "KubeLinter",
  "tool_normalized": "kubelinter",
  "scan_path": "tests/",
  "run_directory": "runs/2025-11-06__14-30-45__KubeLinter",
  "timestamp": "2025-11-06T14:30:45",
  "gates": "1,2,3",
  "models": ["groq", "openrouter", "gemini"],
  "steps_completed": ["detection", "normalization", "llm_repair", "validation"],
  "timings": {
    "detection": 12.3,
    "normalization": 1.2,
    "llm_repair": 145.7,
    "validation": 34.2
  },
  "results": {
    "raw_findings": 45,
    "normalized_findings": 38,
    "fixes_generated": 32,
    "gates_passed": 3,
    "gates_failed": 0
  },
  "completed_at": "2025-11-06T14:34:12",
  "total_duration": 193.4,
  "success": true
}
```

## 🧪 Testing Strategy

### Tests Directory Note

⚠️ **IMPORTANT:** Files in `tests/` are intentionally misconfigured for tool evaluation purposes.

- **Purpose:** Test tool detection capabilities
- **Content:** Deliberately vulnerable manifests
- **Usage:** Pipeline input only, NOT production examples
- **Examples:** Privileged containers, missing probes, floating tags

### Recommended Test Workflow

1. **Baseline run** - Use `tests/` for initial tool comparison
2. **Custom scenarios** - Create specific test cases per category
3. **Real-world validation** - Test on sanitized production manifests
4. **Comparison** - Compare results across all test sets

## 📚 Integration with Existing Layers

### Detection Layer Integration

The orchestrator uses `Detection/detectors.ps1`:

```powershell
# Called by orchestrator
Det-RunKubeLinter -Path "tests" -OutDir "runs/.../detection"
Det-RunCheckov -Path "tests" -OutDir "runs/.../detection"
# etc.
```

**Required:** Each tool function must support `-OutDir` parameter.

### Normalizer Integration

The orchestrator calls `Normalizer/normalize.py` with isolated directories:

```bash
python Normalizer/normalize.py \
  --raw runs/.../detection \
  --out runs/.../normalization \
  --min-support 1 \
  --only-security 1
```

**Key:** `min-support=1` for single-tool runs (no cross-tool correlation).

### LLM Layer Integration

The orchestrator calls `LLMs/multi_llm_orchestrator.py`:

```bash
python LLMs/multi_llm_orchestrator.py \
  --models groq,openrouter,gemini \
  --autofix \
  --hygiene
```

**Environment:**
- `SAFEFIX_NORMALIZATION_DIR` → `runs/.../normalization`
- `SAFEFIX_LLM_DIR` → `runs/.../llm`

### Validation Layer Integration

The orchestrator calls `Validations/validate-gates.ps1`:

```powershell
.\validate-gates.ps1 \
  -InputDir "runs/.../llm/patch_sandbox" \
  -Gates 1,2,3 \
  -EvidenceDir "runs/.../validation/evidence"
```

## 🔄 Typical Research Workflow

```bash
# 1. Run quick test
python orchestrator/batch_run_tools.py --quick --path tests --skip-validate

# 2. Check results
python compare/compare_runs.py --list-runs

# 3. Run full analysis
python orchestrator/batch_run_tools.py --all --path tests --gates 1,2,3

# 4. Generate comparison
python compare/compare_runs.py --runs runs/ --output compare/thesis_results

# 5. Analyze CSVs
cat compare/thesis_results/detection_coverage.csv
cat compare/thesis_results/fix_success_rate.csv
cat compare/thesis_results/summary_report.md
```

## 🐛 Troubleshooting

### Issue: Tool not found

**Solution:**
```bash
# Check available tools
python orchestrator/safefix_single_tool.py --help

# Verify tool is installed
python Detection/detectors.ps1 -List
```

### Issue: No findings generated

**Solution:**
```bash
# Check detection output
cat runs/LATEST/detection/TOOL_raw.json

# Run with dry-run first
python orchestrator/safefix_single_tool.py --tool TOOL --dry-run
```

### Issue: Comparison fails

**Solution:**
```bash
# List available runs
python compare/compare_runs.py --list-runs

# Check metadata exists
ls runs/*/metadata.json

# Run on specific subset
python compare/compare_runs.py --runs "runs/2025-11-06*"
```

## 📖 Further Reading

- **Detection Layer:** `Detection/README.md`
- **Normalizer:** `Normalizer/PERFECT_NORMALIZER.md`
- **LLM Layer:** `LLMs/README.md`
- **Validation:** `Validations/README.md`
- **CLI Usage:** `docs/top-level/CLI_GUIDE.md`

---

**Built for SafeFix-K8s B.Sc. Thesis Project**  
*Modular Pipeline for Kubernetes Security Remediation*
