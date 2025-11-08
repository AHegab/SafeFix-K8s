# SafeFix-K8s Single-Tool Orchestration - Quick Example

## 🚀 Complete Example Walkthrough

This guide demonstrates running the complete pipeline for individual tools and comparing results.

## Step 1: Run a Single Tool

```bash
# Run KubeLinter on test manifests
python orchestrator/safefix_single_tool.py --tool kubelinter --path tests --gates 1,2
```

**Expected Output:**
```
============================================================
SafeFix-K8s Single-Tool Orchestrator
============================================================
Tool: KubeLinter
Scan Path: C:\...\SafeFixK8s\tests
Run Directory: C:\...\SafeFixK8s\runs\2025-11-06__14-30-45__KubeLinter
============================================================

[*] Setting up run directory: ...
[✓] Directory structure created

============================================================
STEP 1: DETECTION - KubeLinter
============================================================
[*] Running KubeLinter on C:\...\tests
[*] Output directory: runs\.../detection
[✓] Detection completed in 12.3s
[✓] Found 45 raw findings

============================================================
STEP 2: NORMALIZATION - KubeLinter only
============================================================
[*] Normalizing findings from KubeLinter
[✓] Normalization completed in 1.2s
[✓] Generated 38 LLM items

============================================================
STEP 3: LLM REPAIR - KubeLinter findings
============================================================
[*] Running LLM orchestration with models: groq,openrouter,gemini
[*] Processing 38 items
[✓] LLM repair completed in 145.7s
[✓] Generated 32 fixes

============================================================
STEP 4: VALIDATION - 1,2 gates
============================================================
[*] Running validation gates: 1,2
[*] Input: runs\.../llm/patch_sandbox
[✓] Validation completed in 34.2s
[✓] Gates passed: 2

[✓] Metadata saved to runs\.../metadata.json

============================================================
✓ PIPELINE COMPLETED SUCCESSFULLY
============================================================
Results:
  Raw Findings: 45
  Normalized: 38
  Fixes Generated: 32
  Gates Passed: 2
  Total Time: 193.4s

Run directory: runs\2025-11-06__14-30-45__KubeLinter
============================================================
```

**Generated Structure:**
```
runs/2025-11-06__14-30-45__KubeLinter/
├── detection/
│   ├── kubelinter_raw.json          # Raw tool output
│   └── logs/
├── normalization/
│   ├── llm_payload.json             # LLM-ready findings
│   └── normalized_findings.json     # Debug output
├── llm/
│   ├── llm_decisions.json           # Fix decisions
│   └── patch_sandbox/               # Fixed YAML files
│       ├── batch-checkjob.yaml
│       └── build-code.deployment.yaml
├── validation/
│   ├── evidence/                    # Per-gate evidence
│   │   ├── gate1_schema.json
│   │   └── gate2_policy.json
│   └── safe_fix_proof.json          # Validation summary
└── metadata.json                    # Run metadata
```

## Step 2: Run Multiple Tools

```bash
# Run quick test subset (3 tools)
python orchestrator/batch_run_tools.py --quick --path tests --gates 1,2
```

**Expected Output:**
```
============================================================
Batch Tool Runner
============================================================
Tools to run: kubelinter, checkov, trivy
Total: 3 tools
============================================================

============================================================
Running pipeline for: kubelinter
============================================================
[... KubeLinter pipeline output ...]
[✓] Pipeline completed

============================================================
Running pipeline for: checkov
============================================================
[... Checkov pipeline output ...]
[✓] Pipeline completed

============================================================
Running pipeline for: trivy
============================================================
[... Trivy pipeline output ...]
[✓] Pipeline completed

============================================================
BATCH RUN COMPLETED
============================================================
Total tools: 3
Successful: 3
Failed: 0
Total time: 589.7s

Results:
  ✓ kubelinter
  ✓ checkov
  ✓ trivy

============================================================
To compare results, run:
  python compare/compare_runs.py --runs runs/
============================================================
```

**Generated Structure:**
```
runs/
├── 2025-11-06__14-30-45__KubeLinter/
├── 2025-11-06__14-35-12__Checkov/
└── 2025-11-06__14-40-28__Trivy/
```

## Step 3: Compare Results

```bash
# Generate comparison CSVs
python compare/compare_runs.py --runs runs/ --output compare/results
```

**Expected Output:**
```
============================================================
SafeFix-K8s Run Comparison Tool
============================================================

[*] Loading data from 3 runs...
[✓] Loaded KubeLinter - 45 findings
[✓] Loaded Checkov - 67 findings
[✓] Loaded Trivy - 51 findings
[✓] Loaded 3 runs successfully

[*] Generating detection coverage matrix...
[✓] Detection coverage saved to compare/results/detection_coverage.csv

[*] Generating fix success matrix...
[✓] Fix success matrix saved to compare/results/fix_success_rate.csv

[*] Generating validation pass matrix...
[✓] Validation pass matrix saved to compare/results/validation_pass_rate.csv

[*] Generating performance comparison...
[✓] Performance comparison saved to compare/results/performance_comparison.csv

[*] Generating summary report...
[✓] Summary report saved to compare/results/summary_report.md

============================================================
✓ COMPARISON COMPLETED
============================================================
Output directory: compare/results
============================================================
```

**Generated Files:**
```
compare/results/
├── detection_coverage.csv        # What each tool detected
├── fix_success_rate.csv          # Fix generation rates
├── validation_pass_rate.csv      # Gate pass rates
├── performance_comparison.csv    # Performance metrics
└── summary_report.md             # Full markdown report
```

## Step 4: Analyze Results

### View Detection Coverage

```bash
cat compare/results/detection_coverage.csv
```

**Output:**
```csv
File,Category,KubeLinter,Checkov,Trivy,Total Tools
batch-checkjob.yaml,PRIVILEGED,✓,✓,✓,3
batch-checkjob.yaml,MISSING_CAP_DROP,,✓,✓,2
batch-checkjob.yaml,POD_DEFAULT_NAMESPACE,✓,✓,✓,3
build-code.deployment.yaml,RUN_AS_NONROOT_FALSE,✓,✓,,2
build-code.deployment.yaml,READONLY_ROOTFS_FALSE,,✓,✓,2
build-code.deployment.yaml,IMAGE_LATEST,✓,✓,✓,3
cache-store.deployment.yaml,NO_RES_LIMITS,✓,✓,✓,3
```

**Insights:**
- ✅ PRIVILEGED detected by all 3 tools (high confidence)
- ⚠️ MISSING_CAP_DROP only by Checkov & Trivy (KubeLinter blind spot)
- ✅ POD_DEFAULT_NAMESPACE detected by all (excellent coverage)
- ⚠️ RUN_AS_NONROOT_FALSE missed by Trivy (coverage gap)

### View Fix Success Rates

```bash
cat compare/results/fix_success_rate.csv
```

**Output:**
```csv
Tool,Total Findings,LLM Processed,Fixes Generated,Needs Review,Safe (No Fix),Fix Success Rate %
KubeLinter,45,38,32,6,0,84.2
Checkov,67,61,48,11,2,78.7
Trivy,51,47,42,5,0,89.4
```

**Insights:**
- ✅ Trivy has highest fix rate (89.4%)
- ⚠️ Checkov has most "needs review" cases (11)
- ✅ All tools have good overall fix rates (>78%)

### View Validation Results

```bash
cat compare/results/validation_pass_rate.csv
```

**Output:**
```csv
Tool,Gates Run,Passed,Failed,Pass Rate %,Files Validated,Timestamp
KubeLinter,2,2,0,100.0,32,2025-11-06T14:34:12Z
Checkov,2,2,0,100.0,48,2025-11-06T14:39:45Z
Trivy,2,2,0,100.0,42,2025-11-06T14:44:58Z
```

**Insights:**
- ✅ All tools passed both validation gates (100%)
- ✅ Gates 1 & 2 (schema + policy) are reliable
- ✅ All generated fixes are valid Kubernetes manifests

### View Performance Metrics

```bash
cat compare/results/performance_comparison.csv
```

**Output:**
```csv
Tool,Detection Time (s),Normalization Time (s),LLM Repair Time (s),Validation Time (s),Total Time (s),Steps Completed
KubeLinter,12.3,1.2,145.7,34.2,193.4,"detection, normalization, llm_repair, validation"
Checkov,45.6,2.1,198.4,45.3,291.4,"detection, normalization, llm_repair, validation"
Trivy,23.1,1.5,156.8,38.9,220.3,"detection, normalization, llm_repair, validation"
```

**Insights:**
- 🚀 KubeLinter is fastest (193.4s total)
- 🐌 Checkov is slowest (291.4s total, 45.6s detection)
- ⚡ Detection time varies significantly (12.3s - 45.6s)
- 🔄 LLM repair dominates total time (~75% of runtime)

### View Summary Report

```bash
cat compare/results/summary_report.md
```

**Output:**
```markdown
# SafeFix-K8s Tool Comparison Report

**Generated:** 2025-11-06 14:45:30

**Runs Analyzed:** 3

## Tools Compared

- **KubeLinter** (2025-11-06T14:30:45)
- **Checkov** (2025-11-06T14:35:12)
- **Trivy** (2025-11-06T14:40:28)

## Detection Coverage Summary

| Tool | Raw Findings | Normalized Items | Categories Detected |
|------|--------------|------------------|---------------------|
| KubeLinter | 45 | 38 | 12 |
| Checkov | 67 | 61 | 15 |
| Trivy | 51 | 47 | 13 |

## Fix Generation Summary

| Tool | Findings | Fixes Generated | Fix Rate |
|------|----------|-----------------|----------|
| KubeLinter | 38 | 32 | 84.2% |
| Checkov | 61 | 48 | 78.7% |
| Trivy | 47 | 42 | 89.4% |

## Validation Summary

| Tool | Gates Run | Passed | Failed | Pass Rate |
|------|-----------|--------|--------|-----------|
| KubeLinter | 2 | 2 | 0 | 100.0% |
| Checkov | 2 | 2 | 0 | 100.0% |
| Trivy | 2 | 2 | 0 | 100.0% |

## Performance Summary

| Tool | Total Time | Detection | Normalization | LLM Repair | Validation |
|------|------------|-----------|---------------|------------|------------|
| KubeLinter | 193.4s | 12.3s | 1.2s | 145.7s | 34.2s |
| Checkov | 291.4s | 45.6s | 2.1s | 198.4s | 45.3s |
| Trivy | 220.3s | 23.1s | 1.5s | 156.8s | 38.9s |

---

*Generated by SafeFix-K8s Run Comparison Tool (B.Sc. Thesis)*
```

## Step 5: Advanced Usage

### Run Specific Tool with Custom Settings

```bash
# KubeAudit with all 5 gates
python orchestrator/safefix_single_tool.py \
  --tool kubeaudit \
  --path tests \
  --gates 1,2,3,4,5 \
  --models groq,openrouter
```

### Resume Failed Run

```bash
# If LLM step failed, resume from there
python orchestrator/safefix_single_tool.py \
  --tool checkov \
  --run-dir runs/2025-11-06__14-35-12__Checkov \
  --skip-detection \
  --skip-normalize
```

### Fast Detection-Only Run

```bash
# Skip expensive steps for quick coverage analysis
python orchestrator/batch_run_tools.py \
  --all \
  --skip-llm \
  --skip-validate
```

### Compare Specific Date

```bash
# Compare only today's runs
python compare/compare_runs.py \
  --runs "runs/2025-11-06*" \
  --output compare/results_2025-11-06
```

## Expected Timeline

For typical test suite (15-20 YAML files):

| Step | Time | Description |
|------|------|-------------|
| Detection | 10-45s | Depends on tool (KubeLinter fast, Checkov slow) |
| Normalization | 1-3s | Always fast |
| LLM Repair | 140-200s | Depends on finding count & models |
| Validation (gates 1-2) | 30-50s | Offline gates only |
| Validation (gates 1-5) | 120-180s | Includes cluster operations |

**Total per tool:** ~3-5 minutes (gates 1-2) or ~5-8 minutes (all gates)

## Troubleshooting

### No findings generated

```bash
# Check raw detection output
cat runs/LATEST_RUN/detection/TOOL_raw.json

# Verify test files exist
ls tests/*.yaml

# Run with dry-run first
python orchestrator/safefix_single_tool.py --tool TOOL --dry-run
```

### LLM fails

```bash
# Check API keys
cat .env | grep API_KEY

# Try with single model
python orchestrator/safefix_single_tool.py --tool TOOL --models groq

# Skip LLM for testing
python orchestrator/safefix_single_tool.py --tool TOOL --skip-llm
```

### Validation fails

```bash
# Run offline gates only
python orchestrator/safefix_single_tool.py --tool TOOL --gates 1,2

# Check validation evidence
cat runs/LATEST_RUN/validation/evidence/*.json

# Skip validation entirely
python orchestrator/safefix_single_tool.py --tool TOOL --skip-validate
```

---

**Ready to run the complete example?**

```bash
# Quick end-to-end test
python orchestrator/batch_run_tools.py --quick --path tests --gates 1,2
python compare/compare_runs.py --runs runs/
cat compare/results/summary_report.md
```

This will give you a complete comparison in ~10-15 minutes!
