# SafeFixK8s Output Directory

## Overview
This directory contains the results from security scanner detection and normalization.

## Files Generated

### 1. `normalized_findings.json`
**Purpose:** Unified findings from all security scanners in a standardized format.

**Structure:**
```json
{
  "version": "1.0",
  "generatedAt": "2025-10-16T...",
  "source": "SafeFixK8s/Normalizer",
  "findings": [
    {
      "findingId": "...",
      "tool": "kubelinter",
      "ruleId": "no-read-only-root-fs",
      "severity": "HIGH",
      "resourceRef": {
        "kind": "Deployment",
        "name": "orders"
      },
      "message": "...",
      "location": {
        "file": "orders-deploy.yaml",
        "line": 42
      },
      "labels": {}
    }
  ]
}
```

**Key Points:**
- ✅ **Includes ALL findings** (duplicates are kept for analysis)
- Each finding has a unique `findingId` (MD5 hash)
- Severities normalized to: CRITICAL | HIGH | MEDIUM | LOW | INFO
- All tools use the same schema

---

### 2. `tool_detection_matrix.csv`
**Purpose:** Excel-friendly table showing which tools detected which issues.

**Columns:**
- **RuleID** — The security rule/check identifier
- **Severity** — Highest severity across all detections
- **ResourceKind** — Kubernetes resource type (Deployment, Pod, etc.)
- **ResourceName** — Name of the resource
- **File** — YAML file path
- **DetectionCount** — How many tools detected this issue
- **ToolCount** — Number of unique tools
- **Tool columns** — One column per tool with ✓ if detected

**Example:**
```
RuleID,Severity,ResourceKind,ResourceName,File,DetectionCount,ToolCount,kubelinter,polaris,trivy-config,...
no-read-only-root-fs,HIGH,Deployment,orders,orders-deploy.yaml,3,3,✓,✓,✓,...
```

**Use Cases:**
- 📊 **Tool comparison:** Which tools are most comprehensive?
- 🔍 **Coverage analysis:** Which issues are detected by multiple tools (high confidence)?
- 📈 **Thesis evaluation:** Compare tool effectiveness, overlap, and unique findings

---

### 3. `tool_detection_matrix.json`
**Purpose:** Programmatic version of the detection matrix with detailed statistics.

**Structure:**
```json
{
  "matrix": [
    {
      "ruleId": "no-read-only-root-fs",
      "severity": "HIGH",
      "resourceKind": "Deployment",
      "resourceName": "orders",
      "file": "orders-deploy.yaml",
      "detectionCount": 3,
      "toolsDetected": ["kubelinter", "polaris", "trivy-config"],
      "toolCount": 3
    }
  ],
  "toolStats": {
    "kubelinter": {
      "total": 45,    // Total findings from this tool
      "unique": 12    // Issues ONLY this tool detected
    },
    "polaris": { ... }
  },
  "allTools": ["checkov", "gitleaks", ...],
  "totalIssues": 234,      // Unique issues (grouped)
  "totalFindings": 716     // Total findings (with duplicates)
}
```

**Key Metrics:**
- **total** — How many findings this tool contributed
- **unique** — How many issues ONLY this tool found (no overlap)
- **detectionCount** — How many tools agree on this issue (consensus)

---

### 4. `raw/` (deleted after normalization)
Contains original scanner outputs:
- `kubelinter_raw.json`
- `polaris_raw.json`
- `trivy_config_raw.json`
- etc.

**Note:** These files are automatically deleted after normalization to save space. Re-run detection to regenerate them.

---

### 5. `logs/`
Contains stderr/diagnostic logs from scanners:
- `kubesec_stderr.txt`
- `kubescape_download.log`
- etc.

**Purpose:** Debugging scanner issues, version info, warnings.

---

## How to Use

### Run Full Pipeline
```powershell
# 1. Run all detectors
cd SafeFixK8s
.\scripts\detectors.ps1
Det-RunAll -Path "tests"

# 2. Normalize findings
python normalizer/normalize_all.py

# 3. Analyze results
# - Open tool_detection_matrix.csv in Excel
# - Or parse tool_detection_matrix.json programmatically
```

### Example Analysis (Python)
```python
import json
import pandas as pd

# Load detection matrix
with open("output/tool_detection_matrix.json") as f:
    data = json.load(f)

# Find high-confidence issues (detected by 3+ tools)
high_confidence = [
    row for row in data["matrix"]
    if row["toolCount"] >= 3
]
print(f"High-confidence issues: {len(high_confidence)}")

# Tool effectiveness ranking
stats = data["toolStats"]
ranking = sorted(stats.items(), key=lambda x: x[1]["total"], reverse=True)
for tool, metrics in ranking:
    print(f"{tool}: {metrics['total']} total, {metrics['unique']} unique")

# Load CSV for visualization
df = pd.read_csv("output/tool_detection_matrix.csv")
print(df.groupby("Severity").size())
```

---

## Thesis Applications

### 1. Tool Comparison
**Research Question:** Which security scanner is most effective?

**Metrics:**
- **Coverage:** Total findings per tool
- **Uniqueness:** Issues only one tool detected (unique value)
- **Precision:** Manual validation of true positives vs. false positives

### 2. Consensus Analysis
**Research Question:** Do multiple tools agree on critical issues?

**Approach:**
- Filter `detectionCount >= 3` for high-confidence issues
- Analyze overlap between tool pairs (Venn diagrams)
- Identify gaps: issues only 1 tool detected (potential false negatives in others)

### 3. Severity Distribution
**Visualization:**
```python
import matplotlib.pyplot as plt

severities = [row["severity"] for row in data["matrix"]]
plt.hist(severities)
plt.title("Security Issue Severity Distribution")
plt.show()
```

### 4. False Positive Analysis
- Manually review issues with `detectionCount == 1` (single tool)
- Calculate FP rate per tool
- Compare against issues with `detectionCount >= 3` (likely true positives)

---

## File Retention Policy

| File | Retained | Reason |
|------|----------|--------|
| `normalized_findings.json` | ✅ Yes | Final output |
| `tool_detection_matrix.csv` | ✅ Yes | Analysis/visualization |
| `tool_detection_matrix.json` | ✅ Yes | Programmatic access |
| `raw/*.json` | ❌ No | Deleted after normalization (save space) |
| `logs/*.txt` | ✅ Yes | Debugging/audit trail |

---

## Console Output Example

```
[ok] wrote output/normalized_findings.json with 716 findings (with duplicates).
[matrix] JSON saved to output/tool_detection_matrix.json
[matrix] CSV saved to output/tool_detection_matrix.csv

============================================================
TOOL DETECTION SUMMARY
============================================================
Total unique issues: 234
Total findings (with duplicates): 716

Per-Tool Statistics:
Tool                 Total      Unique    
----------------------------------------
checkov              89         12        
gitleaks             0          0         
kubelinter           45         8         
kubescape            123        34        
kubescore            67         15        
kubesec              34         3         
polaris              98         21        
terrascan            56         9         
trivy-config         87         14        
trufflehog           0          0         
yamllint             23         7         
============================================================

[cleanup] deleted kubelinter_raw.json
[cleanup] deleted polaris_raw.json
...
[cleanup] removed 13 raw file(s).
```

---

## Next Steps

1. **Open CSV in Excel** — Sort by DetectionCount, filter by Severity
2. **Analyze tool overlap** — Which combinations detect the most?
3. **Manual validation** — Pick a sample and verify true/false positives
4. **Visualize** — Create charts for your thesis (tool comparison, severity distribution)
5. **Automated repair** — Use `normalized_findings.json` as input for the repair engine

---

## Questions?

If you need to regenerate raw files (e.g., for re-analysis):
```powershell
Det-RunAll -Path "tests"  # Don't run normalizer yet
# Now raw files are available in output/raw/
```

To keep raw files permanently, comment out the cleanup section in `normalizer/normalize_all.py`.
