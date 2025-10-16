# SafeFixK8s

**Automated Security Detection, Repair, and Validation for Kubernetes Manifests**

A comprehensive security automation framework that detects misconfigurations in Kubernetes YAML files using 15+ industry-standard scanners, normalizes findings into a unified format, and generates tool comparison matrices for analysis.

---

## 🎯 Features

✅ **Multi-Tool Detection** — Runs 15+ security scanners (KubeLinter, Polaris, Trivy, Kubescape, etc.)  
✅ **Unified Normalization** — Converts heterogeneous scanner outputs to a single schema  
✅ **Tool Comparison Matrix** — Shows which tools detected which issues (CSV + JSON)  
✅ **Offline Capable** — Caches Docker images locally for reproducible runs  
✅ **Duplicate Tracking** — Keeps all findings to analyze tool overlap and consensus  
✅ **Progress Tracking** — Visual progress bar and per-tool timing  
✅ **Automatic Cleanup** — Removes raw files after normalization  

---

## 🏗️ Architecture

```
SafeFixK8s/
├── normalizer/               # Unified parsing & normalization
│   └── normalize_all.py
├── scripts/
│   ├── detectors.ps1         # PowerShell orchestration (15+ tools)
│   └── analyze_matrix.py     # Detection matrix analysis
├── output/
│   ├── normalized_findings.json      # Final unified output
│   ├── tool_detection_matrix.csv     # Excel-friendly comparison
│   ├── tool_detection_matrix.json    # Programmatic analysis
│   ├── raw/                          # Raw scanner outputs (auto-deleted)
│   └── logs/                         # Diagnostic logs
├── tests/
│   └── orders-deploy.yaml    # Hardened K8s deployment for testing
└── tools/
    └── kubescape/            # Local CLI + cached policies
```

---

## 🚀 Quick Start

### Prerequisites
- **Docker Desktop** (for scanner containers)
- **Python 3.9+** (for normalization)
- **PowerShell 5.1+** (for detection orchestration)

### 1. Run Detection
```powershell
cd SafeFixK8s
.\scripts\detectors.ps1

# Run all scanners on test manifests
Det-RunAll -Path "tests"

# Optional: Scan with image analysis
Det-RunAll -Path "tests" -Image "nginx:alpine"
```

This will:
- Pull/load 15+ Docker scanner images (cached in `images/`)
- Run each scanner against your K8s manifests
- Save raw outputs to `output/raw/*.json`
- Show progress bar and timing summary

### 2. Normalize & Analyze
```powershell
python normalizer/normalize_all.py
```

This will:
- Parse all raw scanner outputs
- Generate `normalized_findings.json` (unified schema)
- Create `tool_detection_matrix.csv` (which tools detected what)
- Create `tool_detection_matrix.json` (statistics)
- Delete raw files (cleanup)

### 3. Analyze Results
```powershell
# Run comprehensive analysis
python scripts/analyze_matrix.py
```

Or open `output/tool_detection_matrix.csv` in Excel.

---

## 📊 Detection Matrix

The **tool detection matrix** is the key innovation for thesis analysis:

### CSV Format (Excel-friendly)
```csv
RuleID,Severity,ResourceKind,ResourceName,File,DetectionCount,ToolCount,kubelinter,polaris,trivy-config,...
no-read-only-root-fs,HIGH,Deployment,orders,orders-deploy.yaml,3,3,✓,✓,✓,...
privileged-container,CRITICAL,Pod,nginx,nginx.yaml,5,5,✓,✓,✓,✓,✓,...
```

### JSON Format (programmatic)
```json
{
  "matrix": [
    {
      "ruleId": "no-read-only-root-fs",
      "severity": "HIGH",
      "resourceKind": "Deployment",
      "resourceName": "orders",
      "detectionCount": 3,
      "toolsDetected": ["kubelinter", "polaris", "trivy-config"],
      "toolCount": 3
    }
  ],
  "toolStats": {
    "kubelinter": {
      "total": 45,    // Total findings
      "unique": 12    // Only this tool detected
    }
  },
  "totalIssues": 234,
  "totalFindings": 716
}
```

---

## 🔧 Supported Scanners

### Kubernetes Manifest Linters
- **KubeLinter** — Red Hat/StackRox security linter
- **Polaris** — Fairwinds best practices checker
- **Kube-Score** — Quality/reliability scoring
- **Kubescape** — ARMO/NSA/MITRE compliance scanner
- **Kubesec** — Security risk analysis
- **KubeAudit** — Shopify security auditor
- **Kyverno CLI** — Policy engine (optional)

### IaC/Config Scanners
- **Trivy Config** — Aqua Security misconfig scanner
- **Checkov** — Bridgecrew IaC security
- **Terrascan** — Tenable K8s/Terraform scanner
- **Yamllint** — YAML syntax/style checker

### Secrets Detection
- **Gitleaks** — High-entropy secrets scanner
- **TruffleHog** — Verified credential scanner

### Container Image Scanners (optional)
- **Syft** — SBOM generator
- **Grype** — Vulnerability scanner
- **Hadolint** — Dockerfile linter
- **Dockle** — Docker image security

---

## 📈 Thesis Applications

### 1. Tool Effectiveness Comparison
**Research Question:** Which scanner is most comprehensive?

```python
import json
data = json.load(open("output/tool_detection_matrix.json"))
stats = data["toolStats"]

# Rank by total detections
ranked = sorted(stats.items(), key=lambda x: x[1]["total"], reverse=True)
for tool, metrics in ranked:
    print(f"{tool}: {metrics['total']} total, {metrics['unique']} unique")
```

### 2. Consensus Analysis
**Research Question:** Do tools agree on critical issues?

```python
# High-confidence issues (3+ tools)
high_conf = [r for r in data["matrix"] if r["toolCount"] >= 3]
print(f"High-confidence: {len(high_conf)}")

# Single-tool findings (validate for false positives)
single = [r for r in data["matrix"] if r["toolCount"] == 1]
print(f"Needs validation: {len(single)}")
```

### 3. Severity Distribution
```python
from collections import Counter
severities = Counter(r["severity"] for r in data["matrix"])
print(severities)  # {'HIGH': 89, 'MEDIUM': 67, 'INFO': 45, ...}
```

### 4. Tool Overlap (Jaccard Similarity)
```python
# Run the analysis script
python scripts/analyze_matrix.py
# Outputs: thesis_tool_ranking.csv, thesis_severity_dist.csv, thesis_consensus_dist.csv
```

---

## 🧪 Example Workflow

```powershell
# 1. Scan a real-world K8s project
Det-RunAll -Path "path/to/kubernetes/manifests"

# 2. Normalize
python normalizer/normalize_all.py

# 3. Analyze
python scripts/analyze_matrix.py

# Output:
# ============================================================
# TOOL DETECTION SUMMARY
# ============================================================
# Total unique issues: 234
# Total findings (with duplicates): 716
#
# Per-Tool Statistics:
# Tool                 Total      Unique    
# ----------------------------------------
# kubescape            123        34        
# polaris              98         21        
# checkov              89         12        
# trivy-config         87         14        
# ...
```

---

## 📝 Output Files

| File | Description | Size |
|------|-------------|------|
| `normalized_findings.json` | All findings in unified schema | ~500 KB |
| `tool_detection_matrix.csv` | Excel table (which tools detected what) | ~50 KB |
| `tool_detection_matrix.json` | Matrix + statistics | ~100 KB |
| `thesis_*.csv` | Charts data (ranking, severity, consensus) | ~5 KB each |

---

## ⚙️ Configuration

### Add a New Scanner

1. **Add to `detectors.ps1`:**
```powershell
function Det-NewTool {
  param([string]$Path=".", [string]$Out="$OutDir\newtool_raw.json")
  docker run --rm -v "${PWD}:/work:ro" vendor/newtool:latest `
    scan "/work/$Path" -o json | Set-Content -Encoding UTF8 -Path $Out
}
```

2. **Add to `normalize_all.py`:**
```python
def from_newtool(p: Path) -> List[Dict]:
    data = load_json(p) or {}
    findings = []
    for item in data.get("results", []):
        findings.append(_mk(
            tool="newtool",
            rule=item.get("rule"),
            severity=item.get("severity"),
            kind=item.get("kind"),
            name=item.get("name"),
            message=item.get("message"),
            file=item.get("file")
        ))
    return findings

# In collect_all():
findings += from_newtool(RAW_DIR / "newtool_raw.json")
```

3. **Update `Det-RunAll` steps list** to include `"NewTool"`

---

## 🎓 BSc Thesis Structure

### Suggested Chapters

1. **Introduction**
   - Problem: Manual K8s security audits are slow/incomplete
   - Solution: Automated multi-tool detection + consensus analysis

2. **Background**
   - Kubernetes security best practices (CIS, NSA, MITRE)
   - Static analysis vs. runtime security
   - Existing tools landscape

3. **Related Work**
   - Survey of 15+ scanners
   - Comparison studies (accuracy, performance, coverage)

4. **Design & Implementation**
   - Architecture (detection → normalization → matrix)
   - Tool integration challenges
   - Unified schema design

5. **Evaluation**
   - Dataset: Real-world K8s repos (100+ manifests)
   - Metrics: Coverage, consensus, false positives, performance
   - Tool comparison results (from detection matrix)

6. **Conclusion**
   - Multi-tool consensus improves confidence
   - Unique detections reveal tool strengths
   - Future: Automated repair, validation loop

---

## 🛠️ Development

### Run Tests
```powershell
# Test with hardened manifest (should have minimal findings)
Det-RunAll -Path "tests/orders-deploy.yaml"
python normalizer/normalize_all.py
```

### Debug a Scanner
```powershell
# Run single tool
Det-KubeLinter -Path "tests"

# Check raw output
cat output/raw/kubelinter_raw.json

# Check logs
cat output/logs/kubesec_stderr.txt
```

### Keep Raw Files (Don't Auto-Delete)
Comment out cleanup section in `normalize_all.py`:
```python
# Delete all raw files after successful normalization (keep logs/)
# deleted_count = 0
# if RAW_DIR.exists():
#     ...
```

---

## 📚 Resources

- [Kubescape](https://github.com/kubescape/kubescape) — NSA/MITRE frameworks
- [KubeLinter](https://github.com/stackrox/kube-linter) — Production-ready checks
- [Polaris](https://github.com/FairwindsOps/polaris) — Best practices
- [Trivy](https://github.com/aquasecurity/trivy) — Comprehensive scanner
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

---

## 📄 License

MIT License (for thesis/academic use)

---

## 👤 Author

**Ahmed Hegab**  
BSc Thesis — German International University (GIU)  
Automated Security Detection & Repair for Kubernetes

---

## 🙏 Acknowledgments

This framework builds on the excellent work of:
- StackRox/Red Hat (KubeLinter)
- Fairwinds (Polaris)
- Aqua Security (Trivy)
- ARMO (Kubescape)
- And 10+ other open-source security projects

---

**Next Steps:**
1. Run detection: `Det-RunAll -Path "tests"`
2. Normalize: `python normalizer/normalize_all.py`
3. Analyze: `python scripts/analyze_matrix.py`
4. Open `output/tool_detection_matrix.csv` in Excel
5. Start writing Chapter 5 (Evaluation)! 🎓
