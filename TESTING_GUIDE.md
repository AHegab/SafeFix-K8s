# SafeFixK8s — Complete Testing Guide

## 🚀 Testing from Start to Finish

This guide walks you through testing the entire SafeFixK8s pipeline from detection to analysis.

---

## ✅ Prerequisites Check

### 1. Check Docker is Running
```cmd
docker --version
docker ps
```

**Expected Output:**
```
Docker version 24.x.x
CONTAINER ID   IMAGE   ...
```

**If not working:**
- Start Docker Desktop
- Wait for it to fully start (whale icon in system tray)

### 2. Check Python is Installed
```cmd
python --version
```

**Expected Output:**
```
Python 3.9.x or higher
```

### 3. Navigate to Project Root
```cmd
cd "C:\Users\Ahmed\OneDrive - GIU AS - German International University of Applied Sciences\Desktop\Bsc Thesis\Implementaions\SafeFixK8s"
```

---

## 📋 Step-by-Step Testing

### **STEP 1: Clean Previous Outputs** (Optional but Recommended)

```powershell
# Open PowerShell terminal
# Delete old outputs to start fresh
Remove-Item -Path "output\raw\*.*" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "output\normalized_findings.json" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "output\tool_detection_matrix.csv" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "output\tool_detection_matrix.json" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "output\thesis_*.csv" -Force -ErrorAction SilentlyContinue

Write-Host "✓ Cleaned previous outputs" -ForegroundColor Green
```

---

### **STEP 2: Load Detector Scripts**

```powershell
# Load the PowerShell detector functions
. .\scripts\detectors.ps1

Write-Host "✓ Loaded detector scripts" -ForegroundColor Green
```

**Expected Output:**
```
(No output means success)
```

**If you see errors:**
- Make sure you're in the SafeFixK8s root directory
- Check that `scripts/detectors.ps1` exists

---

### **STEP 3: Ensure Docker Images (First Time Only)**

```powershell
# This downloads/loads all 15+ scanner Docker images
# ONLY RUN THIS ONCE (or when you want to update images)
Ensure-DetectorImages
```

**Expected Output:**
```
Loading image stackrox_kube-linter_latest.tar ...
Loading image quay.io_fairwinds_polaris_latest.tar ...
...
Loaded 15 images from repo cache.
```

**Time:** 5-10 minutes (first time only)  
**Storage:** ~2-3 GB in `images/` folder

**Skip this step if:**
- You already have images cached in `images/` folder
- You've run this before

---

### **STEP 4: Run All Detectors**

```powershell
# Scan the test manifests
Det-RunAll -Path "tests"
```

**Expected Output:**
```
SafeFix-K8s detectors: Running: KubeLinter (7%)
SafeFix-K8s detectors: Running: Polaris (14%)
SafeFix-K8s detectors: Running: TrivyConfig (21%)
...

────────── Detectors runtime summary ──────────
Tool         Sec     Status
--------------------------------
TrivyConfig  12.5    ok
Kubescape    11.2    ok
Polaris      8.7     ok
...
Total time: 45.32 sec
All detectors finished.
```

**Time:** 30-60 seconds (with cached images)

**What happens:**
- 15+ scanners run against `tests/` folder
- Raw outputs saved to `output/raw/*.json`
- Progress bar shows which tool is running
- Summary shows per-tool timing

**Files created:**
```
output/raw/
  ├── kubelinter_raw.json
  ├── polaris_raw.json
  ├── trivy_config_raw.json
  ├── kubescore_raw.json
  ├── kubescape_raw.json
  ├── kubesec_raw.json
  ├── kubeaudit_raw.json
  ├── kyverno_raw.json
  ├── checkov_raw.json
  ├── terrascan_raw.json
  ├── yamllint_raw.txt
  ├── gitleaks_raw.json
  └── trufflehog_raw.json
```

**If a tool fails:**
- It creates a placeholder file: `[{"tool":"...", "note":"error message"}]`
- Other tools continue running
- Check `output/logs/*.txt` for error details

---

### **STEP 5: Verify Raw Outputs**

```powershell
# Check that raw files were created
Get-ChildItem -Path "output\raw" | Select-Object Name, Length

Write-Host "`n✓ Raw files generated" -ForegroundColor Green
```

**Expected Output:**
```
Name                     Length
----                     ------
checkov_raw.json          12345
gitleaks_raw.json            45
kubeaudit_raw.json         8901
kubelinter_raw.json        5678
kubescape_raw.json        23456
kubescore_raw.json         7890
kubesec_raw.json           3456
kyverno_raw.json             67
polaris_raw.json          15678
terrascan_raw.json         9012
trivy_config_raw.json     11234
trufflehog_raw.json          89
yamllint_raw.txt           1234
```

**Troubleshooting:**
- If a file is 0 bytes → Tool failed, check logs
- If a file has `[{"tool":"...","note":"..."}]` → Placeholder (tool error)
- If files are missing → Re-run Step 4

---

### **STEP 6: Normalize Findings**

```cmd
# Switch to cmd or keep PowerShell
python normalizer\normalize_all.py
```

**Expected Output:**
```
[ok] wrote output\normalized_findings.json with 716 findings (with duplicates).
[matrix] JSON saved to output\tool_detection_matrix.json
[matrix] CSV saved to output\tool_detection_matrix.csv

============================================================
TOOL DETECTION SUMMARY
============================================================
Total unique issues: 234
Total findings (with duplicates): 716

Per-Tool Statistics:
Tool                 Total      Unique    
----------------------------------------
kubescape            123        34        
polaris              98         21        
checkov              89         12        
trivy-config         87         14        
kubescore            67         15        
terrascan            56         9         
kubelinter           45         8         
kubesec              34         3         
yamllint             23         7         
gitleaks             0          0         
trufflehog           0          0         
kubeaudit            0          0         
kyverno              0          0         
============================================================

[cleanup] deleted kubelinter_raw.json
[cleanup] deleted polaris_raw.json
...
[cleanup] removed 13 raw file(s).
```

**Time:** 1-2 seconds

**What happens:**
- Parses all 13 raw files
- Generates unified `normalized_findings.json`
- Creates detection matrix (CSV + JSON)
- Shows per-tool statistics
- Deletes raw files (cleanup)

**Files created:**
```
output/
  ├── normalized_findings.json        (~500 KB)
  ├── tool_detection_matrix.csv       (~50 KB)
  └── tool_detection_matrix.json      (~100 KB)
```

**Files deleted:**
```
output/raw/*.json  (all raw files removed)
```

**If you see errors:**
- `FileNotFoundError` → Re-run Step 4 (detectors)
- `JSONDecodeError` → A raw file has invalid JSON (check logs)
- `ImportError` → Missing Python dependencies

---

### **STEP 7: Analyze Detection Matrix**

```cmd
python scripts\analyze_matrix.py
```

**Expected Output:**
```
============================================================
SAFEFIX-K8S DETECTION MATRIX ANALYSIS
============================================================
Total unique issues: 234
Total findings (with duplicates): 716
Tools analyzed: 13

============================================================
TOOL EFFECTIVENESS RANKING
============================================================
Rank   Tool                 Total      Unique     %Unique   
------------------------------------------------------------
1      kubescape            123        34         27.6%     
2      polaris              98         21         21.4%     
3      checkov              89         12         13.5%     
4      trivy-config         87         14         16.1%     
5      kubescore            67         15         22.4%     
...

============================================================
CONSENSUS ANALYSIS
============================================================
Tools           Count      %         
-----------------------------------
5 tool(s)       12         5.1%      
4 tool(s)       23         9.8%      
3 tool(s)       45         19.2%     
2 tool(s)       67         28.6%     
1 tool(s)       87         37.2%     

✓ High-confidence issues (3+ tools): 80
⚠ Single-tool findings (needs validation): 87

============================================================
SEVERITY DISTRIBUTION
============================================================
Severity        Count      %         
-----------------------------------
CRITICAL        15         6.4%      
HIGH            89         38.0%     
MEDIUM          67         28.6%     
LOW             45         19.2%     
INFO            18         7.7%      

============================================================
TOP 10 MOST-DETECTED ISSUES
============================================================
RuleID                         Severity   Tools  Resource            
----------------------------------------------------------------------
no-read-only-root-fs          HIGH       5      Deployment/orders   
privileged-container          CRITICAL   5      Pod/nginx           
missing-resource-limits       MEDIUM     6      Deployment/app      
...

============================================================
TOOL OVERLAP ANALYSIS (Top Pairs)
============================================================
Tool 1               Tool 2               Shared   Jaccard%  
------------------------------------------------------------
kubescape            polaris              45       62.5%     
trivy-config         checkov              34       58.3%     
kubelinter           kubescape            28       51.2%     
...

✓ Exported thesis data to output/thesis_*.csv

============================================================
Analysis complete! Check output/thesis_*.csv for chart data.
============================================================
```

**Time:** 1-2 seconds

**Files created:**
```
output/
  ├── thesis_tool_ranking.csv
  ├── thesis_severity_dist.csv
  └── thesis_consensus_dist.csv
```

---

### **STEP 8: View Results in Excel**

```powershell
# Open the detection matrix CSV
Start-Process "output\tool_detection_matrix.csv"
```

**What you'll see:**
- Excel spreadsheet with tool columns
- ✓ marks showing which tools detected each issue
- Sort by `DetectionCount` to see high-confidence issues
- Filter by `Severity` to prioritize critical issues

---

### **STEP 9: Inspect JSON Outputs**

```cmd
# View normalized findings
type output\normalized_findings.json | more

# View detection matrix
type output\tool_detection_matrix.json | more
```

Or open in VS Code:
```cmd
code output\normalized_findings.json
code output\tool_detection_matrix.json
```

---

## 🎯 Quick Test (Full Pipeline in 5 Commands)

```powershell
# 1. Load scripts
. .\scripts\detectors.ps1

# 2. Ensure images (first time only)
Ensure-DetectorImages

# 3. Run detectors
Det-RunAll -Path "tests"

# 4. Normalize
python normalizer\normalize_all.py

# 5. Analyze
python scripts\analyze_matrix.py

# 6. View in Excel
Start-Process "output\tool_detection_matrix.csv"
```

**Total time:** ~2 minutes (with cached images)

---

## 🔍 Verification Checklist

After running all steps, verify:

```powershell
# Check all output files exist
Test-Path "output\normalized_findings.json"
Test-Path "output\tool_detection_matrix.csv"
Test-Path "output\tool_detection_matrix.json"
Test-Path "output\thesis_tool_ranking.csv"
Test-Path "output\thesis_severity_dist.csv"
Test-Path "output\thesis_consensus_dist.csv"

# Count findings
$data = Get-Content "output\normalized_findings.json" | ConvertFrom-Json
Write-Host "Total findings: $($data.findings.Count)" -ForegroundColor Cyan

# Check matrix size
$matrix = Import-Csv "output\tool_detection_matrix.csv"
Write-Host "Unique issues in matrix: $($matrix.Count)" -ForegroundColor Cyan
```

**Expected:**
```
True
True
True
True
True
True
Total findings: 716
Unique issues in matrix: 234
```

---

## 🐛 Troubleshooting

### Problem: "Docker is not running"
**Solution:**
```powershell
# Start Docker Desktop manually
# Wait 30 seconds
docker ps  # Check if it works
```

### Problem: "Module not found: PowerShell script"
**Solution:**
```powershell
# Make sure you're in the right directory
Get-Location  # Should show: ...SafeFixK8s

# Load the script with dot-sourcing
. .\scripts\detectors.ps1
```

### Problem: "Python command not found"
**Solution:**
```cmd
# Try with full path
py normalizer\normalize_all.py

# Or use Python launcher
python3 normalizer\normalize_all.py
```

### Problem: "No findings generated"
**Solution:**
```powershell
# Check if raw files exist
Get-ChildItem "output\raw"

# Re-run detectors
Det-RunAll -Path "tests"

# Check logs for errors
Get-Content "output\logs\*" | Select-String "error" -Context 2
```

### Problem: "Empty or placeholder raw files"
**Solution:**
```powershell
# Check which tool failed
Get-Content "output\raw\*.json" | Select-String "placeholder|error"

# Check logs
Get-ChildItem "output\logs\*.txt" | ForEach-Object { 
    Write-Host "`n=== $($_.Name) ===" -ForegroundColor Yellow
    Get-Content $_.FullName | Select-Object -Last 20
}

# Try running that specific tool manually
Det-Polaris -Path "tests"  # Example
```

---

## 📊 Expected Results (for tests/orders-deploy.yaml)

Since `orders-deploy.yaml` is a **hardened manifest**, you should see:

- **Low finding count** (~10-20 issues total)
- **Most findings are INFO or LOW severity** (best practices, not critical)
- **Few tools detect issues** (because the manifest is already secure)

**Example summary:**
```
Total unique issues: 12
Total findings: 23
High-confidence issues: 3
```

**Common findings on hardened manifests:**
- Image digest recommendation (best practice)
- Label suggestions (INFO)
- Documentation suggestions (LOW)

---

## 🚀 Test with Real-World Manifests

To get more interesting results:

```powershell
# Test with an insecure manifest
@"
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
"@ | Set-Content "tests\insecure.yaml"

# Re-run pipeline
Det-RunAll -Path "tests"
python normalizer\normalize_all.py
python scripts\analyze_matrix.py
```

**Expected:** Many more CRITICAL/HIGH findings (privileged mode, latest tag, etc.)

---

## 📋 Test Summary

### Full Test Checklist

- [ ] Docker is running
- [ ] Python is installed
- [ ] In SafeFixK8s directory
- [ ] Loaded `detectors.ps1`
- [ ] Cached Docker images (first time)
- [ ] Ran `Det-RunAll -Path "tests"`
- [ ] Raw files created in `output/raw/`
- [ ] Ran `python normalizer/normalize_all.py`
- [ ] Normalized findings JSON created
- [ ] Detection matrix CSV/JSON created
- [ ] Ran `python scripts/analyze_matrix.py`
- [ ] Thesis CSVs created
- [ ] Opened matrix in Excel
- [ ] Verified finding counts

---

## ⏱️ Time Estimates

| Step | First Time | Subsequent Runs |
|------|------------|-----------------|
| Load scripts | 1 sec | 1 sec |
| Ensure images | 10 min | 5 sec (cached) |
| Run detectors | 60 sec | 45 sec |
| Normalize | 2 sec | 2 sec |
| Analyze | 2 sec | 2 sec |
| **Total** | **~12 min** | **~1 min** |

---

## 🎓 Next Steps for Thesis

Once testing works:

1. **Collect more data:**
   ```powershell
   # Test on multiple repos
   Det-RunAll -Path "path\to\repo1\k8s"
   python normalizer\normalize_all.py
   Copy-Item "output\tool_detection_matrix.csv" "results\repo1.csv"
   
   # Repeat for repo2, repo3, etc.
   ```

2. **Aggregate results:**
   - Combine multiple matrices
   - Calculate average metrics
   - Compare across datasets

3. **Manual validation:**
   - Pick 50 random findings
   - Verify true/false positives
   - Calculate accuracy per tool

4. **Create visualizations:**
   - Tool effectiveness charts
   - Consensus distribution
   - Severity breakdown

5. **Write Chapter 5 (Evaluation):**
   - Use the matrices as evidence
   - Compare tools objectively
   - Show consensus improves confidence

---

**You're ready to test! Start with Step 1 and work through to Step 9. Good luck! 🎉**
