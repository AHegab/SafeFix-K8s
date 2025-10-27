# How to Use SafeFixK8s - Detailed Guide

This guide provides step-by-step instructions for using SafeFixK8s to scan Kubernetes YAML files for security issues.

## Table of Contents
1. [Quick Start](#quick-start)
2. [Detailed Usage](#detailed-usage)
3. [Understanding Results](#understanding-results)
4. [Advanced Usage](#advanced-usage)
5. [Common Scenarios](#common-scenarios)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Initial Setup (One-time)

```powershell
# Open PowerShell and navigate to the SafeFixK8s directory
cd "C:\path\to\SafeFixK8s"

# Optional: Pull Docker images (will auto-pull if needed)
.\setup-images.ps1
```

### 2. Run Your First Scan

```powershell
# Navigate to detection directory
cd detection

# Load the detector functions
. .\detectors.ps1

# Scan the test files
Det-RunLean "..\tests"
```

That's it! Results will be saved in `detection/output/raw/`.

---

## Detailed Usage

### Loading the Detectors

Before running any scans, you must load the detector functions into your PowerShell session:

```powershell
cd detection
. .\detectors.ps1
```

**Note**: The dot (`.`) before the script name is required - this "sources" the script, loading all functions into your current session.

### Running All Scanners

The `Det-RunLean` function runs all 8 security tools sequentially:

```powershell
Det-RunLean "<path-to-yaml-files>"
```

**Examples:**
```powershell
# Scan files in tests directory (relative path)
Det-RunLean "..\tests"

# Scan files in current directory
Det-RunLean "."

# Scan files using absolute path
Det-RunLean "C:\Users\YourName\k8s-manifests"
```

**What happens:**
1. Verifies/pulls required Docker images
2. Resolves the scan path
3. Runs each tool sequentially
4. Saves raw results to `output/raw/`
5. Displays timing summary

**Example Output:**
```
Scanning: C:\...\SafeFixK8s\tests

[kubeconform] -> C:\...\kubeconform_raw.json
[kube-linter] -> C:\...\kubelinter_raw.json
[polaris] -> C:\...\polaris_raw.json
[trivy config] -> C:\...\trivy_config_raw.json
[kubescape] -> C:\...\kubescape_raw.json
[kube-score] -> C:\...\kubescore_raw.json
[yamllint] -> C:\...\yamllint_raw.txt
[kubeaudit] -> C:\...\kubeaudit_raw.json

────────── Runtime summary ──────────
Tool          Seconds Status
----          ------- ------
Kubescape       10.23 ok
Trivy            8.45 ok
Polaris          7.12 ok
KubeScore        5.67 ok
KubeLinter       4.89 ok
KubeAudit        3.21 ok
KubeConform      2.45 ok
Yamllint         1.98 ok
```

### Running Individual Tools

You can run specific tools instead of all at once:

#### Kubescape
```powershell
Det-Kubescape "..\tests"
```
- Scans entire directory
- Provides compliance score
- Shows high-stakes workloads
- Output: `kubescape_raw.json`

#### KubeAudit
```powershell
Det-KubeAudit "..\tests"
```
- Scans each YAML file individually
- Shows per-file findings
- Suppresses deprecation warnings
- Output: `kubeaudit_raw.json`

#### KubeLinter
```powershell
Det-KubeLinter "..\tests"
```
- Fast static analysis
- Built-in checks
- Output: `kubelinter_raw.json`

#### Polaris
```powershell
Det-Polaris "..\tests"
```
- Policy-based validation
- Security and reliability checks
- Output: `polaris_raw.json`

#### Trivy Config Scanner
```powershell
Det-TrivyConfig "..\tests"
```
- Misconfiguration detection
- Vulnerability scanning
- Output: `trivy_config_raw.json`

#### KubeScore
```powershell
Det-KubeScore "..\tests"
```
- Best practice scoring
- Per-resource analysis
- Output: `kubescore_raw.json`

#### Yamllint
```powershell
Det-Yamllint "..\tests"
```
- YAML syntax validation
- Style checking
- Output: `yamllint_raw.txt`

#### KubeConform
```powershell
Det-KubeConform "..\tests"
```
- Schema validation
- API version checking
- Output: `kubeconform_raw.json`

---

## Understanding Results

### Raw Output Files

After scanning, raw results are in `detection/output/raw/`:

```
output/raw/
├── kubeaudit_raw.json      # KubeAudit findings
├── kubescape_raw.json      # Kubescape findings  
├── kubelinter_raw.json     # KubeLinter findings
├── polaris_raw.json        # Polaris findings
├── trivy_config_raw.json   # Trivy findings
├── kubescore_raw.json      # KubeScore findings
├── kubeconform_raw.json    # KubeConform findings
└── yamllint_raw.txt        # Yamllint findings
```

### Viewing Results

**View JSON files:**
```powershell
# Pretty-print JSON
Get-Content .\output\raw\kubescape_raw.json | ConvertFrom-Json | ConvertTo-Json -Depth 10

# View in VS Code
code .\output\raw\kubescape_raw.json
```

**View text files:**
```powershell
Get-Content .\output\raw\yamllint_raw.txt
```

### Result Structure

Each tool has its own output format:

**Example - KubeAudit finding:**
```json
{
  "AuditResultName": "AppArmorAnnotationMissing",
  "ResourceName": "nginx",
  "ResourceKind": "Pod",
  "Container": "nginx-container",
  "msg": "AppArmor annotation missing",
  "file": "C:\\...\\nginx_pod.yaml"
}
```

**Example - Kubescape summary:**
```json
{
  "summaryDetails": {
    "complianceScore": 71,
    "controls": {...},
    "resources": {...}
  }
}
```

---

## Advanced Usage

### Custom Output Paths

Specify custom output location:

```powershell
Det-Kubescape -Path "..\tests" -Out "C:\custom\output\kubescape.json"
```

### Scanning Specific Files

Use PowerShell filtering to scan specific files:

```powershell
# Scan only deployment files
$deployments = Get-ChildItem "..\tests" -Filter "*deployment*.yaml"
foreach ($f in $deployments) {
    Det-KubeAudit $f.Directory.FullName
}
```

### Integration with CI/CD

**Example GitHub Actions workflow:**

```yaml
name: K8s Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run SafeFixK8s
        shell: powershell
        run: |
          cd detection
          . .\detectors.ps1
          Det-RunLean "..\manifests"
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: scan-results
          path: detection/output/raw/
```

### Automation Script

Create a script for regular scanning:

```powershell
# scan-nightly.ps1
param(
    [string]$TargetDir = "..\k8s-manifests",
    [string]$ReportDir = "C:\scan-reports\$(Get-Date -Format 'yyyy-MM-dd')"
)

# Setup
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
cd detection
. .\detectors.ps1

# Run scan
Write-Host "Starting scan of $TargetDir..." -ForegroundColor Cyan
Det-RunLean $TargetDir

# Copy results
Copy-Item .\output\raw\* $ReportDir -Force

Write-Host "Results saved to: $ReportDir" -ForegroundColor Green
```

---

## Common Scenarios

### Scenario 1: Scan Development Manifests

```powershell
cd detection
. .\detectors.ps1

# Scan your dev environment manifests
Det-RunLean "C:\projects\myapp\k8s\dev"

# Review findings
code .\output\raw\kubescape_raw.json
```

### Scenario 2: Quick Security Check Before Deployment

```powershell
cd detection
. .\detectors.ps1

# Run fast tools only
Det-KubeLinter "C:\projects\myapp\k8s\prod"
Det-KubeConform "C:\projects\myapp\k8s\prod"

# Check for critical issues
Get-Content .\output\raw\kubelinter_raw.json | ConvertFrom-Json | 
    Where-Object { $_.level -eq "error" }
```

### Scenario 3: Compliance Audit

```powershell
cd detection
. .\detectors.ps1

# Full scan with all tools
Det-RunLean "C:\k8s-production-manifests"

# Generate report timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$reportDir = "C:\compliance-reports\$timestamp"

# Archive results
New-Item -ItemType Directory -Force -Path $reportDir
Copy-Item .\output\raw\* $reportDir

Write-Host "Compliance scan completed. Results in: $reportDir"
```

### Scenario 4: Compare Before/After Changes

```powershell
cd detection
. .\detectors.ps1

# Scan before changes
Det-Kubescape "..\manifests"
Copy-Item .\output\raw\kubescape_raw.json kubescape_before.json

# Make your changes to manifests...

# Scan after changes
Det-Kubescape "..\manifests"
Copy-Item .\output\raw\kubescape_raw.json kubescape_after.json

# Compare
Compare-Object (Get-Content kubescape_before.json) (Get-Content kubescape_after.json)
```

---

## Troubleshooting

### Issue: "Det-RunLean command not found"

**Solution:** You need to load the detectors first:
```powershell
. .\detectors.ps1
```

### Issue: Docker not running

**Error:** `Cannot connect to the Docker daemon`

**Solution:** Start Docker Desktop and wait for it to be ready:
```powershell
# Check Docker status
docker ps
```

### Issue: "Path does not exist"

**Solution:** Use correct relative or absolute paths:
```powershell
# From detection directory, use relative path
Det-RunLean "..\tests"

# Or use absolute path
Det-RunLean "C:\full\path\to\tests"
```

### Issue: No findings in output

**Possible causes:**
1. No YAML files in target directory
2. YAML files don't contain Kubernetes resources
3. Resources are fully compliant (rare!)

**Solution:** Verify your files:
```powershell
# Check for YAML files
Get-ChildItem "..\tests" -Recurse -Include *.yaml,*.yml

# Verify Kubernetes resources
Get-Content "..\tests\some-file.yaml"
```

### Issue: Tool produces placeholder output

**Example:** `[{"tool":"kubescape","note":"failed: ..."}]`

**Solutions:**
1. Check if tool CLI is installed (for local execution)
2. Ensure Docker image is available
3. Verify target directory is accessible
4. Check file permissions

```powershell
# Test Docker connectivity
docker run --rm hello-world

# Test tool availability
Get-Command kubescape
Get-Command kubeaudit
```

### Issue: Slow scanning

**Solutions:**
1. Install tools locally (faster than Docker)
2. Scan smaller directories
3. Run individual tools instead of `Det-RunLean`
4. Use SSD storage for Docker

### Getting Help

For issues not covered here:
1. Check tool-specific logs in `detection/output/logs/`
2. Review raw output files in `detection/output/raw/`
3. Run tools individually to isolate issues
4. Check tool documentation:
   - [Kubescape Docs](https://kubescape.io/docs/)
   - [KubeAudit Docs](https://github.com/Shopify/kubeaudit)
   - [KubeLinter Docs](https://docs.kubelinter.io/)

---

## Next Steps

After scanning:

1. **Review findings** in `detection/output/raw/`
2. **Normalize results** using the normalizer:
   ```powershell
   cd ..\normalizer
   python normalize_all.py
   ```
3. **Analyze normalized output** in `output/normalized_findings.json`
4. **Remediate issues** in your Kubernetes manifests
5. **Re-scan** to verify fixes

---

## Tips & Best Practices

1. **Regular Scanning**: Integrate into your development workflow
2. **Version Control**: Track changes in findings over time
3. **Prioritize**: Focus on critical/high severity issues first
4. **Tool Updates**: Keep Docker images updated with `docker pull`
5. **Documentation**: Document exceptions and accepted risks
6. **Automation**: Use scheduled tasks for regular scanning
7. **Multiple Environments**: Scan dev, staging, and prod separately

---

## Support

For questions or issues:
- Create an issue on GitHub
- Contact: Ahmed Hegab (@AHegab)
- Review tool-specific documentation

---

**Last Updated:** October 2025
