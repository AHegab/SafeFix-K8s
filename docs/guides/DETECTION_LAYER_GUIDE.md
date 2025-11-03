# 🔍 SafeFix-K8s Detection Layer - Complete Guide

**Version:** 1.0  
**Date:** November 3, 2025  
**Component:** Multi-Tool Security Detection System  
**Status:** Production-Ready ✅

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Supported Tools](#supported-tools)
4. [Detection Workflow](#detection-workflow)
5. [Tool Configuration](#tool-configuration)
6. [Output Structure](#output-structure)
7. [Usage Guide](#usage-guide)
8. [Performance Metrics](#performance-metrics)
9. [Troubleshooting](#troubleshooting)
10. [Integration](#integration)

---

## 🎯 Overview

### Purpose

The Detection Layer is the **first component** of SafeFix-K8s that scans Kubernetes manifests using 13 specialized security tools to identify vulnerabilities, misconfigurations, and compliance violations.

### Key Features

✅ **Multi-Tool Analysis** - 13 specialized security scanners  
✅ **Parallel Execution** - Concurrent tool execution for speed  
✅ **Raw Output Preservation** - Complete findings saved for analysis  
✅ **Comprehensive Coverage** - Security, compliance, quality, secrets  
✅ **Tool Independence** - Each tool operates independently  
✅ **Zero Data Loss** - All findings captured and stored  

### Design Philosophy

> "**Detect Everything, Normalize Later**"

The Detection Layer follows a **maximalist approach**:
- Run ALL available security tools
- Capture ALL raw output
- Let the Normalizer handle deduplication
- Preserve complete forensic evidence

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     DETECTION LAYER                              │
│                                                                   │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐  │
│  │   Scanner    │      │   Scanner    │      │   Scanner    │  │
│  │   Pool 1     │      │   Pool 2     │      │   Pool 3     │  │
│  ├──────────────┤      ├──────────────┤      ├──────────────┤  │
│  │  • Checkov   │      │  • KubeAudit │      │  • Polaris   │  │
│  │  • Trivy     │      │  • KubeLinter│      │  • KubeScore │  │
│  │  • Kubescape │      │  • Conftest  │      │  • Pluto     │  │
│  │  • Gitleaks  │      │  • KubeConform      │  • RBAC-Police│ │
│  │  • Yamllint  │      │              │      │              │  │
│  └──────────────┘      └──────────────┘      └──────────────┘  │
│         │                      │                      │         │
│         └──────────────────────┼──────────────────────┘         │
│                                ▼                                │
│                    ┌─────────────────────┐                      │
│                    │  Output Collector   │                      │
│                    │  (Raw JSON/TXT)     │                      │
│                    └─────────────────────┘                      │
│                                │                                │
└────────────────────────────────┼────────────────────────────────┘
                                 ▼
                    Detection/output/raw/*.json
```

### Component Breakdown

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Scanner Pool** | Execute security tools in parallel | PowerShell, Go, Python |
| **Output Collector** | Capture raw JSON/TXT output | File I/O |
| **Tool Manager** | Install and update tools | Package managers |
| **Log Aggregator** | Collect execution logs | PowerShell logging |

---

## 🛠️ Supported Tools

### Complete Tool Matrix

| # | Tool | Version | Type | Language | Output Format | Focus Area |
|---|------|---------|------|----------|---------------|------------|
| 1 | **Checkov** | 2.3+ | SAST | Python | JSON | Security policies |
| 2 | **Trivy** | 0.48+ | Vuln Scanner | Go | JSON | Misconfigurations |
| 3 | **KubeAudit** | 0.22+ | Auditor | Go | JSON | Security audit |
| 4 | **KubeLinter** | 0.6+ | Linter | Go | JSON | Best practices |
| 5 | **Polaris** | 8.5+ | Config Validator | Go | JSON | Configuration |
| 6 | **KubeScore** | 1.17+ | Scorer | Go | JSON | Quality scoring |
| 7 | **Kubescape** | 3.0+ | Security Framework | Go | JSON | RBAC, hardening |
| 8 | **Conftest** | 0.49+ | Policy Engine | Go | JSON | OPA policies |
| 9 | **KubeConform** | 0.6+ | Schema Validator | Go | JSON | Schema validation |
| 10 | **RBAC-Police** | 1.0+ | RBAC Analyzer | Go | JSON | RBAC permissions |
| 11 | **Yamllint** | 1.33+ | YAML Linter | Python | TXT | YAML syntax |
| 12 | **Gitleaks** | 8.18+ | Secret Scanner | Go | JSON | Credential detection |
| 13 | **Pluto** | 5.19+ | Deprecation Checker | Go | JSON | API versions |

### Tool Categories

#### 1. Security Scanners (Primary)
- **Checkov**: Policy-as-Code security scanner
  - 400+ built-in policies
  - CIS Kubernetes Benchmark
  - Custom policy support
  
- **Trivy**: Comprehensive vulnerability scanner
  - Misconfiguration detection
  - IaC scanning
  - Fast and accurate

- **KubeAudit**: Kubernetes-native auditor
  - Security best practices
  - PodSecurityPolicy validation
  - Resource-level analysis

#### 2. Compliance & Best Practices
- **KubeLinter**: Lint and enforce best practices
  - 30+ production-ready checks
  - Custom rule support
  - CI/CD integration

- **Polaris**: Configuration validation
  - Workload health checks
  - Security context validation
  - Resource management

- **KubeScore**: Quality scoring
  - Scoring system (0-10)
  - Production readiness
  - Actionable recommendations

#### 3. Specialized Scanners
- **Kubescape**: Security framework scanner
  - NSA/CISA guidelines
  - MITRE ATT&CK framework
  - Multi-framework support

- **Conftest**: Policy enforcement (OPA)
  - Open Policy Agent integration
  - Custom Rego policies
  - Flexible policy management

- **KubeConform**: Schema validation
  - Kubernetes API validation
  - CRD support
  - Fast schema checking

#### 4. RBAC & Permissions
- **RBAC-Police**: RBAC analyzer
  - Permission audit
  - Privilege escalation detection
  - Role binding analysis

#### 5. Code Quality & Secrets
- **Yamllint**: YAML syntax validation
  - Syntax checking
  - Formatting validation
  - Configurable rules

- **Gitleaks**: Secret detection
  - 100+ secret patterns
  - High-entropy detection
  - Custom regex support

- **Pluto**: API deprecation checker
  - Kubernetes version compatibility
  - Deprecated API detection
  - Migration recommendations

---

## 🔄 Detection Workflow

### Step-by-Step Process

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Pre-Scan Validation                             │
│ ───────────────────────────────────────────────────────│
│ • Check if tools are installed                          │
│ • Verify test manifests exist                           │
│ • Create output directories                             │
│ • Clear old results (optional)                          │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: Parallel Tool Execution                         │
│ ───────────────────────────────────────────────────────│
│ Pool 1 (Security)    Pool 2 (Quality)    Pool 3 (Spec) │
│ • Checkov            • KubeLinter        • Conftest     │
│ • Trivy              • KubeScore         • KubeConform  │
│ • KubeAudit          • Polaris           • RBAC-Police  │
│ • Kubescape          • Gitleaks          • Pluto        │
│ • Yamllint           •                   •              │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: Output Collection                               │
│ ───────────────────────────────────────────────────────│
│ • Capture stdout/stderr                                 │
│ • Save to Detection/output/raw/                         │
│ • Preserve exit codes                                   │
│ • Log errors and warnings                               │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│ Step 4: Result Validation                               │
│ ───────────────────────────────────────────────────────│
│ • Verify output files exist                             │
│ • Check JSON validity                                   │
│ • Count findings per tool                               │
│ • Generate summary statistics                           │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│ Step 5: Handoff to Normalizer                           │
│ ───────────────────────────────────────────────────────│
│ • Raw outputs ready: Detection/output/raw/*.json        │
│ • Total findings: ~1,336 raw findings                   │
│ • Next stage: Normalization Layer                       │
└─────────────────────────────────────────────────────────┘
```

### Execution Timeline

```
Time (seconds)
│
0s  ├─ Start detection
    │
1s  ├─ Checkov running ████████████████████ (15s)
    ├─ Trivy running   ██████████ (10s)
    ├─ KubeAudit       ████████ (8s)
    ├─ Kubescape       ████████████ (12s)
    │
5s  ├─ KubeLinter      ██████ (6s)
    ├─ Polaris         ███████ (7s)
    ├─ KubeScore       █████ (5s)
    │
10s ├─ Conftest        ████ (4s)
    ├─ KubeConform     ███ (3s)
    ├─ RBAC-Police     ████ (4s)
    │
15s ├─ Gitleaks        ██████ (6s)
    ├─ Pluto           ███ (3s)
    ├─ Yamllint        ██ (2s)
    │
20s ├─ All tools complete ✓
    │
25s ├─ Output validation ✓
    │
30s └─ Detection complete ✓
```

**Total Time:** ~20-30 seconds for 16 test files

---

## ⚙️ Tool Configuration

### Installation Scripts

#### Windows (PowerShell)
```powershell
# Install all tools
.\Detection\install-tools.ps1

# Individual tool installation
choco install checkov trivy kubeaudit -y
go install github.com/kubescape/kubescape/v3@latest
pip install yamllint gitleaks
```

#### Linux (Bash)
```bash
# Install all tools
./Detection/install-tools.sh

# Individual tool installation
brew install checkov trivy kubeaudit
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
pip3 install yamllint
```

### Configuration Files

#### Checkov Configuration
```yaml
# .checkov.yml
framework:
  - kubernetes
quiet: false
output: json
skip-check:
  - CKV_K8S_43  # Skip specific checks if needed
```

#### Trivy Configuration
```yaml
# trivy.yaml
severity: CRITICAL,HIGH,MEDIUM,LOW
format: json
exit-code: 0  # Don't fail on findings
```

#### Conftest Policies
```rego
# Detection/policies/conftest/*.rego
package main

deny[msg] {
  input.kind == "Pod"
  not input.spec.securityContext
  msg = "Pod must have securityContext"
}
```

### Custom OPA Policies

Located in `Detection/policies/`:

1. **privileged-containers.rego** - Block privileged containers
2. **host-namespaces.rego** - Detect hostNetwork/hostPID
3. **capabilities.rego** - Validate Linux capabilities
4. **resource-limits.rego** - Enforce resource requests/limits
5. **default-namespace.rego** - Prevent default namespace usage

---

## 📤 Output Structure

### Directory Layout

```
Detection/
├── output/
│   ├── raw/                        ← Raw tool outputs
│   │   ├── checkov_raw.json       ← 58 findings
│   │   ├── trivy_config_raw.json  ← 234 findings
│   │   ├── kubeaudit_raw.json     ← 143 findings
│   │   ├── kubelinter_raw.json    ← 98 findings
│   │   ├── polaris_raw.json       ← 187 findings
│   │   ├── kubescore_raw.json     ← 76 findings
│   │   ├── kubescape_raw.json     ← 312 findings
│   │   ├── conftest_raw.json      ← 89 findings
│   │   ├── kubeconform_raw.json   ← 12 findings
│   │   ├── rbacpolice_raw.json    ← 23 findings
│   │   ├── yamllint_raw.txt       ← 45 findings
│   │   ├── gitleaks_raw.json      ← 34 findings
│   │   └── pluto_raw.json         ← 25 findings
│   │
│   └── logs/                       ← Execution logs
│       ├── checkov.log
│       ├── trivy.log
│       └── ...
│
├── policies/                       ← OPA/Conftest policies
│   ├── checkov/
│   ├── conftest/
│   └── gitleaks-rules.toml
│
├── scripts/                        ← Helper scripts
│   └── pluto-scan.ps1
│
└── tools/                          ← Tool binaries (optional)
    └── rbac-police/
```

### Raw Output Formats

#### Checkov Output (JSON)
```json
{
  "results": {
    "failed_checks": [
      {
        "check_id": "CKV_K8S_22",
        "check_name": "Use read-only filesystem for containers",
        "file_path": "/tests/14.genkubesec_privileged_pod.yaml",
        "resource": "Pod.pod-name.spec.containers[0]",
        "check_class": "kubernetes",
        "guideline": "https://docs.bridgecrew.io/..."
      }
    ]
  }
}
```

#### Trivy Output (JSON)
```json
{
  "Results": [
    {
      "Target": "tests/3.nginx_pod_example.yaml",
      "Misconfigurations": [
        {
          "ID": "KSV003",
          "Title": "Default capabilities: some containers do not drop all",
          "Severity": "MEDIUM",
          "Resolution": "Add 'ALL' to securityContext.capabilities.drop"
        }
      ]
    }
  ]
}
```

#### Kubescape Output (JSON)
```json
{
  "results": [
    {
      "resourceID": "path=2640958186/api=/v1//Pod/efs-plugin",
      "controls": [
        {
          "controlID": "C-0057",
          "name": "Privileged container",
          "status": {"status": "failed"},
          "rules": [
            {
              "name": "rule-privilege-escalation",
              "paths": [
                {
                  "fixPath": {
                    "path": "spec.containers[0].securityContext.privileged",
                    "value": ""
                  }
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

#### Polaris Output (JSON)
```json
{
  "Results": [
    {
      "Name": "nginx-deployment",
      "Kind": "Deployment",
      "PodResult": {
        "ContainerResults": [
          {
            "Name": "nginx",
            "Results": {
              "linuxHardening": {
                "ID": "linuxHardening",
                "Message": "Container should set securityContext",
                "Success": false,
                "Severity": "warning"
              }
            }
          }
        ]
      }
    }
  ]
}
```

---

## 📖 Usage Guide

### Basic Usage

#### 1. Run All Detectors
```powershell
# Run all 13 tools on test manifests
.\Detection\detectors.ps1
```

#### 2. Run Specific Tool
```powershell
# Run only Checkov
checkov -d tests/ -o json > Detection/output/raw/checkov_raw.json

# Run only Trivy
trivy config tests/ --format json > Detection/output/raw/trivy_config_raw.json
```

#### 3. Custom Scan Targets
```powershell
# Scan specific directory
.\Detection\detectors.ps1 -Path "path/to/manifests"

# Scan single file
trivy config my-deployment.yaml
```

### Advanced Usage

#### Parallel Execution
```powershell
# Run tools in parallel (faster)
$jobs = @()
$jobs += Start-Job { checkov -d tests/ -o json }
$jobs += Start-Job { trivy config tests/ --format json }
$jobs += Start-Job { kubeaudit all -f tests/ }
$jobs | Wait-Job | Receive-Job
```

#### Custom Policy Scanning
```powershell
# Run Conftest with custom policies
conftest test tests/ `
  --policy Detection/policies/conftest/ `
  --output json > Detection/output/raw/conftest_raw.json
```

#### Filtered Scanning
```powershell
# Scan only specific resource types
kubelinter lint tests/ `
  --include Deployment,Pod,Service `
  --format json
```

---

## 📊 Performance Metrics

### Execution Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| **Total Tools** | 13 | All production-ready |
| **Avg Scan Time** | 25 seconds | For 16 test files |
| **Raw Findings** | 1,336 | Before normalization |
| **Files Scanned** | 16 | K8s + non-K8s |
| **Parallel Pools** | 3 | For faster execution |

### Tool Performance

| Tool | Avg Time | Findings | Coverage |
|------|----------|----------|----------|
| Checkov | 15s | 58 | Security policies |
| Trivy | 10s | 234 | Misconfigurations |
| KubeAudit | 8s | 143 | Security audit |
| KubeLinter | 6s | 98 | Best practices |
| Polaris | 7s | 187 | Configuration |
| KubeScore | 5s | 76 | Quality score |
| Kubescape | 12s | 312 | Security framework |
| Conftest | 4s | 89 | OPA policies |
| KubeConform | 3s | 12 | Schema validation |
| RBAC-Police | 4s | 23 | RBAC analysis |
| Yamllint | 2s | 45 | YAML syntax |
| Gitleaks | 6s | 34 | Secrets |
| Pluto | 3s | 25 | Deprecations |

### Resource Usage

```
CPU Usage:  30-50% (parallel execution)
Memory:     ~500MB peak
Disk I/O:   ~10MB/s read, ~2MB/s write
Network:    0 (offline scanning)
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Tool Not Found
```
Error: 'checkov' is not recognized as an internal or external command
```

**Solution:**
```powershell
# Install missing tool
choco install checkov -y
# Or
pip install checkov
```

#### 2. Permission Denied
```
Error: Access denied to C:\Program Files\...
```

**Solution:**
```powershell
# Run as Administrator
# Or use --user flag for Python tools
pip install --user checkov
```

#### 3. JSON Parse Error
```
Error: Invalid JSON in kubescape_raw.json
```

**Solution:**
```powershell
# Re-run the tool
kubescape scan tests/ --format json --output Detection/output/raw/kubescape_raw.json

# Validate JSON
Get-Content Detection/output/raw/kubescape_raw.json | ConvertFrom-Json
```

#### 4. No Findings Detected
```
Warning: Tool completed but found 0 issues
```

**Solution:**
- Check if test files have actual vulnerabilities
- Verify tool configuration
- Review tool logs in `Detection/output/logs/`

#### 5. Timeout Issues
```
Error: Tool execution exceeded 60 seconds
```

**Solution:**
```powershell
# Increase timeout in detectors.ps1
$timeout = 120  # 2 minutes
```

### Debug Mode

```powershell
# Enable verbose logging
$VerbosePreference = "Continue"
.\Detection\detectors.ps1 -Verbose

# Check tool versions
checkov --version
trivy --version
kubeaudit version
```

---

## 🔗 Integration

### With Normalization Layer

```python
# Normalizer automatically reads from Detection/output/raw/
from normalize import main

# Process all raw outputs
results = main()
# Output: output/llm_payload.json
```

### With CI/CD Pipeline

```yaml
# GitHub Actions
name: Security Scan
on: [push]
jobs:
  detect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Detection
        run: ./Detection/detectors.ps1
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: detection-results
          path: Detection/output/raw/
```

### With GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - detect

security-scan:
  stage: detect
  script:
    - ./Detection/detectors.ps1
  artifacts:
    paths:
      - Detection/output/raw/
    expire_in: 1 week
```

---

## 📚 Additional Resources

### Documentation
- [Checkov Docs](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [Trivy Docs](https://aquasecurity.github.io/trivy/)
- [Kubescape Docs](https://kubescape.io/docs/)
- [Conftest Docs](https://www.conftest.dev/)

### Tool Repositories
- [Checkov GitHub](https://github.com/bridgecrewio/checkov)
- [Trivy GitHub](https://github.com/aquasecurity/trivy)
- [KubeAudit GitHub](https://github.com/Shopify/kubeaudit)
- [KubeLinter GitHub](https://github.com/stackrox/kube-linter)

### Community
- [CNCF Security TAG](https://github.com/cncf/tag-security)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)

---

## 📝 Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-03 | Initial production release |
| 0.9 | 2025-10-27 | Added 13th tool (Pluto) |
| 0.8 | 2025-10-15 | Parallel execution support |
| 0.7 | 2025-10-01 | Custom OPA policies |

---

## 🎯 Summary

### Detection Layer Capabilities

✅ **13 Security Tools** - Comprehensive coverage  
✅ **1,336 Raw Findings** - Complete detection  
✅ **25-Second Scan** - Fast execution  
✅ **100% Automation** - Zero manual intervention  
✅ **Production-Ready** - Tested and validated  

### Next Steps

After Detection completes:
1. ✅ Raw outputs saved to `Detection/output/raw/`
2. ➡️ **Next Stage:** [Normalization Layer](../Normalizer/NORMALIZATION_LAYER_GUIDE.md)
3. ➡️ Normalizer processes 1,336 → 131 findings
4. ➡️ LLM generates patches

---

**Status:** ✅ Detection Layer Ready for Production

**Last Updated:** November 3, 2025  
**Maintainer:** SafeFix-K8s Team  
**License:** MIT
