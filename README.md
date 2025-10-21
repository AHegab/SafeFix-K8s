# SafeFixK8s - Kubernetes Security Scanner

A comprehensive Kubernetes YAML security scanning framework that aggregates findings from multiple industry-standard security tools.

## Overview

SafeFixK8s scans Kubernetes YAML files for security misconfigurations, vulnerabilities, and best practice violations using **11 security tools** (8 core + 3 extended):

### Core Tools (8)
- **KubeAudit** - Security auditing tool for Kubernetes clusters
- **Kubescape** - ARMO's comprehensive security platform
- **KubeLinter** - Static analysis tool for Kubernetes YAML files
- **Polaris** - Validation of best practices in your Kubernetes clusters
- **Trivy** - Comprehensive security scanner (config scanning)
- **KubeScore** - Static code analysis for Kubernetes object definitions
- **Yamllint** - YAML file linter
- **KubeConform** - Kubernetes resource validation

### Extended Tools (3) - NEW!
- **kube-bench** - CIS Kubernetes Benchmark compliance checker
- **rbac-police** - RBAC and permissions analysis tool
- **pluto** - Deprecated Kubernetes API version detector

## Features

- **Multi-tool scanning**: Leverages 11 different security tools for comprehensive coverage
- **Extended coverage**: Includes CIS benchmarks, RBAC analysis, and API deprecation detection
- **Unified output**: Normalizes findings from all tools into a single JSON format
- **Flexible execution**: Supports both local CLI tools and Docker-based scanning
- **Two scan modes**: 
  - `Det-RunLean`: Fast scan with 8 core tools
  - `Det-RunExtended`: Comprehensive scan with all 11 tools
- **Detailed reporting**: Includes timing information and tool-specific results
- **Error handling**: Graceful handling of tool failures with placeholder outputs

## Prerequisites

### Required
- **PowerShell** 5.1 or later (Windows) or PowerShell Core (cross-platform)
- **Docker** Desktop (for Docker-based tool execution)

### Optional (for faster local execution)
You can install tools locally instead of using Docker:
- [Kubescape](https://github.com/kubescape/kubescape/releases)
- [KubeAudit](https://github.com/Shopify/kubeaudit/releases)

Other tools will automatically use Docker containers if not installed locally.

## Installation

### Basic Installation

1. Clone the repository:
```bash
git clone https://github.com/AHegab/SafeFixK8s.git
cd SafeFixK8s
```

2. Ensure Docker images are available (optional - will auto-pull on first run):
```powershell
.\setup-images.ps1
```

### Installing Extended Tools (Optional)

#### kube-bench (CIS Kubernetes Benchmark Compliance)

**Windows (Automated):**
```powershell
# Run as Administrator
.\install-kube-bench.ps1
```

**Linux/macOS (Automated):**
```bash
# Run with sudo or as root
sudo ./install-kube-bench.sh
```

**Manual Installation:**
- Download from: https://github.com/aquasecurity/kube-bench/releases/tag/v0.13.0
- Extract and add to PATH
- Verify: `kube-bench version`

**Note:** kube-bench is designed to run **on Kubernetes cluster nodes** (master/worker), not for static YAML analysis. It performs CIS benchmark compliance checks on running cluster components.

#### pluto (Deprecated API Detection)

**Windows (Chocolatey):**
```powershell
choco install pluto
```

**macOS/Linux (Homebrew):**
```bash
brew install FairwindsOps/tap/pluto
```

**Manual Installation:**
- Download from: https://github.com/FairwindsOps/pluto/releases
- Extract and add to PATH
- Verify: `pluto version`

#### rbac-police (RBAC Analysis)

The framework includes a built-in PowerShell-based RBAC analyzer. For advanced cluster-based RBAC analysis:

**kubectl plugin:**
```bash
# Using krew
kubectl krew install rbac-police

# Or download from
# https://github.com/FairwindsOps/rbac-police/releases
```

**Note:** The built-in implementation works with RBAC manifest files and requires no additional installation.

## Usage

### Basic Usage

Navigate to the detection directory and load the functions:

```powershell
cd detection
. .\detectors.ps1
```

### Scan a Directory

**Option 1: Fast Scan (8 core tools)**
```powershell
Det-RunLean "..\tests"
```

**Option 2: Extended Scan (11 tools including CIS, RBAC, API deprecation)**
```powershell
Det-RunExtended "..\tests"
```

This will:
1. Scan all YAML files in the `tests` directory
2. Run selected security tools (8 or 11)
3. Save raw results to `detection/output/raw/`
4. Display timing information for each tool

**Recommendation:** Use `Det-RunLean` for regular scans. Use `Det-RunExtended` when you need:
- CIS benchmark compliance checks
- Deep RBAC permissions analysis
- Kubernetes API deprecation detection

### Run Individual Tools

You can also run tools individually:

```powershell
# Scan with Kubescape
Det-Kubescape "..\tests"

# Scan with KubeAudit
Det-KubeAudit "..\tests"

# Scan with KubeLinter
Det-KubeLinter "..\tests"

# Scan with Polaris
Det-Polaris "..\tests"

# Scan with Trivy
Det-TrivyConfig "..\tests"

# Scan with KubeScore
Det-KubeScore "..\tests"

# Scan with Yamllint
Det-Yamllint "..\tests"

# Scan with KubeConform
Det-KubeConform "..\tests"

# NEW: Extended tools
Det-KubeBench "..\tests"      # CIS Benchmarks
Det-RBACPolice "..\tests"     # RBAC Analysis
Det-Pluto "..\tests"          # API Deprecation
```

### Output Locations

Raw tool outputs are saved to:

**Core Tools:**
```
detection/output/raw/
├── kubeaudit_raw.json
├── kubescape_raw.json
├── kubelinter_raw.json
├── polaris_raw.json
├── trivy_config_raw.json
├── kubescore_raw.json
├── kubeconform_raw.json
└── yamllint_raw.txt
```

**Extended Tools (when using Det-RunExtended):**
```
detection/output/raw/
├── ... (core tools above)
├── kube-bench_raw.json       # CIS Benchmark results
├── rbacpolice_raw.json       # RBAC analysis results
└── pluto_raw.json            # Deprecated API results
```

## Directory Structure

```
SafeFixK8s/
├── detection/
│   ├── detectors.ps1           # Main detection functions
│   ├── test-detectors.ps1      # Test runner script
│   ├── output/
│   │   ├── raw/                # Raw tool outputs
│   │   └── logs/               # Execution logs
│   ├── images/                 # Docker images cache
│   └── tools/                  # Tool-specific configurations
├── normalizer/
│   └── normalize_all.py        # Result normalization script
├── output/
│   └── normalized_findings.json # Normalized scan results
├── tests/                      # Sample Kubernetes YAML files
└── README.md                   # This file
```

## Normalization

After scanning, normalize the findings into a unified format:

```powershell
cd ..\normalizer
python normalize_all.py
```

This creates `output/normalized_findings.json` with standardized findings from all tools.

## Example Workflow

Complete workflow for scanning and normalizing results:

```powershell
# 1. Navigate to detection directory
cd detection

# 2. Load detector functions
. .\detectors.ps1

# 3. Run all scanners on test files
Det-RunLean "..\tests"

# 4. Normalize the results
cd ..\normalizer
python normalize_all.py

# 5. View normalized results
cat ..\output\normalized_findings.json
```

## Tool-Specific Notes

### Kubescape
- Requires directory path (not individual files)
- Outputs JSON with format version v2
- Shows detailed security posture overview
- Calculates compliance score (0-100)

### KubeAudit
- Processes individual YAML files
- Suppresses deprecation warnings automatically
- Outputs JSON format per file
- Findings include file path metadata

### KubeLinter
- Scans entire directories
- JSON output format
- Fast static analysis
- Built-in best practice checks

### Polaris
- Comprehensive policy engine
- JSON output format
- Checks security and reliability

### Trivy
- Config scanning mode
- JSON output format
- Detects misconfigurations and vulnerabilities

### KubeScore
- Analyzes individual YAML files
- JSON output format
- Scores based on best practices

### Yamllint
- YAML syntax and style checking
- Text output format (parsable)
- Configurable rules

### KubeConform
- Validates Kubernetes resources against schemas
- JSON output format
- Strict validation mode

### kube-bench (Extended Tool)
- **Purpose**: CIS Kubernetes Benchmark compliance checking
- **Requirement**: Must run on actual Kubernetes cluster nodes
- **Output**: JSON format with CIS benchmark test results
- **Limitation**: Does not analyze YAML manifests - requires runtime access to cluster components

**Usage on cluster nodes:**
```bash
# On master node
sudo kube-bench run --targets master --json

# On worker node
sudo kube-bench run --targets node --json

# Full cluster scan (run on appropriate nodes)
sudo kube-bench run --targets master,node,etcd,policies --json
```

**Check version:**
```bash
kube-bench version
```

**Available test targets:**
- `master` - Control plane components (API server, scheduler, controller-manager)
- `node` - Worker node components (kubelet, proxy)
- `etcd` - Etcd data store
- `policies` - Security policies and RBAC

**Configuration location:**
- Windows: `C:\Program Files\kube-bench\cfg\`
- Linux: `/etc/kube-bench/` or `/opt/kube-bench/cfg/`

### rbac-police (Extended Tool)
- **Purpose**: RBAC permissions analysis
- **Implementation**: Built-in PowerShell analyzer for manifests
- **Output**: JSON format with permission findings
- **Detects**: Wildcard permissions, overly permissive roles

**What it checks:**
- Wildcard verbs (`verbs: ["*"]`)
- Wildcard resources (`resources: ["*"]`)
- Wildcard API groups (`apiGroups: ["*"]`)

### pluto (Extended Tool)
- **Purpose**: Deprecated Kubernetes API detection
- **Requirement**: Local CLI installation
- **Output**: JSON format with deprecated API findings
- **Works with**: Any Kubernetes manifest files (offline analysis)

**Usage:**
```bash
# Scan directory for deprecated APIs
pluto detect-files -d ./manifests --output json

# Scan for specific Kubernetes version
pluto detect-files -d ./manifests --target-versions k8s=v1.29.0 --output json
```

**Helpful for:**
- Planning Kubernetes version upgrades
- Identifying APIs removed in newer versions
- Ensuring manifest compatibility

## Troubleshooting

### Docker Issues
If you encounter Docker errors, ensure Docker Desktop is running:
```powershell
docker ps
```

### Missing Tools
If a local tool is not found, the script will automatically fall back to Docker.

### Path Issues
Use relative paths from your current directory or provide absolute paths:
```powershell
# Relative path
Det-RunLean "..\tests"

# Absolute path
Det-RunLean "C:\path\to\yaml\files"
```

### Empty Results
If a tool produces no findings:
- Check that YAML files exist in the target directory
- Verify YAML files contain valid Kubernetes resources
- Review tool-specific output in `detection/output/raw/`

## Performance

Typical scan times for 15 test files (on modern hardware):
- KubeAudit: ~2-5 seconds
- Kubescape: ~8-12 seconds
- KubeLinter: ~3-5 seconds
- Polaris: ~5-8 seconds
- Trivy: ~6-10 seconds
- KubeScore: ~4-6 seconds
- Yamllint: ~2-3 seconds
- KubeConform: ~2-4 seconds

**Total scan time**: ~30-60 seconds for all tools

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is part of a BSc Thesis at GIU (German International University of Applied Sciences).

## Author

Ahmed Hegab (@AHegab)

## Acknowledgments

- Kubescape by ARMO
- KubeAudit by Shopify
- KubeLinter by StackRox
- Polaris by Fairwinds
- Trivy by Aqua Security
- KubeScore by Zegl
- Yamllint by Adrienverge
- KubeConform by Yannh
