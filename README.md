# SafeFixK8s - Kubernetes Security Scanner

A comprehensive Kubernetes YAML security scanning framework that aggregates findings from multiple industry-standard security tools.

## Overview

SafeFixK8s scans Kubernetes YAML files for security misconfigurations, vulnerabilities, and best practice violations using 8 different security tools:

- **KubeAudit** - Security auditing tool for Kubernetes clusters
- **Kubescape** - ARMO's comprehensive security platform
- **KubeLinter** - Static analysis tool for Kubernetes YAML files
- **Polaris** - Validation of best practices in your Kubernetes clusters
- **Trivy** - Comprehensive security scanner (config scanning)
- **KubeScore** - Static code analysis for Kubernetes object definitions
- **Yamllint** - YAML file linter
- **KubeConform** - Kubernetes resource validation

## Features

- **Multi-tool scanning**: Leverages 8 different security tools for comprehensive coverage
- **Unified output**: Normalizes findings from all tools into a single JSON format
- **Flexible execution**: Supports both local CLI tools and Docker-based scanning
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

1. Clone the repository:
```bash
git clone https://github.com/AHegab/SafeFixK8s.git
cd SafeFixK8s
```

2. Ensure Docker images are available (optional - will auto-pull on first run):
```powershell
.\setup-images.ps1
```

## Usage

### Basic Usage

Navigate to the detection directory and load the functions:

```powershell
cd detection
. .\detectors.ps1
```

### Scan a Directory

Scan all Kubernetes YAML files in a directory:

```powershell
Det-RunLean "..\tests"
```

This will:
1. Scan all YAML files in the `tests` directory
2. Run all 8 security tools
3. Save raw results to `detection/output/raw/`
4. Display timing information for each tool

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
```

### Output Locations

Raw tool outputs are saved to:
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
