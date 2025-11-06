# 📁 SafeFix-K8s Repository Structure

**Version:** 2.0 (Reorganized)  
**Date:** November 3, 2025  
**Status:** Production-Ready ✅

---

## 📋 Overview

This document describes the clean, organized structure of the SafeFix-K8s repository designed for easy navigation and maintenance.

---

## 🗂️ Directory Structure

```
SafeFixK8s/
│
├── 📚 docs/                          # All documentation
│   ├── README.md                     # Main project documentation
│   ├── ARCHITECTURE.md               # System architecture overview
│   ├── HOW_TO_USE.md                 # User guide
│   ├── COMMANDS.md                   # CLI reference
│   └── guides/                       # Layer-specific guides
│       ├── DETECTION_LAYER_GUIDE.md
│       ├── NORMALIZATION_LAYER_GUIDE.md
│       └── VALIDATION_ANALYSIS.md
│
├── 🔍 Detection/                     # Layer 1: Multi-Tool Detection
│   ├── README.md                     # Detection layer overview
│   ├── detectors.ps1                 # Main detection script
│   ├── scripts/                      # Helper scripts
│   │   ├── install-tools.ps1
│   │   ├── run_detection.ps1
│   │   ├── test-detectors.ps1
│   │   └── pluto-scan.ps1
│   ├── policies/                     # Security policies
│   │   ├── checkov/                  # Custom Checkov checks
│   │   ├── conftest/                 # OPA/Rego policies
│   │   └── gitleaks-rules.toml       # Gitleaks configuration
│   ├── output/                       # Detection outputs
│   │   ├── raw/                      # Raw tool outputs (*.json)
│   │   └── logs/                     # Execution logs
│   ├── tools/                        # Tool binaries (optional)
│   └── vendor/                       # Third-party tools
│       └── rbac-police/
│
├── 🔄 Normalizer/                    # Layer 2: Finding Normalization
│   ├── README.md                     # Normalizer overview
│   ├── normalize.py                  # Main normalization script
│   ├── validate_output.py            # Output validation
│   └── configs/                      # Normalizer configurations
│
├── 🤖 LLMs/                          # Layer 3: AI-Powered Patching
│   ├── README.md                     # LLM orchestrator overview
│   └── multi_llm_orchestrator.py     # Multi-LLM patch generator
│
├── ✅ Validations/                   # Layer 4: Validation & Verification
│   ├── README.md                     # Validation overview
│   ├── validate-gates.ps1            # Validation gates script
│   ├── safe_fix_proof.json           # Validation results
│   ├── tools/                        # Validation utilities
│   │   ├── generate_coverage_excel.py
│   │   ├── generate_coverage_csv.py
│   │   └── coverage_data.py
│   ├── policies/                     # Validation policies
│   ├── reports/                      # Validation reports
│   └── evidence/                     # Validation evidence
│       └── patch_sandbox_*/          # Patch validation results
│
├── 🧪 tests/                         # Test manifests
│   ├── 3.nginx_pod_example.yaml
│   ├── 13.jenkins_agent_pod.yaml
│   ├── 14.genkubesec_privileged_pod.yaml
│   ├── 15.pod_privilege_escalation.yaml
│   ├── 16.busybox_pod_missing_memory.yaml
│   ├── 20.wordpress_mariadb_compose.yaml
│   ├── 28.role_overly_permissive.yaml
│   ├── 29.helm_rabbitmq_hardcoded_credentials.yaml
│   └── ...
│
├── 📊 output/                        # Pipeline outputs
│   ├── normalized_findings.json      # Normalized findings
│   ├── llm_payload.json              # LLM-ready payload
│   ├── llm_decisions.json            # LLM patch decisions
│   ├── Coverage_Matrix_Updated.csv   # Coverage analysis
│   └── patch_sandbox/                # Generated patches
│       ├── 1/
│       ├── 2/
│       └── ...
│
├── 🔧 scripts/                       # Utility scripts
│   ├── clean-outputs.ps1             # Clean output directories
│   ├── cli.py                        # CLI interface
│   └── utils/                        # Helper utilities
│       ├── analyze_conftest.py
│       ├── check_conftest_mapping.py
│       ├── check_privileged.py
│       ├── gap_analysis.py
│       └── debug_conftest_parser.py
│
├── ⚙️ configs/                       # Global configurations
│   ├── .checkov.yaml                 # Checkov configuration
│   ├── .kube-linter.yaml             # KubeLinter configuration
│   ├── .env                          # Environment variables
│   └── .gitignore                    # Git ignore rules
│
├── 🐳 .kube/                         # Kubernetes configs (optional)
│
├── 📦 .venv/                         # Python virtual environment
│
├── 📄 README.md                      # Main README
├── 📜 LICENSE                        # License file
└── 📋 CHANGELOG.md                   # Version history

```

---

## 🎯 Layer Organization

### Layer 1: Detection
**Location:** `Detection/`  
**Purpose:** Multi-tool security scanning  
**Entry Point:** `Detection/detectors.ps1`  
**Outputs:** `Detection/output/raw/*.json`

### Layer 2: Normalization
**Location:** `Normalizer/`  
**Purpose:** Finding aggregation & deduplication  
**Entry Point:** `Normalizer/normalize.py`  
**Outputs:** `output/normalized_findings.json`

### Layer 3: LLM Orchestration
**Location:** `LLMs/`  
**Purpose:** AI-powered patch generation  
**Entry Point:** `LLMs/multi_llm_orchestrator.py`  
**Outputs:** `output/llm_decisions.json`, `output/patch_sandbox/`

### Layer 4: Validation
**Location:** `Validations/`  
**Purpose:** Patch verification & quality gates  
**Entry Point:** `Validations/validate-gates.ps1`  
**Outputs:** `Validations/reports/`, `Validations/evidence/`

---

## 📚 Documentation Organization

### Main Documentation
- **README.md** - Project overview, quick start
- **docs/ARCHITECTURE.md** - System design, data flow
- **docs/HOW_TO_USE.md** - User guide, examples
- **docs/COMMANDS.md** - CLI reference

### Layer Guides
- **docs/guides/DETECTION_LAYER_GUIDE.md** - Complete detection documentation
- **docs/guides/NORMALIZATION_LAYER_GUIDE.md** - Normalization deep-dive
- **docs/guides/VALIDATION_ANALYSIS.md** - Validation results

### Component README Files
- **Detection/README.md** - Detection layer specifics
- **Normalizer/README.md** - Normalizer specifics
- **LLMs/README.md** - LLM orchestrator specifics
- **Validations/README.md** - Validation specifics

---

## 🔧 Scripts Organization

### Detection Scripts
Location: `Detection/scripts/`
- `install-tools.ps1` - Install security tools
- `run_detection.ps1` - Run detection layer
- `test-detectors.ps1` - Test tool installation
- `pluto-scan.ps1` - API deprecation scanning

### Utility Scripts
Location: `scripts/utils/`
- `analyze_conftest.py` - Analyze Conftest output
- `check_conftest_mapping.py` - Verify rule mappings
- `check_privileged.py` - Check privileged containers
- `gap_analysis.py` - Gap analysis tool
- `debug_conftest_parser.py` - Debug parser issues

### Maintenance Scripts
Location: `scripts/`
- `clean-outputs.ps1` - Clean output directories
- `cli.py` - CLI interface

---

## 📊 Output Organization

### Detection Outputs
**Location:** `Detection/output/`
- `raw/*.json` - Raw tool outputs (13 files)
- `logs/*.log` - Execution logs

### Normalized Outputs
**Location:** `output/`
- `normalized_findings.json` - All normalized findings
- `llm_payload.json` - LLM-ready subset
- `llm_decisions.json` - LLM patch decisions
- `Coverage_Matrix_Updated.csv` - Coverage analysis

### Patch Outputs
**Location:** `output/patch_sandbox/`
- `1/` - Patch attempt 1
- `2/` - Patch attempt 2
- etc.

### Validation Outputs
**Location:** `Validations/`
- `reports/*.md` - Validation reports
- `evidence/patch_sandbox_*_tests_*/` - Validation evidence
- `safe_fix_proof.json` - Validation proof

---

## 🧪 Test Files Organization

**Location:** `tests/`

### Naming Convention
`<number>.<description>.yaml`

Examples:
- `3.nginx_pod_example.yaml` - Basic nginx pod
- `14.genkubesec_privileged_pod.yaml` - Privileged container test
- `28.role_overly_permissive.yaml` - RBAC test

### Categories
- **Security Tests** - Privileged, capabilities, host access
- **Quality Tests** - Resource limits, probes, labels
- **Compliance Tests** - API versions, namespaces
- **Special Cases** - Non-K8s files (Docker Compose, Helm)

---

## ⚙️ Configuration Files

### Root Level
- `.gitignore` - Git ignore patterns
- `.env` - Environment variables (API keys)

### Tool Configurations
**Location:** `configs/`
- `.checkov.yaml` - Checkov settings
- `.kube-linter.yaml` - KubeLinter settings

### Policy Configurations
**Location:** `Detection/policies/`
- `checkov/*.py` - Custom Checkov policies
- `conftest/*.rego` - OPA policies
- `gitleaks-rules.toml` - Secret detection rules

---

## 🚀 Quick Navigation

### Running the Pipeline
```bash
# Step 1: Detection
cd Detection
.\detectors.ps1

# Step 2: Normalization
cd ..\Normalizer
python normalize.py

# Step 3: LLM Patching
cd ..\LLMs
python multi_llm_orchestrator.py

# Step 4: Validation
cd ..\Validations
.\validate-gates.ps1
```

### Viewing Results
```bash
# Raw detection output
ls Detection\output\raw\

# Normalized findings
cat output\normalized_findings.json

# LLM patches
ls output\patch_sandbox\

# Validation reports
ls Validations\reports\
```

### Documentation
```bash
# Main README
cat README.md

# Layer guides
cat docs\guides\DETECTION_LAYER_GUIDE.md
cat docs\guides\NORMALIZATION_LAYER_GUIDE.md

# How to use
cat docs\HOW_TO_USE.md
```

---

## 📏 Best Practices

### File Organization
1. ✅ Keep layer-specific files in layer directories
2. ✅ Put shared utilities in `scripts/utils/`
3. ✅ Store all docs in `docs/` or component `README.md`
4. ✅ Use descriptive names for test files
5. ✅ Keep outputs separate from source code

### Documentation
1. ✅ Main `README.md` for high-level overview
2. ✅ Layer `README.md` for component specifics
3. ✅ Detailed guides in `docs/guides/`
4. ✅ Inline comments for complex logic
5. ✅ Keep docs up-to-date with code

### Scripts
1. ✅ Use PowerShell for Windows automation
2. ✅ Use Python for cross-platform tools
3. ✅ Keep scripts focused (single responsibility)
4. ✅ Add help/usage messages
5. ✅ Log important operations

---

## 🔄 Migration Notes

### Files Reorganized
- ❌ Root-level Python scripts → ✅ `scripts/utils/`
- ❌ Root-level docs → ✅ `docs/`
- ❌ Mixed layer guides → ✅ `docs/guides/`
- ❌ Scattered configs → ✅ `configs/`

### Files Kept in Root
- ✅ `README.md` - Main entry point
- ✅ `.gitignore` - Git configuration
- ✅ `.venv/` - Python environment

### Files by Layer
- ✅ `Detection/` - All detection scripts, policies, outputs
- ✅ `Normalizer/` - Normalization logic
- ✅ `LLMs/` - LLM orchestration
- ✅ `Validations/` - Validation tools
- ✅ `tests/` - Test manifests
- ✅ `output/` - Pipeline outputs

---

## 🎯 Summary

### Benefits of New Structure
✅ **Clear Layer Separation** - Easy to find component files  
✅ **Centralized Documentation** - All docs in `docs/`  
✅ **Organized Scripts** - Utilities grouped logically  
✅ **Clean Root** - Minimal clutter  
✅ **Easy Navigation** - Intuitive hierarchy  
✅ **Professional Layout** - Industry-standard organization  

### Next Steps
1. ✅ Create new directory structure
2. ✅ Move files to appropriate locations
3. ✅ Update import paths in Python scripts
4. ✅ Update PowerShell script paths
5. ✅ Update documentation references
6. ✅ Test all scripts after reorganization

---

**Status:** ✅ Repository Structure Defined

**Last Updated:** November 3, 2025  
**Maintainer:** SafeFix-K8s Team
