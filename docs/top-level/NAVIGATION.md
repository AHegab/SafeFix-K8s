# 🚀 Quick Navigation Guide

**SafeFix-K8s Repository Organization - November 3, 2025**

---

## 📍 Where to Find Everything

### 📖 Want to Read Documentation?
```bash
cd docs/

# Main guides
cat HOW_TO_USE.md         # Complete user guide
cat COMMANDS.md           # CLI reference

# Layer-specific guides
cd guides/
cat DETECTION_LAYER_GUIDE.md       # 13 tools, 25KB guide
cat NORMALIZATION_LAYER_GUIDE.md   # 22 categories, 28KB guide
cat VALIDATION_ANALYSIS.md         # 98.5% accuracy analysis
```

### 🔍 Want to Run Detection?
```bash
cd Detection/

# Main detection script
.\detectors.ps1              # Runs all 13 tools

# Helper scripts
cd scripts/
.\install-tools.ps1          # Install all security tools
.\run_detection.ps1          # Alternative detection script
.\test-detectors.ps1         # Test tool installation

# View results
cd ..\output\raw\
dir *.json                   # 13 raw output files
```

### 🔄 Want to Normalize Findings?
```bash
cd Normalizer/

# Main normalization
python normalize.py          # Creates normalized_findings.json

# Validate output
python validate_output.py    # Checks accuracy
```

### 🤖 Want to Generate Patches?
```bash
cd LLMs/

# Run LLM orchestrator
python multi_llm_orchestrator.py

# View patches
cd ..\output\patch_sandbox\
dir                          # Patch directories 1/, 2/, etc.
```

### ✅ Want to Validate Results?
```bash
cd Validations/

# Run validation gates
.\validate-gates.ps1

# View evidence
cd evidence\
dir patch_sandbox_*         # Validation evidence per patch

# View reports
cd ..\reports\
dir *.md                    # Validation reports
```

### 🧪 Want to See Test Files?
```bash
cd tests/

dir *.yaml                  # 16 test manifests

# Key test files:
# 14.genkubesec_privileged_pod.yaml  - Privileged container
# 15.pod_privilege_escalation.yaml   - Privilege escalation
# 28.role_overly_permissive.yaml     - RBAC issues
# 34.unencrypted_secret.yaml         - Secret management
```

### 📊 Want to View Results?
```bash
cd output/

# Main outputs
cat normalized_findings.json    # 131 normalized findings
cat llm_payload.json           # LLM-ready subset
cat llm_decisions.json         # LLM patch decisions
cat Coverage_Matrix_Updated.csv # Coverage analysis

# Patch outputs
cd patch_sandbox\
dir                            # Patch directories
```

### 🔧 Want to Use Utilities?
```bash
cd scripts/

# Main utilities
python cli.py                   # CLI interface
.\clean-outputs.ps1            # Clean output directories

# Helper utilities
cd utils\
python analyze_conftest.py      # Analyze Conftest output
python check_privileged.py      # Check privileged containers
python gap_analysis.py         # Gap analysis
```

### ⚙️ Want to Configure Tools?
```bash
cd configs/

# Tool configurations
cat .checkov.yaml              # Checkov settings
cat .kube-linter.yaml          # KubeLinter settings
cat .env                       # API keys (don't commit!)

# Policy configurations
cd ..\Detection\policies\
dir checkov\*.py               # Custom Checkov policies
dir conftest\*.rego            # OPA policies
cat gitleaks-rules.toml        # Secret detection rules
```

---

## 🎯 Common Tasks

### Run Full Pipeline
```bash
# From repository root:

# 1. Detection
cd Detection
.\detectors.ps1

# 2. Normalization
cd ..\Normalizer
python normalize.py

# 3. LLM Patching
cd ..\LLMs
python multi_llm_orchestrator.py

# 4. Validation
cd ..\Validations
.\validate-gates.ps1
```

### View All Documentation
```bash
# Main README
cat README.md

# Layer guides (comprehensive!)
cat docs\guides\DETECTION_LAYER_GUIDE.md
cat docs\guides\NORMALIZATION_LAYER_GUIDE.md
cat docs\guides\VALIDATION_ANALYSIS.md

# Component READMEs
cat Detection\README.md
cat Normalizer\README.md
cat LLMs\README.md
cat Validations\README.md
```

### Clean Everything
```bash
# From root
.\scripts\clean-outputs.ps1

# This removes:
# - Detection/output/raw/*.json
# - output/*.json
# - output/patch_sandbox/*
# - Validations/evidence/*
# - Validations/reports/*
```

### Add New Test File
```bash
# 1. Create test file
cd tests\
# Create: <number>.<description>.yaml

# 2. Run detection
cd ..\Detection
.\detectors.ps1

# 3. See if it's detected
cd ..\output
cat normalized_findings.json | findstr "<your-file-name>"
```

---

## 🗺️ Directory Map

```
SafeFixK8s/                           ← You are here (root)
│
├── 📚 docs/                          ← Go here for documentation
│   ├── guides/                       ← Layer-specific guides
│   │   ├── DETECTION_LAYER_GUIDE.md     ← 13 tools explained
│   │   ├── NORMALIZATION_LAYER_GUIDE.md ← 22 categories explained
│   │   └── VALIDATION_ANALYSIS.md       ← 98.5% accuracy proof
│   ├── HOW_TO_USE.md                 ← Start here for usage
│   └── COMMANDS.md                   ← CLI reference
│
├── 🔍 Detection/                     ← Go here to scan
│   ├── detectors.ps1                 ← Main script
│   ├── scripts/                      ← Helper scripts
│   │   ├── install-tools.ps1            ← Install 13 tools
│   │   ├── run_detection.ps1
│   │   └── test-detectors.ps1
│   ├── policies/                     ← Security policies
│   │   ├── checkov/                     ← Custom Checkov
│   │   └── conftest/                    ← OPA policies
│   └── output/raw/                   ← Results go here
│       ├── checkov_raw.json
│       ├── trivy_config_raw.json
│       └── ... (11 more)
│
├── 🔄 Normalizer/                    ← Go here to normalize
│   ├── normalize.py                  ← Main script
│   └── validate_output.py            ← Validation
│
├── 🤖 LLMs/                          ← Go here for AI patches
│   └── multi_llm_orchestrator.py     ← LLM script
│
├── ✅ Validations/                   ← Go here to validate
│   ├── validate-gates.ps1            ← Validation script
│   ├── evidence/                     ← Proof goes here
│   └── reports/                      ← Reports go here
│
├── 🧪 tests/                         ← Test manifests
│   └── *.yaml                        ← 16 test files
│
├── 📊 output/                        ← Pipeline outputs
│   ├── normalized_findings.json      ← 131 findings
│   ├── llm_payload.json              ← LLM subset
│   └── patch_sandbox/                ← Patches
│
├── 🔧 scripts/                       ← Utilities
│   ├── cli.py                        ← CLI interface
│   ├── clean-outputs.ps1             ← Cleanup
│   └── utils/                        ← Helpers
│
└── ⚙️ configs/                       ← Configurations
    ├── .checkov.yaml
    ├── .kube-linter.yaml
    └── .env
```

---

## 💡 Pro Tips

### 1. Always Start Here
```bash
# Read the main README first
cat README.md

# Then check layer guides
cd docs/guides/
```

### 2. Layer READMEs Are Your Friends
```bash
# Each layer has its own README
cat Detection/README.md
cat Normalizer/README.md
cat LLMs/README.md
cat Validations/README.md
```

### 3. Use Tab Completion
```bash
# Windows PowerShell
cd Det<TAB>      # Completes to Detection/
cd Nor<TAB>      # Completes to Normalizer/
```

### 4. Follow the Pipeline Order
```
1. Detection/     ← Start
2. Normalizer/    ← Then
3. LLMs/          ← Then
4. Validations/   ← Finish
```

### 5. Check Output Frequently
```bash
# After each layer:
cd output/
dir               # See what's been created
```

---

## 🔗 Quick Links

| What | Where |
|------|-------|
| **Main README** | `/README.md` |
| **How to Use** | `/docs/HOW_TO_USE.md` |
| **Detection Guide** | `/docs/guides/DETECTION_LAYER_GUIDE.md` |
| **Normalization Guide** | `/docs/guides/NORMALIZATION_LAYER_GUIDE.md` |
| **Validation Analysis** | `/docs/guides/VALIDATION_ANALYSIS.md` |
| **Run Detection** | `/Detection/detectors.ps1` |
| **Run Normalization** | `/Normalizer/normalize.py` |
| **Run LLM** | `/LLMs/multi_llm_orchestrator.py` |
| **Run Validation** | `/Validations/validate-gates.ps1` |
| **Test Files** | `/tests/*.yaml` |
| **Results** | `/output/` |

---

## 🎓 Learning Path

### For Beginners
1. Read `/README.md`
2. Read `/docs/HOW_TO_USE.md`
3. Run `/Detection/detectors.ps1`
4. Check `/output/normalized_findings.json`

### For Researchers
1. Read `/docs/guides/DETECTION_LAYER_GUIDE.md` (25KB)
2. Read `/docs/guides/NORMALIZATION_LAYER_GUIDE.md` (28KB)
3. Read `/docs/guides/VALIDATION_ANALYSIS.md` (15KB)
4. Analyze `/output/` results

### For Developers
1. Check `/scripts/utils/` for helper tools
2. Review `/Detection/policies/` for custom rules
3. Explore `/Normalizer/normalize.py` for logic
4. Study `/LLMs/multi_llm_orchestrator.py` for AI

---

**Last Updated:** November 3, 2025  
**Repository Version:** 2.0 (Reorganized)  
**Navigation Difficulty:** ⭐ Easy (Professional Structure)

✅ Clean structure  
✅ Easy navigation  
✅ Clear documentation  
✅ Logical organization
