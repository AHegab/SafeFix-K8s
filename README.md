# SafeFixK8s

**Automated Kubernetes Security Remediation System**

SafeFixK8s is an intelligent, multi-stage pipeline that automatically detects, analyzes, and fixes security misconfigurations in Kubernetes YAML manifests. It combines the power of 13 industry-standard security scanners with advanced AI-driven patch generation to deliver production-ready, secure Kubernetes deployments.

## Overview

SafeFixK8s addresses the critical challenge of Kubernetes security hardening by automating the entire remediation lifecycle:

1. **Detection**: Runs 13 security scanning tools to comprehensively identify vulnerabilities
2. **Normalization**: Aggregates and unifies findings from different tools into a standardized schema
3. **Repair**: Generates intelligent security patches using a hybrid approach (deterministic + template-based + LLM-guided)
4. **Validation**: Validates fixes through a rigorous 7-gate framework to ensure safety and effectiveness

### Key Features

- **Multi-Tool Security Scanning**: Leverages 13 industry-leading security tools for comprehensive coverage
- **Intelligent Normalization**: Unifies findings into 50+ standardized security categories across 7 families
- **Hybrid Repair Strategy**: Combines deterministic fixes, smart templates, and AI-guided patches for optimal results
- **Multi-LLM Consensus**: Uses multiple AI providers (OpenAI, Groq, Gemini, OpenRouter) with fallback support
- **Rigorous Validation**: 7-gate validation framework ensures fixes are safe and production-ready
- **Zero Token Optimization**: Prioritizes deterministic fixes to minimize LLM costs
- **Comprehensive Security Hardening**: Applies all 4 critical security controls atomically
- **Human-Readable Reports**: Generates detailed explanations alongside technical outputs

## Table of Contents

- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Full Pipeline](#full-pipeline)
  - [Individual Stages](#individual-stages)
  - [Advanced Options](#advanced-options)
- [Architecture](#architecture)
- [Security Tools](#security-tools)
- [Configuration](#configuration)
- [Output Structure](#output-structure)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

#### Required Software

1. **Python 3.8+**
   ```bash
   python3 --version
   ```

2. **Docker** (for security scanners)
   ```bash
   docker --version
   ```

3. **PowerShell** (Windows) or **Bash** (Linux/Mac)
   - Windows: PowerShell 5.1+ (built-in)
   - Linux/Mac: Bash 4.0+

#### System Requirements

- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 11+
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 10GB free space (for Docker images)
- **Network**: Internet connection for LLM APIs and Docker pulls

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SafeFixK8s
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API keys**

   Create a `.env` file in the project root with your LLM provider API keys:
   ```bash
   # OpenRouter (Grok Vision)
   OPENROUTER_API_KEY=your_key_here
   OPENROUTER_MODEL=x-ai/grok-vision-beta

   # Google Gemini
   GEMINI_API_KEY=your_key_here
   GEMINI_MODEL=gemini-2.0-flash-exp

   # Groq (Llama)
   GROQ_API_KEY=your_key_here
   GROQ_MODEL=llama-3.1-70b-versatile

   # OpenAI (GPT-4o-mini)
   OPENAI_API_KEY=your_key_here
   OPENAI_MODEL=gpt-4o-mini
   ```

   **Note**: You only need API keys for the LLM providers you plan to use. The system supports fallback across providers.

4. **Pull Docker images for security scanners**

   The detection layer will automatically pull required Docker images on first run. You can pre-pull them:
   ```bash
   docker pull bridgecrew/checkov:latest
   docker pull aquasec/trivy:latest
   docker pull quay.io/armosec/kubescape:latest
   # ... (other scanners will pull automatically)
   ```

5. **Verify installation**
   ```bash
   python pipeline.py --help
   ```

## Quick Start

### Basic Usage

1. **Place your Kubernetes manifests** in the `tests/` directory:
   ```bash
   mkdir -p tests/
   cp your-deployment.yaml tests/
   ```

2. **Run the full pipeline**:

   **Linux/Mac**:
   ```bash
   ./run_pipeline.sh
   ```

   **Windows**:
   ```bash
   .\run_pipeline.bat
   ```

   Or directly with Python:
   ```bash
   python pipeline.py --input tests/ --output results/
   ```

3. **Review the results**:
   ```bash
   # View secured manifests
   cat results/repair/SECURED_*.yaml

   # Read human-friendly explanation
   cat results/repair/EXPLANATION_*.yaml.md

   # Check validation summary
   cat results/validation/SUMMARY_VALIDATION.csv
   ```

### Example Output

After running the pipeline, you'll find:

```
results/
├── detection/
│   ├── raw/                          # Raw scanner outputs (13 JSON files)
│   └── logs/                         # Detection logs
├── normalization/
│   ├── normalized_findings.json      # All findings with metadata
│   ├── llm_payload.json              # Actionable findings for repair
│   └── buckets.csv                   # Summary by category
├── repair/
│   ├── SECURED_deployment.yaml       # Fixed manifests
│   ├── EXPLANATION_deployment.yaml.md # Human-readable explanation
│   └── ...
└── validation/
    ├── SUMMARY_VALIDATION.csv        # High-level validation summary
    └── REPORT_VALIDATE_*.json        # Detailed validation reports
```

## Usage

### Full Pipeline

Run all 4 stages in sequence:

```bash
python pipeline.py --input tests/ --output results/
```

Options:
- `--input`: Directory containing Kubernetes YAML manifests (required)
- `--output`: Output directory for results (default: `output/`)
- `--detection-mode`: Scanner mode - `lean` (10 tools) or `extended` (13 tools) (default: `lean`)
- `--models`: Comma-separated LLM providers (default: `groq,openrouter,gemini`)
- `--concurrency`: Number of concurrent LLM requests (default: 5)
- `--strict`: Enable strict validation mode
- `--verbose, -v`: Enable verbose logging
- `--quiet, -q`: Quiet mode (errors only)

### Individual Stages

Run specific pipeline stages independently:

#### Stage 1: Detection

```bash
python pipeline.py --stage detection --input tests/ --output results/
```

Options:
- `--detection-mode lean`: Use 10 core scanners (faster)
- `--detection-mode extended`: Use all 13 scanners (comprehensive)

#### Stage 2: Normalization

```bash
python pipeline.py --stage normalize \
  --raw results/detection/raw/ \
  --tests tests/ \
  --output results/
```

#### Stage 3: Repair

```bash
python pipeline.py --stage repair \
  --payload results/normalization/llm_payload.json \
  --tests tests/ \
  --output results/ \
  --models groq,openrouter,gemini \
  --concurrency 5
```

Options:
- `--models`: Comma-separated list of LLM providers to use
- `--concurrency`: Number of parallel LLM requests (higher = faster but more API load)

#### Stage 4: Validation

```bash
python pipeline.py --stage validate \
  --tests tests/ \
  --fixed results/repair/ \
  --payload results/normalization/llm_payload.json \
  --output results/ \
  --strict
```

Options:
- `--strict`: Enable strict validation (fails on warnings)

### Advanced Options

#### Custom Output Directory Structure

```bash
python pipeline.py \
  --input tests/ \
  --output custom-results/ \
  --detection-mode extended \
  --models openai,groq \
  --concurrency 10 \
  --verbose
```

#### Skip Detection (Use Existing Scans)

```bash
# Run only normalization, repair, and validation
python pipeline.py --stage normalize --raw existing/detection/raw/ --tests tests/
python pipeline.py --stage repair --payload results/normalization/llm_payload.json --tests tests/
python pipeline.py --stage validate --tests tests/ --fixed results/repair/
```

## Architecture

SafeFixK8s implements a **4-stage architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                    STAGE 1: DETECTION                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PowerShell Orchestrator (detectors.ps1)                  │  │
│  │  - Runs 13 security scanners via Docker                  │  │
│  │  - Modes: LEAN (10 tools) / EXTENDED (13 tools)          │  │
│  │  - Output: output/detection/raw/*.json                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STAGE 2: NORMALIZATION                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Normalizer (normalizer.py)                               │  │
│  │  - Parses 13 different tool outputs                      │  │
│  │  - Maps to 50+ standard categories (7 families)          │  │
│  │  - Applies false positive filtering                      │  │
│  │  - Implements consensus scoring                          │  │
│  │  - Outputs:                                              │  │
│  │    • normalized_findings.json (all findings)             │  │
│  │    • llm_payload.json (actionable items)                 │  │
│  │    • buckets.csv (summary)                               │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                   STAGE 3: REPAIR (LLM)                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Multi-LLM Orchestrator (multi_llm_orchestrator.py)       │  │
│  │  - Implements 3 fix strategies:                          │  │
│  │    • DETERMINISTIC (0 tokens)                            │  │
│  │    • TEMPLATE (minimal tokens)                           │  │
│  │    • LLM_GUIDED (with fallback)                          │  │
│  │  - Comprehensive security hardening (4 controls)         │  │
│  │  - JSON Patch (RFC-6902) application                     │  │
│  │  - Patch deduplication & filtering                       │  │
│  │  - Outputs:                                              │  │
│  │    • SECURED_*.yaml (fixed manifests)                    │  │
│  │    • EXPLANATION_*.md (human reports)                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STAGE 4: VALIDATION                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 7-Gate Validation (validation_gates_improved.py)         │  │
│  │  - Schema auto-fix engine                                │  │
│  │  - 20+ category validators                               │  │
│  │  - Dangerous config detection                            │  │
│  │  - Kubeconform integration                               │  │
│  │  - Diff analysis                                         │  │
│  │  - Parallel processing support                           │  │
│  │  - Outputs:                                              │  │
│  │    • SUMMARY_VALIDATION.csv                              │  │
│  │    • REPORT_VALIDATE_*.json (detailed reports)           │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Multi-Tool Consensus**: Reduces false positives by requiring agreement from multiple scanners
2. **Deterministic First**: Prioritizes zero-LLM-token fixes where possible (cost + reliability)
3. **Safe Defaults**: Never modifies protected fields (image, selectors, metadata.name)
4. **Comprehensive Hardening**: Applies all 4 security controls together to avoid partial fixes
5. **Category Families**: Organizes 50+ categories into 7 logical families for better understanding
6. **Strong Tool Mapping**: Identifies authoritative tools per category
7. **Human-Readable Output**: Generates markdown explanations alongside technical JSON
8. **Validation Gates**: Multi-layered verification ensures fixes don't break workloads

## Security Tools

SafeFixK8s integrates **13 industry-standard security scanners** for comprehensive coverage:

### Core Tools (LEAN Mode - 10 tools)

1. **Checkov** - Infrastructure-as-Code security scanner by Bridgecrew
2. **Conftest** - OPA-based policy testing framework
3. **Trivy** - Comprehensive security scanner by Aqua Security
4. **Kubescape** - Kubernetes security platform by ARMO
5. **Polaris** - Best practices validation by Fairwinds
6. **KubeLinter** - Static analysis tool by StackRox/Red Hat
7. **Kubeaudit** - Security auditing tool by Shopify
8. **KubeScore** - Static code analysis for Kubernetes
9. **Kubeconform** - Kubernetes schema validation
10. **yamllint** - YAML linting and validation

### Extended Tools (EXTENDED Mode - Additional 3 tools)

11. **Pluto** - Deprecated Kubernetes API detection by Fairwinds
12. **GitLeaks** - Secret detection and prevention
13. **RBAC-Police** - RBAC least-privilege enforcement

### Tool Selection Strategy

- **LEAN mode** (default): Runs 10 core tools - faster, suitable for CI/CD pipelines
- **EXTENDED mode**: Runs all 13 tools - comprehensive, suitable for security audits

Each tool contributes unique findings to the normalization layer, where consensus scoring reduces false positives.

## Configuration

### Environment Variables (.env)

Configure LLM providers and models:

```bash
# OpenRouter Configuration
OPENROUTER_API_KEY=your_openrouter_key
OPENROUTER_MODEL=x-ai/grok-vision-beta

# Google Gemini Configuration
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-2.0-flash-exp

# Groq Configuration
GROQ_API_KEY=your_groq_key
GROQ_MODEL=llama-3.1-70b-versatile

# OpenAI Configuration
OPENAI_API_KEY=your_openai_key
OPENAI_MODEL=gpt-4o-mini
```

### Security Categories

SafeFixK8s normalizes findings into **7 category families** with **50+ specific categories**:

#### 1. PrivilegeHostNamespace
- Privileged containers
- Host access (PID, IPC, network)
- Security contexts (allowPrivilegeEscalation, capabilities, seccomp, AppArmor)
- Read-only root filesystem

#### 2. ResourceConfigDoS
- Resource limits and requests
- Liveness and readiness probes
- High availability settings

#### 3. ImageSupplyChain
- Image tags (latest, version pinning)
- Image pull policies
- Trusted registries

#### 4. SecretsExposure
- Hardcoded credentials
- Secret detection and leaks

#### 5. RBAC
- Role bindings and permissions
- Wildcard permissions
- Cluster-admin usage

#### 6. NetworkExposureTLS
- NetworkPolicies
- Ingress configurations
- TLS settings

#### 7. DeprecatedAPIIngress
- Deprecated Kubernetes API versions

## Output Structure

After running the pipeline, the output directory contains:

```
results/
├── detection/
│   ├── raw/
│   │   ├── checkov_raw.json          # Checkov findings
│   │   ├── trivy_raw.json            # Trivy findings
│   │   ├── kubescape_raw.json        # Kubescape findings
│   │   ├── conftest_raw.json         # Conftest findings
│   │   ├── polaris_raw.json          # Polaris findings
│   │   ├── kubelinter_raw.json       # KubeLinter findings
│   │   ├── kubeaudit_raw.json        # Kubeaudit findings
│   │   ├── kubescore_raw.json        # KubeScore findings
│   │   ├── kubeconform_raw.json      # Kubeconform findings
│   │   ├── yamllint_raw.json         # yamllint findings
│   │   ├── pluto_raw.json            # Pluto findings (extended)
│   │   ├── gitleaks_raw.json         # GitLeaks findings (extended)
│   │   └── rbac_police_raw.json      # RBAC-Police findings (extended)
│   └── logs/
│       └── detection_<timestamp>.log # Detection execution logs
│
├── normalization/
│   ├── normalized_findings.json      # All findings with full metadata
│   ├── llm_payload.json              # Filtered, actionable findings for LLM
│   └── buckets.csv                   # Summary grouped by (file, resource, category)
│
├── repair/
│   ├── SECURED_deployment.yaml       # Fixed Kubernetes manifest
│   ├── EXPLANATION_deployment.yaml.md # Human-readable explanation of fixes
│   └── ... (one pair per input manifest)
│
└── validation/
    ├── SUMMARY_VALIDATION.csv        # High-level summary (file, status, critical/high/medium/low counts)
    ├── REPORT_VALIDATE_deployment.yaml.json # Detailed validation report
    └── ... (one report per manifest)
```

### Key Output Files

#### normalized_findings.json
Complete dataset of all security findings with:
- Tool name and version
- Category and severity
- File path and resource reference
- Consensus score
- Detailed descriptions

#### llm_payload.json
Filtered, actionable findings ready for repair:
- Excludes non-auto-fixable categories
- Groups by file and resource
- Includes fix strategy hints

#### SECURED_*.yaml
Fixed Kubernetes manifests with:
- All applicable security patches applied
- Protected fields preserved (image, selectors, metadata.name)
- Valid Kubernetes YAML structure

#### EXPLANATION_*.yaml.md
Human-readable reports explaining:
- What vulnerabilities were found
- What fixes were applied
- Why each fix was necessary
- Which categories were fixed vs. skipped

#### SUMMARY_VALIDATION.csv
Validation summary showing:
- File name
- Overall status (PASS/NEEDS_REVIEW/FAIL)
- Count of violations by severity
- Key validation messages

## Examples

### Example 1: Secure an Nginx Deployment

**Input** (`tests/nginx-deployment.yaml`):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
```

**Run Pipeline**:
```bash
python pipeline.py --input tests/ --output results/
```

**Output** (`results/repair/SECURED_nginx-deployment.yaml`):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
      annotations:
        container.apparmor.security.beta.kubernetes.io/nginx: runtime/default
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginx:latest  # Note: Manual fix recommended for :latest tag
        ports:
        - containerPort: 80
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        livenessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
```

**Explanation** (`results/repair/EXPLANATION_nginx-deployment.yaml.md`):
```markdown
# Security Fixes Applied to nginx-deployment.yaml

## Summary
Applied comprehensive security hardening to nginx Deployment.

## Vulnerabilities Fixed

### 1. Privileged Container
**Severity**: HIGH
**Category**: Security/PrivilegedContainer
**Fix**: Added `allowPrivilegeEscalation: false` and removed privileged mode

### 2. Missing Capabilities Drop
**Severity**: MEDIUM
**Category**: Security/CapabilitiesAdded
**Fix**: Dropped all capabilities with `capabilities.drop: [ALL]`

### 3. Missing Seccomp Profile
**Severity**: MEDIUM
**Category**: Security/SeccompProfileMissing
**Fix**: Added seccomp profile `RuntimeDefault`

### 4. Read-Only Root Filesystem
**Severity**: MEDIUM
**Category**: Security/ReadOnlyRootFilesystemFalse
**Fix**: Set `readOnlyRootFilesystem: true` and added emptyDir volumes for writable paths

### 5. Running as Root
**Severity**: HIGH
**Category**: AuthZ/RunAsRootAllowed
**Fix**: Added `runAsNonRoot: true` and `runAsUser: 1000`

### 6. Missing Resource Limits
**Severity**: MEDIUM
**Category**: ResourceConfig/LimitsMissing
**Fix**: Added memory/CPU requests and limits

### 7. Missing Health Probes
**Severity**: MEDIUM
**Category**: ResourceConfig/LivenessProbeMissing
**Fix**: Added liveness and readiness probes

## Manual Follow-Up Required

### Image Tag: latest
**Category**: ImageSupplyChain/ImageTagLatest
**Recommendation**: Pin to specific version (e.g., `nginx:1.25.3-alpine`)
```

### Example 2: Run Individual Stages

```bash
# Stage 1: Detection only
python pipeline.py --stage detection --input tests/ --output scan-results/

# Stage 2: Normalize existing scan results
python pipeline.py --stage normalize \
  --raw scan-results/detection/raw/ \
  --tests tests/ \
  --output scan-results/

# Stage 3: Generate fixes using only OpenAI
python pipeline.py --stage repair \
  --payload scan-results/normalization/llm_payload.json \
  --tests tests/ \
  --output scan-results/ \
  --models openai

# Stage 4: Validate with strict mode
python pipeline.py --stage validate \
  --tests tests/ \
  --fixed scan-results/repair/ \
  --output scan-results/ \
  --strict
```

## Troubleshooting

### Common Issues

#### 1. Docker Permission Errors

**Problem**: `ERROR: Got permission denied while trying to connect to the Docker daemon socket`

**Solution**:
```bash
# Linux: Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo (not recommended for production)
sudo python pipeline.py --input tests/
```

#### 2. LLM API Errors

**Problem**: `ERROR: Invalid API key for <provider>`

**Solution**:
- Verify your `.env` file contains valid API keys
- Check that API keys have sufficient credits/quota
- Ensure API keys have correct permissions

#### 3. PowerShell Execution Policy (Windows)

**Problem**: `Cannot be loaded because running scripts is disabled on this system`

**Solution**:
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 4. Missing Docker Images

**Problem**: `ERROR: Unable to find image '<tool>:latest' locally`

**Solution**: Docker will automatically pull images on first run. Ensure you have internet connectivity.

#### 5. Out of Memory Errors

**Problem**: Pipeline crashes with OOM errors

**Solution**:
- Reduce `--concurrency` value (default: 5)
- Process fewer files at once
- Increase Docker memory limit in Docker Desktop settings

### Debug Mode

Enable verbose logging for detailed diagnostics:

```bash
python pipeline.py --input tests/ --output results/ --verbose
```

### Log Files

Check log files in the output directory:
```bash
# Detection logs
cat results/detection/logs/detection_*.log

# Pipeline logs (if using wrapper scripts)
cat results/pipeline.log
```

## Project Structure

```
SafeFixK8s/
├── Detection/
│   ├── detectors.ps1              # PowerShell scanner orchestrator
│   └── ...
├── Normalizer/
│   ├── normalizer.py              # Finding normalization engine (1,968 lines)
│   └── ...
├── LLMs/
│   ├── multi_llm_orchestrator.py  # Multi-LLM repair orchestrator (2,176 lines)
│   └── ...
├── Validations/
│   ├── validation_gates_improved.py # 7-gate validation framework (1,409 lines)
│   └── ...
├── policies/
│   ├── conftest/                  # OPA Rego policies
│   ├── checkov/                   # Checkov custom policies
│   └── ...
├── configs/
│   └── ...                        # Configuration files
├── tests/
│   └── ...                        # Test Kubernetes manifests
├── .env                           # LLM API keys (not in git)
├── .gitignore
├── pipeline.py                    # Main CLI orchestrator (655 lines)
├── requirements.txt               # Python dependencies
├── run_pipeline.sh                # Linux/Mac launcher
├── run_pipeline.bat               # Windows launcher
└── README.md                      # This file
```

## Contributing

This project is part of a BSc thesis on automated Kubernetes security remediation. Contributions, suggestions, and feedback are welcome.

### Development Setup

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## License

[License information to be added]

## Acknowledgments

This project integrates and builds upon the following open-source security tools:

- Checkov (Bridgecrew)
- Trivy (Aqua Security)
- Kubescape (ARMO)
- Polaris (Fairwinds)
- KubeLinter (StackRox/Red Hat)
- Kubeaudit (Shopify)
- KubeScore
- Conftest (Open Policy Agent)
- Kubeconform
- yamllint
- Pluto (Fairwinds)
- GitLeaks
- RBAC-Police

Special thanks to the Kubernetes security community for their invaluable tools and research.

## Contact

For questions, issues, or feedback, please open an issue on GitHub or contact the project maintainers.

---

**SafeFixK8s** - Automating Kubernetes Security, One Manifest at a Time
