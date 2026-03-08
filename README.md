# SafeFixK8s 🛡️

**Automated Kubernetes Security Remediation Pipeline**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker Required](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)

SafeFixK8s is an intelligent, multi-stage security pipeline that automatically detects, analyzes, and remediates security misconfigurations in Kubernetes manifests. By combining 13 industry-standard security scanners with AI-powered patch generation, it delivers production-ready, secure Kubernetes deployments.

## 🎯 Key Features

- **🔍 Comprehensive Detection**: Leverages 13 industry-leading security scanners for maximum coverage
- **🎨 Intelligent Normalization**: Unifies findings into 50+ standardized security categories across 7 families
- **🤖 Hybrid Repair Strategy**: Combines deterministic fixes, smart templates, and AI-guided patches
- **🔄 Multi-LLM Consensus**: Uses multiple AI providers (OpenAI, Groq, Gemini, OpenRouter) with automatic fallback
- **✅ Rigorous Validation**: 7-gate validation framework ensures fixes are safe and production-ready
- **💰 Cost Optimized**: Prioritizes deterministic fixes to minimize LLM API costs
- **🔒 Comprehensive Hardening**: Applies all 4 critical security controls atomically
- **📊 Human-Readable Reports**: Generates detailed explanations alongside technical outputs

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Security Tools](#-security-tools)
- [Output Structure](#-output-structure)
- [Configuration](#-configuration)
- [Examples](#-examples)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Docker** (for security scanners)
- **PowerShell 5.1+** (Windows) or **Bash 4.0+** (Linux/Mac)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/SafeFixK8s.git
cd SafeFixK8s

# Install Python dependencies
pip install -r requirements.txt

# Configure API keys (copy example and edit)
cp .env.example .env
# Edit .env with your LLM API keys
```

### Basic Usage

```bash
# Place your Kubernetes manifests in tests/
mkdir -p tests/
cp your-deployment.yaml tests/

# Run the full pipeline
python pipeline.py --input tests/ --output results/

# View secured manifests
cat results/repair/SECURED_*.yaml

# Read human-friendly explanation
cat results/repair/EXPLANATION_*.yaml.md
```

**That's it!** Your Kubernetes manifests are now secured and validated.

## 📦 Installation

### System Requirements

- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 11+
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 10GB free space (for Docker images)
- **Network**: Internet connection for LLM APIs and Docker pulls

### Detailed Setup

1. **Install Python 3.8+**
   ```bash
   python3 --version  # Verify installation
   ```

2. **Install Docker**
   ```bash
   docker --version  # Verify installation
   ```

3. **Clone Repository**
   ```bash
   git clone https://github.com/yourusername/SafeFixK8s.git
   cd SafeFixK8s
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Configure API Keys**
   
   Create a `.env` file in the project root:
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

   **Note**: You only need API keys for the LLM providers you plan to use. The system supports automatic fallback across providers.

6. **Verify Installation**
   ```bash
   python pipeline.py --help
   ```

## 📖 Usage

### Full Pipeline

Run all 4 stages in sequence:

```bash
python pipeline.py --input tests/ --output results/
```

**Options:**
- `--input DIR`: Directory containing Kubernetes YAML manifests (required)
- `--output DIR`: Output directory for results (default: `output/`)
- `--detection-mode MODE`: Scanner mode - `lean` (10 tools) or `extended` (13 tools) (default: `lean`)
- `--models LIST`: Comma-separated LLM providers (default: `groq,openrouter,gemini`)
- `--concurrency N`: Number of concurrent LLM requests (default: 5)
- `--strict`: Enable strict validation mode
- `--verbose, -v`: Enable verbose logging

### Individual Stages

Run specific pipeline stages independently:

#### Stage 1: Detection

```bash
python pipeline.py --stage detection --input tests/ --output results/
```

**Options:**
- `--detection-mode lean`: Use 10 core scanners (faster, ~2-5 minutes)
- `--detection-mode extended`: Use all 13 scanners (comprehensive, ~5-10 minutes)

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

**Options:**
- `--models`: Comma-separated list of LLM providers (`openai`, `groq`, `gemini`, `openrouter`)
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

**Options:**
- `--strict`: Enable strict validation (fails on warnings)

### Convenience Scripts

**Linux/Mac:**
```bash
./run_pipeline.sh
```

**Windows:**
```bash
.\run_pipeline.bat
```

## 🏗️ Architecture

SafeFixK8s implements a 4-stage pipeline architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                    STAGE 1: DETECTION                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PowerShell Orchestrator (detectors.ps1)                  │  │
│  │  • Runs 13 security scanners via Docker                  │  │
│  │  • Modes: LEAN (10 tools) / EXTENDED (13 tools)          │  │
│  │  • Output: output/detection/raw/*.json                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STAGE 2: NORMALIZATION                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Normalizer (normalizer.py)                               │  │
│  │  • Parses 13 different tool outputs                      │  │
│  │  • Maps to 50+ standard categories (7 families)          │  │
│  │  • Applies false positive filtering                      │  │
│  │  • Implements consensus scoring                          │  │
│  │  • Outputs: normalized_findings.json, llm_payload.json   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                   STAGE 3: REPAIR (LLM)                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Multi-LLM Orchestrator (multi_llm_orchestrator.py)       │  │
│  │  • 3 fix strategies: DETERMINISTIC, TEMPLATE, LLM_GUIDED │  │
│  │  • Comprehensive security hardening (4 controls)         │  │
│  │  • JSON Patch (RFC-6902) application                     │  │
│  │  • Outputs: SECURED_*.yaml, EXPLANATION_*.md             │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STAGE 4: VALIDATION                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 7-Gate Validation (validation_gates_improved.py)         │  │
│  │  • Schema auto-fix engine                                │  │
│  │  • 20+ category validators                               │  │
│  │  • Dangerous config detection                            │  │
│  │  • Kubeconform integration                               │  │
│  │  • Outputs: SUMMARY_VALIDATION.csv, detailed reports     │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Multi-Tool Consensus**: Reduces false positives through agreement from multiple scanners
2. **Deterministic First**: Prioritizes zero-LLM-token fixes (cost + reliability)
3. **Safe Defaults**: Never modifies protected fields (image, selectors, metadata.name)
4. **Comprehensive Hardening**: Applies all 4 security controls together
5. **Human-Readable**: Generates markdown explanations alongside technical JSON
6. **Validation Gates**: Multi-layered verification ensures fixes don't break workloads

## 🔧 Security Tools

SafeFixK8s integrates **13 industry-standard security scanners**:

### Core Tools (LEAN Mode - 10 tools)

| Tool | Provider | Focus Area |
|------|----------|------------|
| **Checkov** | Bridgecrew | Infrastructure-as-Code security |
| **Conftest** | Open Policy Agent | OPA-based policy testing |
| **Trivy** | Aqua Security | Comprehensive security scanning |
| **Kubescape** | ARMO | Kubernetes security platform |
| **Polaris** | Fairwinds | Best practices validation |
| **KubeLinter** | StackRox/Red Hat | Static analysis |
| **Kubeaudit** | Shopify | Security auditing |
| **KubeScore** | Community | Static code analysis |
| **Kubeconform** | Community | Schema validation |
| **yamllint** | Community | YAML linting |

### Extended Tools (EXTENDED Mode - Additional 3 tools)

| Tool | Provider | Focus Area |
|------|----------|------------|
| **Pluto** | Fairwinds | Deprecated API detection |
| **GitLeaks** | Community | Secret detection |
| **RBAC-Police** | Community | RBAC least-privilege |

**Mode Selection:**
- **LEAN mode** (default): Runs 10 core tools - faster, suitable for CI/CD
- **EXTENDED mode**: Runs all 13 tools - comprehensive, suitable for security audits

## 📂 Output Structure

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
│   ├── SECURED_*.yaml                # Fixed manifests
│   ├── EXPLANATION_*.yaml.md         # Human-readable explanations
│   └── ...
└── validation/
    ├── SUMMARY_VALIDATION.csv        # High-level validation summary
    └── REPORT_VALIDATE_*.json        # Detailed validation reports
```

## ⚙️ Configuration

### Security Categories

SafeFixK8s normalizes findings into **7 category families** with **50+ specific categories**:

1. **PrivilegeHostNamespace**: Privileged containers, host access, security contexts
2. **ResourceConfigDoS**: Resource limits, health probes, high availability
3. **ImageSupplyChain**: Image tags, pull policies, trusted registries
4. **SecretsExposure**: Hardcoded credentials, secret leaks
5. **RBAC**: Role bindings, permissions, cluster-admin usage
6. **NetworkExposureTLS**: NetworkPolicies, Ingress, TLS settings
7. **DeprecatedAPIIngress**: Deprecated Kubernetes API versions

### Validation Configuration

Customize validation rules in `Validations/validation_config.yaml`:

```yaml
enable_kubeconform: true          # Schema validation
enable_schema_autofix: true       # Auto-fix schema errors
enable_parallel_validation: true  # Parallel processing
max_workers: 4                    # Concurrent validators
strict_mode: false                # Fail on warnings
```

## 💡 Examples

### Example: Secure a Simple Nginx Deployment

**Input** (`tests/nginx.yaml`):
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

**Run Pipeline:**
```bash
python pipeline.py --input tests/ --output results/
```

**Output** (`results/repair/SECURED_nginx.yaml`):

✅ **Security Improvements Applied:**
- ✅ Added security contexts (runAsNonRoot, allowPrivilegeEscalation: false)
- ✅ Dropped all capabilities
- ✅ Added seccomp and AppArmor profiles
- ✅ Set read-only root filesystem with emptyDir volumes
- ✅ Added resource limits and requests
- ✅ Added liveness and readiness probes
- ✅ Disabled ServiceAccount token auto-mount

See [USAGE_GUIDE.md](USAGE_GUIDE.md) for complete examples.

## 📚 Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)**: Comprehensive usage guide with examples
- **[METHODOLOGY.md](METHODOLOGY.md)**: Technical methodology and algorithms
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Contribution guidelines

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/SafeFixK8s.git
cd SafeFixK8s

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

This project integrates and builds upon these excellent open-source security tools:
- Checkov (Bridgecrew), Trivy (Aqua Security), Kubescape (ARMO)
- Polaris (Fairwinds), KubeLinter (StackRox/Red Hat), Kubeaudit (Shopify)
- KubeScore, Conftest (OPA), Kubeconform, yamllint
- Pluto (Fairwinds), GitLeaks, RBAC-Police

Special thanks to the Kubernetes security community for their invaluable tools and research.

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/SafeFixK8s/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/SafeFixK8s/discussions)

## 🌟 Star History

If you find SafeFixK8s useful, please consider giving it a star ⭐

---

**SafeFixK8s** - Automating Kubernetes Security, One Manifest at a Time 🛡️
