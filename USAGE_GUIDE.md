# SafeFixK8s Usage Guide

**Comprehensive Guide to Using SafeFixK8s for Kubernetes Security Remediation**

This guide provides detailed instructions, examples, and best practices for using SafeFixK8s to secure your Kubernetes manifests.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Usage](#advanced-usage)
4. [Pipeline Stages](#pipeline-stages)
5. [Configuration](#configuration)
6. [Real-World Examples](#real-world-examples)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [CI/CD Integration](#cicd-integration)
10. [Performance Tuning](#performance-tuning)

---

## Getting Started

### Prerequisites Checklist

Before running SafeFixK8s, ensure you have:

- ✅ Python 3.8 or higher installed
- ✅ Docker installed and running
- ✅ At least one LLM provider API key (OpenAI, Groq, Gemini, or OpenRouter)
- ✅ 8GB+ RAM available
- ✅ Internet connection for Docker pulls and LLM APIs

### First-Time Setup

1. **Install SafeFixK8s**

```bash
# Clone repository
git clone https://github.com/yourusername/SafeFixK8s.git
cd SafeFixK8s

# Install dependencies
pip install -r requirements.txt
```

2. **Configure API Keys**

Create a `.env` file in the project root:

```bash
# Minimum configuration (choose at least one provider)
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=llama-3.1-70b-versatile
```

For redundancy and better coverage, configure multiple providers:

```bash
# Recommended configuration (multiple providers for fallback)
OPENROUTER_API_KEY=sk-or-v1-your_openrouter_key
OPENROUTER_MODEL=x-ai/grok-vision-beta

GEMINI_API_KEY=AIzaSy_your_gemini_key
GEMINI_MODEL=gemini-2.0-flash-exp

GROQ_API_KEY=gsk_your_groq_key
GROQ_MODEL=llama-3.1-70b-versatile

OPENAI_API_KEY=sk-your_openai_key
OPENAI_MODEL=gpt-4o-mini
```

3. **Verify Installation**

```bash
python pipeline.py --help
```

You should see the help menu with all available options.

---

## Basic Usage

### Scenario 1: Secure a Single Manifest

**Step 1**: Create a test directory and add your manifest

```bash
mkdir -p tests/
cp your-deployment.yaml tests/
```

**Step 2**: Run the full pipeline

```bash
python pipeline.py --input tests/ --output results/
```

**Step 3**: Review the results

```bash
# View the secured manifest
cat results/repair/SECURED_your-deployment.yaml

# Read the human-friendly explanation
cat results/repair/EXPLANATION_your-deployment.yaml.md

# Check validation summary
cat results/validation/SUMMARY_VALIDATION.csv
```

### Scenario 2: Secure Multiple Manifests

Place all your YAML files in the `tests/` directory:

```bash
tests/
├── deployment-1.yaml
├── deployment-2.yaml
├── statefulset.yaml
└── daemonset.yaml
```

Run the pipeline once to process all files:

```bash
python pipeline.py --input tests/ --output results/
```

SafeFixK8s will process each file independently and generate separate secured manifests.

### Scenario 3: Quick Validation Only

If you already have secured manifests and want to validate them:

```bash
python pipeline.py --stage validate \
  --tests original/ \
  --fixed secured/ \
  --output results/
```

---

## Advanced Usage

### Custom Output Directory Structure

Organize outputs by date or project:

```bash
# Using date-based directories
OUTPUT_DIR="results/$(date +%Y%m%d_%H%M%S)"
python pipeline.py --input tests/ --output $OUTPUT_DIR
```

```bash
# Using project-based directories
python pipeline.py \
  --input projects/microservice-a/ \
  --output results/microservice-a/
```

### Selecting LLM Providers

Choose specific LLM providers based on your needs:

```bash
# Use only Groq (fastest, free tier available)
python pipeline.py --input tests/ --models groq

# Use only OpenAI (highest quality)
python pipeline.py --input tests/ --models openai

# Use multiple providers for consensus (recommended)
python pipeline.py --input tests/ --models groq,gemini,openrouter
```

### Detection Modes

**LEAN Mode** (Default - Faster):
```bash
python pipeline.py --input tests/ --detection-mode lean
```
- Uses 10 core security scanners
- Execution time: ~2-5 minutes
- Suitable for: CI/CD pipelines, rapid iteration

**EXTENDED Mode** (Comprehensive):
```bash
python pipeline.py --input tests/ --detection-mode extended
```
- Uses all 13 security scanners (adds Pluto, GitLeaks, RBAC-Police)
- Execution time: ~5-10 minutes
- Suitable for: Security audits, pre-production validation

### Strict Validation Mode

Enable strict mode to fail on warnings:

```bash
python pipeline.py --input tests/ --strict
```

In strict mode:
- Schema warnings cause validation failure
- Medium severity issues cause validation failure
- Recommended for production deployments

### Parallel Processing

Control the number of concurrent LLM requests:

```bash
# Conservative (lower API load, slower)
python pipeline.py --input tests/ --concurrency 2

# Balanced (default)
python pipeline.py --input tests/ --concurrency 5

# Aggressive (higher API load, faster)
python pipeline.py --input tests/ --concurrency 10
```

**Note**: Higher concurrency may trigger rate limits. Start with default (5) and adjust based on your API quotas.

---

## Pipeline Stages

SafeFixK8s consists of 4 stages that can be run independently or together.

### Stage 1: Detection

**Purpose**: Run security scanners to identify vulnerabilities

```bash
python pipeline.py --stage detection \
  --input tests/ \
  --output results/ \
  --detection-mode lean
```

**Output**:
- `results/detection/raw/*.json`: Raw scanner outputs (13 JSON files)
- `results/detection/logs/*.log`: Execution logs

**When to use standalone**:
- You want to run only security scanning
- Integrating with external normalization tools
- Debugging scanner configurations

### Stage 2: Normalization

**Purpose**: Parse scanner outputs and unify findings into standard categories

```bash
python pipeline.py --stage normalize \
  --raw results/detection/raw/ \
  --tests tests/ \
  --output results/
```

**Inputs**:
- `--raw`: Directory with raw scanner outputs from Stage 1
- `--tests`: Directory with original manifests

**Output**:
- `normalized_findings.json`: All findings with metadata
- `llm_payload.json`: Actionable findings for repair
- `buckets.csv`: Summary grouped by file/category

**When to use standalone**:
- You already have scanner outputs
- Testing normalization logic
- Analyzing findings without applying fixes

### Stage 3: Repair

**Purpose**: Generate security fixes using deterministic rules and LLMs

```bash
python pipeline.py --stage repair \
  --payload results/normalization/llm_payload.json \
  --tests tests/ \
  --output results/ \
  --models groq,gemini \
  --concurrency 5
```

**Inputs**:
- `--payload`: LLM payload from Stage 2
- `--tests`: Directory with original manifests
- `--models`: Comma-separated LLM providers
- `--concurrency`: Number of parallel requests

**Output**:
- `SECURED_*.yaml`: Fixed manifests
- `EXPLANATION_*.yaml.md`: Human-readable reports

**When to use standalone**:
- You already have normalized findings
- Testing different LLM configurations
- Re-running repairs without re-scanning

### Stage 4: Validation

**Purpose**: Validate that fixes are correct and don't introduce issues

```bash
python pipeline.py --stage validate \
  --tests tests/ \
  --fixed results/repair/ \
  --payload results/normalization/llm_payload.json \
  --output results/ \
  --strict
```

**Inputs**:
- `--tests`: Directory with original manifests
- `--fixed`: Directory with secured manifests from Stage 3
- `--payload`: LLM payload (optional, for detailed reporting)
- `--strict`: Enable strict mode

**Output**:
- `SUMMARY_VALIDATION.csv`: High-level validation summary
- `REPORT_VALIDATE_*.json`: Detailed validation reports

**When to use standalone**:
- Validating manually fixed manifests
- Re-running validation after adjustments
- Integration testing with deployment pipelines

---

## Configuration

### Environment Variables (.env)

**Complete Configuration Template**:

```bash
# ============================================================
# OpenRouter Configuration (Grok, Claude, etc.)
# ============================================================
OPENROUTER_API_KEY=sk-or-v1-your_key_here
OPENROUTER_MODEL=x-ai/grok-vision-beta
# Alternative models:
# - anthropic/claude-3.5-sonnet
# - google/gemini-2.0-flash-exp:free

# ============================================================
# Google Gemini Configuration
# ============================================================
GEMINI_API_KEY=AIzaSy_your_key_here
GEMINI_MODEL=gemini-2.0-flash-exp
# Alternative models:
# - gemini-1.5-pro
# - gemini-1.5-flash

# ============================================================
# Groq Configuration (Fast inference)
# ============================================================
GROQ_API_KEY=gsk_your_key_here
GROQ_MODEL=llama-3.1-70b-versatile
# Alternative models:
# - llama-3.1-8b-instant
# - mixtral-8x7b-32768

# ============================================================
# OpenAI Configuration
# ============================================================
OPENAI_API_KEY=sk-your_key_here
OPENAI_MODEL=gpt-4o-mini
# Alternative models:
# - gpt-4o
# - gpt-4-turbo
```

### Validation Configuration (validation_config.yaml)

Customize validation behavior in `Validations/validation_config.yaml`:

```yaml
# Schema validation
enable_kubeconform: true
enable_schema_autofix: true

# Parallel processing
enable_parallel_validation: true
max_workers: 4

# Strict mode settings
fail_on_needs_review: false
strict_mode: false

# Dangerous fields detection
dangerous_fields:
  - field: "spec.hostNetwork"
    expected: false
    severity: "HIGH"
  - field: "spec.hostPID"
    expected: false
    severity: "HIGH"

# Forbidden capabilities
forbidden_capabilities:
  - "SYS_ADMIN"
  - "NET_ADMIN"
  - "SYS_PTRACE"

# Trusted registries
trusted_registries:
  - "gcr.io"
  - "docker.io/library"
  - "quay.io"

# Category-specific validation rules
validation_rules:
  "Security/PrivilegedContainer":
    severity: "CRITICAL"
    validator: "privileged_false"
    description: "Ensure containers are not running in privileged mode"
  
  "Security/AllowPrivilegeEscalation":
    severity: "HIGH"
    validator: "privilege_escalation_false"
    description: "Prevent privilege escalation"
```

---

## Real-World Examples

### Example 1: Simple Web Application

**Scenario**: Secure a basic nginx deployment

**Input** (`tests/nginx.yaml`):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-web
spec:
  replicas: 2
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

**Command**:
```bash
python pipeline.py --input tests/ --output results/
```

**Output** (`results/repair/SECURED_nginx.yaml`):

The secured version will include:
- ✅ Non-root user execution
- ✅ Read-only root filesystem
- ✅ Dropped capabilities
- ✅ Resource limits
- ✅ Health probes
- ✅ Security contexts
- ✅ Seccomp and AppArmor profiles

### Example 2: Database StatefulSet

**Scenario**: Secure a PostgreSQL StatefulSet

**Input** (`tests/postgres.yaml`):
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_PASSWORD
          value: "mypassword123"  # Hardcoded secret!
```

**Command**:
```bash
python pipeline.py --input tests/ --output results/
```

**Key Fixes Applied**:
- 🔒 Extracts hardcoded password into Kubernetes Secret
- ✅ Adds security contexts
- ✅ Sets resource limits
- ✅ Adds liveness/readiness probes
- ✅ Configures proper volume mounts for writable paths

### Example 3: Microservices Architecture

**Scenario**: Secure multiple microservices

**Directory Structure**:
```
microservices/
├── frontend-deployment.yaml
├── backend-deployment.yaml
├── database-statefulset.yaml
├── cache-deployment.yaml
└── worker-deployment.yaml
```

**Command**:
```bash
python pipeline.py \
  --input microservices/ \
  --output results/microservices/ \
  --detection-mode extended \
  --models groq,gemini,openrouter \
  --concurrency 8 \
  --strict
```

**Benefits**:
- Processes all services in one run
- Extended mode for comprehensive scanning
- Multiple LLM providers for consensus
- Higher concurrency for faster processing
- Strict validation for production readiness

### Example 4: CI/CD Pipeline Integration

**Scenario**: Validate manifests in CI before deployment

**GitLab CI Example** (`.gitlab-ci.yml`):
```yaml
stages:
  - validate
  - deploy

kubernetes-security-check:
  stage: validate
  image: python:3.11
  services:
    - docker:dind
  before_script:
    - pip install -r requirements.txt
  script:
    - python pipeline.py --input k8s/ --output results/ --strict
  artifacts:
    paths:
      - results/
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

**GitHub Actions Example** (`.github/workflows/k8s-security.yml`):
```yaml
name: Kubernetes Security Check

on:
  pull_request:
    paths:
      - 'k8s/**/*.yaml'
  push:
    branches:
      - main

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run SafeFixK8s
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: |
          python pipeline.py \
            --input k8s/ \
            --output results/ \
            --strict \
            --detection-mode lean
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: results/
```

---

## Best Practices

### 1. Version Control Integration

**DO**:
```bash
# Store original manifests in version control
git add k8s/original/

# Review secured manifests before committing
diff k8s/original/deploy.yaml results/repair/SECURED_deploy.yaml

# Commit secured versions
git add k8s/secured/
git commit -m "Apply security hardening to deployments"
```

**DON'T**:
- Don't commit the `.env` file with API keys
- Don't blindly deploy secured manifests without review

### 2. Incremental Adoption

Start with non-critical workloads:
```bash
# Phase 1: Dev environment
python pipeline.py --input dev-manifests/ --output results/dev/

# Phase 2: Staging environment
python pipeline.py --input staging-manifests/ --output results/staging/

# Phase 3: Production (with strict mode)
python pipeline.py --input prod-manifests/ --output results/prod/ --strict
```

### 3. Manual Review Categories

Some categories require manual intervention:

**Network Policies**: 
```markdown
SafeFixK8s will NOT auto-generate NetworkPolicies because they require
application-specific knowledge. Review the normalization output and create
NetworkPolicies manually based on your architecture.
```

**Image Tags**:
```markdown
The `latest` tag will NOT be auto-updated to prevent breaking changes.
Pin versions in your CI/CD pipeline with vulnerability scanning.
```

### 4. Cost Optimization

Minimize LLM API costs:

```bash
# Use lean mode for faster scans
python pipeline.py --detection-mode lean

# Use single, cost-effective provider
python pipeline.py --models groq  # Free tier available

# Lower concurrency for small batches
python pipeline.py --concurrency 3
```

**Cost Breakdown** (approximate):
- Deterministic fixes: $0 (no LLM calls)
- Template-based fixes: ~$0.001 per fix
- LLM-guided fixes: ~$0.01 per fix

Most fixes (60-70%) are deterministic or template-based, keeping costs minimal.

### 5. Testing Secured Manifests

Before deploying to production:

```bash
# 1. Validate syntax
kubectl apply --dry-run=client -f results/repair/SECURED_*.yaml

# 2. Validate against cluster (without applying)
kubectl apply --dry-run=server -f results/repair/SECURED_*.yaml

# 3. Deploy to test namespace
kubectl apply -f results/repair/SECURED_*.yaml -n test

# 4. Monitor for issues
kubectl get pods -n test
kubectl logs -n test <pod-name>

# 5. Promote to production if successful
kubectl apply -f results/repair/SECURED_*.yaml -n production
```

---

## Troubleshooting

### Issue 1: Docker Permission Denied

**Symptom**:
```
ERROR: Got permission denied while trying to connect to Docker daemon
```

**Solution** (Linux):
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker ps
```

**Solution** (Windows):
- Ensure Docker Desktop is running
- Run PowerShell as Administrator if needed

### Issue 2: LLM API Rate Limits

**Symptom**:
```
ERROR: HTTP 429 - Rate limit exceeded for <provider>
```

**Solution**:
```bash
# Reduce concurrency
python pipeline.py --concurrency 2

# Use different provider
python pipeline.py --models gemini  # Switch from groq

# Add delays between requests (modify LLM orchestrator)
```

### Issue 3: Out of Memory

**Symptom**:
```
MemoryError: Unable to allocate array
```

**Solution**:
```bash
# Process fewer files at once
python pipeline.py --input small-batch/ --output results/

# Increase Docker memory limit (Docker Desktop Settings)
# Recommended: 8GB minimum

# Disable parallel validation
# Edit Validations/validation_config.yaml:
enable_parallel_validation: false
```

### Issue 4: PowerShell Execution Policy (Windows)

**Symptom**:
```
Cannot be loaded because running scripts is disabled on this system
```

**Solution**:
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verify
Get-ExecutionPolicy
```

### Issue 5: Schema Validation Failures

**Symptom**:
```
ERROR: Kubeconform validation failed
```

**Solution**:
```yaml
# Enable auto-fix in validation_config.yaml
enable_schema_autofix: true

# Or disable strict schema validation temporarily
enable_kubeconform: false
```

### Issue 6: Missing Scanner Outputs

**Symptom**:
```
ERROR: Expected 13 scanner outputs, found 8
```

**Solution**:
```bash
# Check Docker logs
docker logs <container-id>

# Verify internet connection (for image pulls)
docker pull bridgecrew/checkov:latest

# Run detection with verbose logging
python pipeline.py --stage detection --input tests/ --verbose
```

---

## CI/CD Integration

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        GROQ_API_KEY = credentials('groq-api-key')
    }
    
    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/yourorg/k8s-manifests.git'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    python3 pipeline.py \
                        --input k8s/ \
                        --output results/ \
                        --detection-mode lean \
                        --strict
                '''
            }
        }
        
        stage('Publish Results') {
            steps {
                publishHTML([
                    reportDir: 'results',
                    reportFiles: 'validation/SUMMARY_VALIDATION.csv',
                    reportName: 'Security Scan Results'
                ])
            }
        }
        
        stage('Deploy if Passed') {
            when {
                expression { 
                    return fileExists('results/validation/SUMMARY_VALIDATION.csv')
                }
            }
            steps {
                sh 'kubectl apply -f results/repair/'
            }
        }
    }
}
```

### Azure DevOps Pipeline

```yaml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - k8s/*

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'
    
- script: |
    pip install -r requirements.txt
  displayName: 'Install dependencies'

- script: |
    python pipeline.py \
      --input $(System.DefaultWorkingDirectory)/k8s \
      --output $(Build.ArtifactStagingDirectory)/results \
      --strict
  displayName: 'Run SafeFixK8s'
  env:
    GROQ_API_KEY: $(GROQ_API_KEY)

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)/results'
    artifactName: 'security-results'
```

---

## Performance Tuning

### Optimize for Speed

```bash
# Use lean mode
python pipeline.py --detection-mode lean

# Increase concurrency (if API limits allow)
python pipeline.py --concurrency 10

# Use fastest LLM provider
python pipeline.py --models groq
```

**Expected Performance**:
- Lean mode: 2-5 minutes for 10 manifests
- Extended mode: 5-10 minutes for 10 manifests

### Optimize for Quality

```bash
# Use extended mode
python pipeline.py --detection-mode extended

# Use multiple LLM providers
python pipeline.py --models openai,groq,gemini,openrouter

# Enable strict validation
python pipeline.py --strict
```

### Optimize for Cost

```bash
# Use lean mode (fewer scanner licenses if applicable)
python pipeline.py --detection-mode lean

# Use single free-tier LLM
python pipeline.py --models groq

# Lower concurrency (reduce API costs)
python pipeline.py --concurrency 3
```

### Resource Requirements

| Scenario | Manifests | Mode | Time | RAM | API Calls |
|----------|-----------|------|------|-----|-----------|
| Small | 1-5 | LEAN | 2-3 min | 4GB | ~10-20 |
| Medium | 10-20 | LEAN | 5-8 min | 8GB | ~50-100 |
| Large | 50+ | LEAN | 15-25 min | 16GB | ~200-500 |
| Audit | Any | EXTENDED | +50% | +2GB | +30% |

---

## Summary

SafeFixK8s is a powerful tool for automating Kubernetes security remediation. Key takeaways:

1. **Start Simple**: Use default settings for first runs
2. **Review Outputs**: Always review secured manifests before deploying
3. **Test First**: Deploy to non-production environments first
4. **Integrate Gradually**: Start with CI/CD validation, then auto-remediation
5. **Monitor Costs**: Most fixes are deterministic (free), but monitor LLM usage
6. **Stay Updated**: Review new security categories and scanner updates

For more information:
- [README.md](README.md) - Project overview
- [METHODOLOGY.md](METHODOLOGY.md) - Technical details
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute

---

**Need Help?** Open an issue on GitHub or consult the troubleshooting section above.
