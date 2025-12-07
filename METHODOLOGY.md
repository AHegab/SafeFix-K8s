# SafeFixK8s Pipeline Methodology

**Comprehensive Technical Documentation**

This document provides an in-depth explanation of the methodologies, methods, algorithms, and implementation approaches used in each layer of the SafeFixK8s pipeline.

## Table of Contents

1. [Pipeline Overview](#pipeline-overview)
2. [Stage 1: Detection Layer](#stage-1-detection-layer)
3. [Stage 2: Normalization Layer](#stage-2-normalization-layer)
4. [Stage 3: Repair Layer](#stage-3-repair-layer)
5. [Stage 4: Validation Layer](#stage-4-validation-layer)
6. [Cross-Cutting Concerns](#cross-cutting-concerns)
7. [Design Patterns and Algorithms](#design-patterns-and-algorithms)
8. [Performance Optimization](#performance-optimization)
9. [Error Handling and Resilience](#error-handling-and-resilience)

---

## Pipeline Overview

### Architectural Philosophy

SafeFixK8s implements a **multi-stage pipeline architecture** based on the following design principles:

1. **Separation of Concerns**: Each stage has a single, well-defined responsibility
2. **Data Flow Consistency**: Standardized input/output formats between stages
3. **Fail-Fast with Recovery**: Early validation with graceful degradation
4. **Deterministic Behavior**: Reproducible results given the same inputs
5. **Extensibility**: Easy to add new tools, categories, or fix strategies
6. **Observability**: Comprehensive logging and human-readable reports

### Pipeline State Machine

```
┌──────────┐     ┌───────────────┐     ┌────────┐     ┌────────────┐
│  INPUT   │────▶│  DETECTION    │────▶│ NORMAL │────▶│   REPAIR   │
│ Manifests│     │ (13 scanners) │     │  IZE   │     │ (LLM/Rules)│
└──────────┘     └───────────────┘     └────────┘     └────────────┘
                                                              │
                                                              ▼
                 ┌────────────┐     ┌─────────────────────────┐
                 │   OUTPUT   │◀────│     VALIDATION          │
                 │  Secured   │     │ (7-gate framework)      │
                 │ Manifests  │     └─────────────────────────┘
                 └────────────┘
```

Each stage is **independently executable**, allowing for:
- Incremental processing
- Stage-specific debugging
- Integration with external workflows
- Reuse of intermediate results

---

## Stage 1: Detection Layer

**Location**: `Detection/detectors.ps1`

**Responsibility**: Execute multiple security scanning tools and collect raw findings

### 1.1 Architecture and Design

#### Orchestration Strategy

The detection layer implements a **PowerShell-based orchestration** approach for several reasons:

1. **Cross-Platform Compatibility**: PowerShell Core runs on Windows, Linux, and macOS
2. **Docker Integration**: Native support for Docker CLI operations
3. **Parallel Execution**: Built-in job management for concurrent scanner execution
4. **Error Recovery**: Robust error handling with per-tool isolation

#### Tool Selection Methodology

**13 Tools** are integrated based on:

1. **Coverage Diversity**: Each tool focuses on different security aspects
   - Static analysis (Checkov, KubeLinter)
   - Policy enforcement (Conftest, OPA)
   - Comprehensive scanning (Trivy, Kubescape)
   - Best practices (Polaris, KubeScore)
   - Specialized detection (GitLeaks for secrets, Pluto for deprecations)

2. **Industry Adoption**: All tools are widely used in production environments

3. **Open Source**: All tools are open-source with active maintenance

4. **Output Standardization**: All tools support JSON output for parsing

### 1.2 Execution Modes

#### LEAN Mode (10 tools)
- **Target**: CI/CD pipelines, rapid iteration
- **Execution Time**: ~2-5 minutes
- **Tools**: Core security scanners
- **Use Case**: Continuous integration, development workflows

#### EXTENDED Mode (13 tools)
- **Target**: Security audits, compliance checks
- **Execution Time**: ~5-10 minutes
- **Tools**: All scanners including specialized ones (Pluto, GitLeaks, RBAC-Police)
- **Use Case**: Pre-deployment validation, security reviews

### 1.3 Tool Execution Strategy

#### Docker Containerization

All tools run in **isolated Docker containers** for:

1. **Reproducibility**: Consistent versions across environments
2. **Isolation**: Tool failures don't affect other scanners
3. **Portability**: No local installation required
4. **Version Control**: Pin specific tool versions for deterministic behavior

#### Execution Pattern (Per Tool)

```powershell
docker run --rm \
  -v <input-path>:/src \
  -v <output-path>:/output \
  <tool-image>:<version> \
  <tool-specific-args> \
  --output-format json \
  --output-file /output/<tool>_raw.json \
  /src
```

#### Parallel Execution

Tools are executed in **parallel groups** based on dependencies:

- **Group 1** (no dependencies): Checkov, Trivy, Polaris, KubeLinter, Kubeaudit
- **Group 2** (schema-dependent): Kubeconform
- **Group 3** (specialized): GitLeaks, Pluto, RBAC-Police

### 1.4 Output Format

Each tool produces a **raw JSON output** with tool-specific schema:

```
output/detection/raw/
├── checkov_raw.json        # Bridgecrew schema
├── trivy_raw.json          # Aqua Security schema
├── kubescape_raw.json      # ARMO schema
├── conftest_raw.json       # OPA policy violations
├── polaris_raw.json        # Fairwinds schema
├── kubelinter_raw.json     # StackRox schema
├── kubeaudit_raw.json      # Shopify schema
├── kubescore_raw.json      # KubeScore schema
├── kubeconform_raw.json    # Schema validation errors
├── yamllint_raw.json       # YAML linting issues
├── pluto_raw.json          # Deprecated API findings
├── gitleaks_raw.json       # Secret detection results
└── rbac_police_raw.json    # RBAC analysis
```

### 1.5 Error Handling

#### Tool Failure Isolation

Each tool runs in a **try-catch block** with:

1. **Individual Error Handling**: Tool failure doesn't stop the pipeline
2. **Fallback Reporting**: Empty JSON on failure for consistent parsing
3. **Logging**: Detailed error logs for debugging
4. **Status Tracking**: Per-tool success/failure metrics

#### Timeout Management

- **Per-tool timeout**: 10 minutes (configurable)
- **Action on timeout**: Log warning, mark as failed, continue with other tools

---

## Stage 2: Normalization Layer

**Location**: `Normalizer/normalizer.py` (1,968 lines)

**Responsibility**: Parse 13 different tool outputs and unify into a standardized schema

### 2.1 Core Challenges

1. **Schema Heterogeneity**: 13 different JSON formats
2. **Category Mapping**: 100+ tool-specific checks → 50+ standard categories
3. **Resource Resolution**: Match findings to specific Kubernetes resources
4. **False Positive Filtering**: Distinguish real issues from noise
5. **Consensus Scoring**: Aggregate findings from multiple tools

### 2.2 Architecture

#### Two-Phase Processing

**Phase 1: Parsing and Mapping**
```python
raw_findings = []
for tool in ["checkov", "trivy", "kubescape", ...]:
    parser = get_parser(tool)  # Tool-specific parser
    findings = parser.parse(raw_json)
    findings = parser.map_to_categories(findings)
    raw_findings.extend(findings)
```

**Phase 2: Aggregation and Filtering**
```python
buckets = aggregate_by_resource_and_category(raw_findings)
buckets = apply_false_positive_filtering(buckets)
buckets = calculate_consensus_scores(buckets)
normalized = finalize_output(buckets)
```

### 2.3 Category Taxonomy

#### 7 Category Families

The normalization layer organizes findings into **7 logical families**:

##### 1. PrivilegeHostNamespace
**Scope**: Container privilege escalation and host access

**Categories** (18):
- `Security/PrivilegedContainer`
- `Security/AllowPrivilegeEscalation`
- `Security/CapabilitiesAdded`
- `Security/CapabilitiesNotDropped`
- `Security/SeccompProfileMissing`
- `Security/ApparmorProfileMissing`
- `Security/ReadOnlyRootFilesystemFalse`
- `Security/HostPIDSharing`
- `Security/HostIPCSharing`
- `Security/HostNetworkSharing`
- `Security/HostPortMapping`
- `Security/HostPathVolume`
- `AuthZ/RunAsRootAllowed`
- `AuthZ/RunAsNonRootFalse`
- `AuthZ/EffectiveUserRoot`
- `AuthZ/SELinuxMissing`
- `AuthZ/FSGroupMissing`
- `AuthZ/SupplementalGroupsMissing`

**Methodology**: Focus on preventing container breakout and privilege escalation

##### 2. ResourceConfigDoS
**Scope**: Resource management and availability

**Categories** (8):
- `ResourceConfig/LimitsMissing`
- `ResourceConfig/RequestsMissing`
- `ResourceConfig/LivenessProbeMissing`
- `ResourceConfig/ReadinessProbeMissing`
- `ResourceConfig/StartupProbeMissing`
- `ResourceConfig/ReplicasSingle`
- `ResourceConfig/PodDisruptionBudgetMissing`
- `ResourceConfig/CPULimitHigh`

**Methodology**: Prevent resource exhaustion and ensure high availability

##### 3. ImageSupplyChain
**Scope**: Container image security

**Categories** (5):
- `ImageSupplyChain/ImageTagLatest`
- `ImageSupplyChain/ImagePullPolicyNotAlways`
- `ImageSupplyChain/ImageTagMissing`
- `ImageSupplyChain/ImageRegistryUntrusted`
- `ImageSupplyChain/ImageDigestMissing`

**Methodology**: Ensure reproducible, verified container images

##### 4. SecretsExposure
**Scope**: Credential and secret management

**Categories** (6):
- `Secrets/HardcodedPassword`
- `Secrets/HardcodedAPIKey`
- `Secrets/HardcodedToken`
- `Secrets/EnvironmentVarSensitive`
- `Secrets/SecretInConfigMap`
- `Secrets/SecretInPlainText`

**Methodology**: Prevent credential leakage using pattern matching and heuristics

##### 5. RBAC
**Scope**: Role-based access control

**Categories** (8):
- `RBAC/WildcardVerbs`
- `RBAC/WildcardResources`
- `RBAC/ClusterAdminBinding`
- `RBAC/PrivilegedRole`
- `RBAC/CreatePods`
- `RBAC/DeletePods`
- `RBAC/ExcessivePermissions`
- `AuthZ/ServiceAccountTokenAutoMount`

**Methodology**: Enforce least-privilege access

##### 6. NetworkExposureTLS
**Scope**: Network policies and encryption

**Categories** (5):
- `Network/NetworkPolicyMissing`
- `Network/IngressNoTLS`
- `Network/ServiceTypeLoadBalancer`
- `Network/ServiceTypeNodePort`
- `Network/ExternalIPExposure`

**Methodology**: Minimize attack surface and enforce encryption

##### 7. DeprecatedAPIIngress
**Scope**: Kubernetes API deprecations

**Categories** (4):
- `Deprecated/APIVersion`
- `Deprecated/IngressAPI`
- `Deprecated/PodSecurityPolicy`
- `Deprecated/DeprecatedField`

**Methodology**: Ensure compatibility with modern Kubernetes versions

### 2.4 Parsing Methodology (Per Tool)

#### Tool-Specific Parsers

Each tool has a **dedicated parser class** implementing:

```python
class ToolParser:
    def parse(self, raw_json: dict) -> List[Finding]:
        """Extract findings from tool-specific schema"""

    def map_category(self, tool_check_id: str) -> str:
        """Map tool check ID to standard category"""

    def extract_metadata(self, finding: dict) -> dict:
        """Extract file path, resource, severity, etc."""
```

#### Example: Checkov Parser

```python
def parse_checkov(raw_json: dict) -> List[Finding]:
    findings = []
    for result in raw_json.get("results", {}).get("failed_checks", []):
        finding = Finding(
            tool="checkov",
            check_id=result["check_id"],              # CKV_K8S_16
            category=map_checkov_to_category(result), # Security/PrivilegedContainer
            severity=result.get("severity", "MEDIUM"),
            file_path=result["file_path"],
            resource_type=result["resource_type"],    # Deployment
            resource_name=result["resource_name"],    # nginx
            description=result["check_name"],
            line_start=result.get("file_line_range", [0])[0]
        )
        findings.append(finding)
    return findings
```

#### Category Mapping Tables

Each parser uses **static mapping tables**:

```python
CHECKOV_CATEGORY_MAP = {
    "CKV_K8S_16": "Security/PrivilegedContainer",
    "CKV_K8S_20": "Security/AllowPrivilegeEscalation",
    "CKV_K8S_10": "Security/CapabilitiesNotDropped",
    "CKV_K8S_14": "Security/ReadOnlyRootFilesystemFalse",
    "CKV_K8S_8": "ResourceConfig/LivenessProbeMissing",
    "CKV_K8S_9": "ResourceConfig/ReadinessProbeMissing",
    "CKV_K8S_11": "ResourceConfig/LimitsMissing",
    # ... 50+ mappings
}
```

### 2.5 Resource Resolution Algorithm

#### Challenge: Matching Findings to Resources

Tools report findings in different ways:
- Some provide full resource path (e.g., `Deployment/nginx`)
- Some only provide file path (e.g., `deployment.yaml`)
- Some provide line numbers

#### Solution: Multi-Level Resolution

```python
def resolve_resource(finding: Finding, manifests: dict) -> Resource:
    """
    Resolve finding to specific Kubernetes resource using:
    1. Exact match (file + kind + name)
    2. File + kind match
    3. File-only match
    4. Line number matching
    """

    # Level 1: Exact match
    if finding.file and finding.kind and finding.name:
        return find_exact_resource(manifests, finding)

    # Level 2: File + kind
    if finding.file and finding.kind:
        return find_resource_by_file_and_kind(manifests, finding)

    # Level 3: File only (single resource per file)
    if finding.file:
        resources = manifests[finding.file]
        if len(resources) == 1:
            return resources[0]

    # Level 4: Line number matching
    if finding.line_start:
        return find_resource_by_line_number(manifests, finding)

    return None  # Unresolved
```

### 2.6 Aggregation and Bucketing

#### Bucket Definition

A **bucket** represents a unique combination of:
- File path
- Resource (kind + name + namespace)
- Category

```python
@dataclass
class Bucket:
    file: str
    resource_kind: str
    resource_name: str
    resource_namespace: str
    category: str
    severity: str          # Highest severity among findings
    tools: List[str]       # Tools that reported this issue
    count: int             # Number of findings
    score: float           # Consensus score (0.0-1.0)
    status: str            # "Actual" or "FalsePositive"
    findings: List[Finding]
```

#### Aggregation Algorithm

```python
def aggregate_findings(findings: List[Finding]) -> List[Bucket]:
    buckets = {}

    for finding in findings:
        # Create bucket key
        key = (
            finding.file,
            finding.resource_kind,
            finding.resource_name,
            finding.resource_namespace,
            finding.category
        )

        # Add to bucket
        if key not in buckets:
            buckets[key] = Bucket(...)

        bucket = buckets[key]
        bucket.tools.append(finding.tool)
        bucket.count += 1
        bucket.findings.append(finding)

        # Update severity (take highest)
        if severity_rank(finding.severity) > severity_rank(bucket.severity):
            bucket.severity = finding.severity

    return list(buckets.values())
```

### 2.7 Consensus Scoring

#### Methodology

**Consensus scoring** reduces false positives by weighing tool agreement:

```python
def calculate_consensus_score(bucket: Bucket) -> float:
    """
    Score = (weighted_tool_count) / (total_possible_weight)

    Tool weights:
    - Strong tools (authoritative): 0.3
    - Regular tools: 0.2
    - Weak tools (noisy): 0.1
    """

    # Define tool weights per category
    weights = get_tool_weights(bucket.category)

    # Calculate weighted score
    weighted_sum = sum(weights.get(tool, 0.1) for tool in bucket.tools)
    max_possible = sum(weights.values())

    return weighted_sum / max_possible if max_possible > 0 else 0.0
```

#### Strong Tool Mapping

Certain tools are **authoritative** for specific categories:

```python
STRONG_TOOL_MAP = {
    "Secrets/*": ["gitleaks"],                     # GitLeaks for secrets
    "RBAC/*": ["rbac-police", "kubeaudit"],       # RBAC specialists
    "Deprecated/*": ["pluto"],                     # Deprecation expert
    "Security/Privileged*": ["checkov", "trivy"], # Privilege escalation
    "Network/*": ["kubescape", "polaris"],        # Network policies
}
```

**Example**: If GitLeaks reports a secret, consensus score is higher than if only Checkov reports it.

### 2.8 False Positive Filtering

#### Strategy 1: Secret Detection Filtering

**Challenge**: Many false positives for secrets (e.g., "admin" as username)

**Solution**: Multi-layered heuristics

```python
def is_false_positive_secret(finding: Finding) -> bool:
    """
    Filter secrets using:
    1. Entropy check (randomness)
    2. Common word blacklist
    3. Format validation (e.g., UUID, JWT)
    4. Context analysis (variable names)
    """

    value = finding.secret_value

    # Check entropy (high randomness = likely secret)
    if calculate_entropy(value) < 3.5:
        return True  # Low entropy = likely false positive

    # Blacklist common words
    if value.lower() in ["admin", "user", "test", "example"]:
        return True

    # Check if it's a placeholder
    if value.startswith("$(") or value.startswith("${"):
        return True  # Environment variable reference

    return False
```

#### Strategy 2: RBAC Filtering

**Challenge**: RBAC findings when no RBAC manifests exist

**Solution**: Contextual filtering

```python
def filter_rbac_findings(buckets: List[Bucket], manifest_files: List[str]) -> List[Bucket]:
    """
    Remove RBAC findings if no RBAC manifests (Role, ClusterRole, RoleBinding)
    are present in the input.
    """

    rbac_kinds = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
    has_rbac = any(
        manifest.kind in rbac_kinds
        for manifest in parse_all_manifests(manifest_files)
    )

    if not has_rbac:
        return [b for b in buckets if not b.category.startswith("RBAC/")]

    return buckets
```

### 2.9 Output Generation

#### Output 1: normalized_findings.json

**Complete dataset** with all findings and metadata:

```json
{
  "summary": {
    "total_findings": 247,
    "total_buckets": 89,
    "files_analyzed": 12,
    "tools_run": 13
  },
  "findings": [
    {
      "id": "finding-001",
      "tool": "checkov",
      "check_id": "CKV_K8S_16",
      "category": "Security/PrivilegedContainer",
      "severity": "HIGH",
      "file": "deployment.yaml",
      "resource": {
        "kind": "Deployment",
        "name": "nginx",
        "namespace": "default"
      },
      "description": "Container runs as privileged",
      "line_number": 24,
      "timestamp": "2025-12-07T10:30:00Z"
    }
  ],
  "buckets": [...]
}
```

#### Output 2: llm_payload.json

**Filtered, actionable findings** for repair stage:

```json
{
  "files": [
    {
      "path": "deployment.yaml",
      "resources": [
        {
          "kind": "Deployment",
          "name": "nginx",
          "namespace": "default",
          "findings": [
            {
              "category": "Security/PrivilegedContainer",
              "severity": "HIGH",
              "tools": ["checkov", "trivy", "polaris"],
              "consensus_score": 0.85,
              "description": "Container runs as privileged",
              "fix_strategy": "DETERMINISTIC"
            }
          ]
        }
      ]
    }
  ]
}
```

**Filtering rules**:
- Exclude non-auto-fixable categories (e.g., `Network/NetworkPolicyMissing`)
- Exclude low-confidence findings (score < 0.3)
- Group by file and resource for efficient repair

#### Output 3: buckets.csv

**Summary for human review**:

```csv
File,Resource,Category,Severity,Tools,Count,Score,Status
deployment.yaml,Deployment/nginx,Security/PrivilegedContainer,HIGH,"checkov,trivy,polaris",3,0.85,Actual
deployment.yaml,Deployment/nginx,ResourceConfig/LimitsMissing,MEDIUM,"checkov,kubescape",2,0.60,Actual
```

---

## Stage 3: Repair Layer

**Location**: `LLMs/multi_llm_orchestrator.py` (2,176 lines)

**Responsibility**: Generate and apply security patches using hybrid approaches

### 3.1 Architecture and Design Philosophy

#### Hybrid Fix Strategy

The repair layer implements a **three-tier strategy**:

1. **DETERMINISTIC** (0 LLM tokens)
   - Rule-based patches for well-defined fixes
   - 100% reproducible
   - Examples: Remove privileged=true, set namespace, drop capabilities

2. **TEMPLATE** (minimal LLM tokens)
   - Smart templates with context-aware logic
   - Heuristic-based (e.g., probe port selection, resource calculation)
   - Examples: Health probes, resource limits

3. **LLM_GUIDED** (AI-assisted with fallback)
   - Complex security contexts requiring contextual understanding
   - Multi-LLM consensus for reliability
   - Fallback to templates if LLM fails

#### Design Principle: Deterministic First

**Rationale**:
- **Cost**: LLM API calls are expensive
- **Reliability**: Deterministic fixes are 100% consistent
- **Speed**: No API latency
- **Transparency**: Easy to audit and understand

**Result**: ~70% of fixes are deterministic, minimizing LLM usage.

### 3.2 Fix Strategy Mapping

#### Category → Strategy Mapping

```python
CATEGORY_FIX_STRATEGY = {
    # DETERMINISTIC (0 tokens)
    "Security/PrivilegedContainer": "DETERMINISTIC",
    "Security/AllowPrivilegeEscalation": "DETERMINISTIC",
    "Security/CapabilitiesNotDropped": "DETERMINISTIC",
    "Security/CapabilitiesAdded": "DETERMINISTIC",
    "Security/SeccompProfileMissing": "DETERMINISTIC",
    "Security/ApparmorProfileMissing": "DETERMINISTIC",
    "Security/ReadOnlyRootFilesystemFalse": "DETERMINISTIC",
    "AuthZ/RunAsRootAllowed": "DETERMINISTIC",
    "AuthZ/RunAsNonRootFalse": "DETERMINISTIC",
    "AuthZ/ServiceAccountTokenAutoMount": "DETERMINISTIC",
    "Namespace/NamespaceMissing": "DETERMINISTIC",
    "RBAC/WildcardVerbs": "DETERMINISTIC",
    "RBAC/WildcardResources": "DETERMINISTIC",

    # TEMPLATE (minimal tokens)
    "ResourceConfig/LivenessProbeMissing": "TEMPLATE",
    "ResourceConfig/ReadinessProbeMissing": "TEMPLATE",
    "ResourceConfig/LimitsMissing": "TEMPLATE",
    "ResourceConfig/RequestsMissing": "TEMPLATE",

    # LLM_GUIDED (with fallback)
    "Security/HostPathVolume": "LLM_GUIDED",
    "Secrets/HardcodedPassword": "LLM_GUIDED",

    # SKIP (requires manual intervention)
    "Network/NetworkPolicyMissing": "SKIP",
    "ImageSupplyChain/ImageTagLatest": "SKIP",
    "Deprecated/APIVersion": "SKIP"
}
```

### 3.3 Deterministic Fix Handlers

#### Handler: Comprehensive Security Hardening

**Challenge**: Multiple security controls must be applied **atomically** to avoid partial fixes.

**Solution**: Single handler applies all 4 controls together:

```python
def apply_comprehensive_security_hardening(manifest: dict, findings: List[Finding]) -> List[JSONPatch]:
    """
    Apply all 4 security controls atomically:
    1. allowPrivilegeEscalation: false
    2. capabilities.drop: [ALL]
    3. readOnlyRootFilesystem: true
    4. runAsNonRoot: true + runAsUser: 1000

    Also handles:
    - Pod-level security context
    - Container-level security context
    - Necessary volumes for read-only filesystem (tmp, cache, run)
    """

    patches = []

    # Pod-level security context
    patches.extend([
        {
            "op": "add",
            "path": "/spec/template/spec/securityContext",
            "value": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "seccompProfile": {"type": "RuntimeDefault"}
            }
        }
    ])

    # Container-level security contexts
    for i, container in enumerate(manifest["spec"]["template"]["spec"]["containers"]):
        patches.extend([
            {
                "op": "add",
                "path": f"/spec/template/spec/containers/{i}/securityContext",
                "value": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "readOnlyRootFilesystem": True,
                    "runAsNonRoot": True,
                    "runAsUser": 1000
                }
            }
        ])

    # Add volumes for writable paths (required for nginx, httpd, etc.)
    patches.extend(create_emptydir_volumes(manifest, ["tmp", "cache", "run"]))

    return patches
```

**Key Insight**: Applying controls together prevents inconsistent states (e.g., readOnlyRootFilesystem without writable volumes).

#### Handler: AppArmor Profile

**Challenge**: AppArmor is configured via **annotations**, not `securityContext`.

**Solution**: Special handler for annotations:

```python
def apply_apparmor_profile(manifest: dict, findings: List[Finding]) -> List[JSONPatch]:
    """
    AppArmor uses annotations:
    container.apparmor.security.beta.kubernetes.io/<container-name>: runtime/default
    """

    patches = []
    containers = manifest["spec"]["template"]["spec"]["containers"]

    for container in containers:
        annotation_key = f"container.apparmor.security.beta.kubernetes.io/{container['name']}"
        patches.append({
            "op": "add",
            "path": f"/spec/template/metadata/annotations/{annotation_key}",
            "value": "runtime/default"
        })

    return patches
```

#### Handler: RBAC Wildcard Cleanup

**Challenge**: Remove wildcard permissions from RBAC roles.

**Solution**: Replace wildcards with explicit verbs/resources:

```python
def fix_rbac_wildcards(manifest: dict, findings: List[Finding]) -> List[JSONPatch]:
    """
    Replace wildcard (*) with explicit permissions.

    Strategy:
    1. Identify wildcard verbs or resources
    2. Replace with minimal required permissions
    3. Apply least-privilege principle
    """

    patches = []

    for i, rule in enumerate(manifest.get("rules", [])):
        # Fix wildcard verbs
        if "*" in rule.get("verbs", []):
            patches.append({
                "op": "replace",
                "path": f"/rules/{i}/verbs",
                "value": ["get", "list", "watch"]  # Read-only by default
            })

        # Fix wildcard resources
        if "*" in rule.get("resources", []):
            patches.append({
                "op": "replace",
                "path": f"/rules/{i}/resources",
                "value": ["pods", "services"]  # Common safe resources
            })

    return patches
```

### 3.4 Template-Based Fix Handlers

#### Handler: Health Probes

**Challenge**: Probes need port and path information from the container.

**Solution**: Smart template with heuristics:

```python
def generate_health_probes(container: dict, manifest: dict) -> dict:
    """
    Generate liveness and readiness probes based on container configuration.

    Heuristics:
    1. Detect HTTP ports (80, 8080, 3000, 5000, etc.)
    2. Detect gRPC ports (9090, 50051, etc.)
    3. Detect TCP ports (any other port)
    4. Use common health check paths (/health, /healthz, /)
    """

    # Extract container ports
    ports = container.get("ports", [])

    # Find HTTP port
    http_port = None
    for port in ports:
        port_num = port.get("containerPort")
        if port_num in [80, 8080, 8000, 3000, 5000, 9000]:
            http_port = port_num
            break

    if http_port:
        # HTTP probe
        return {
            "livenessProbe": {
                "httpGet": {
                    "path": detect_health_path(container),  # /health, /healthz, /
                    "port": http_port
                },
                "initialDelaySeconds": 30,
                "periodSeconds": 10
            },
            "readinessProbe": {
                "httpGet": {
                    "path": detect_health_path(container),
                    "port": http_port
                },
                "initialDelaySeconds": 5,
                "periodSeconds": 5
            }
        }

    # Fallback: TCP probe
    if ports:
        return {
            "livenessProbe": {
                "tcpSocket": {"port": ports[0]["containerPort"]},
                "initialDelaySeconds": 30,
                "periodSeconds": 10
            },
            "readinessProbe": {
                "tcpSocket": {"port": ports[0]["containerPort"]},
                "initialDelaySeconds": 5,
                "periodSeconds": 5
            }
        }

    return None  # No ports defined, skip probes
```

**Path Detection Heuristic**:

```python
def detect_health_path(container: dict) -> str:
    """
    Detect health check path based on image name.
    """
    image = container.get("image", "").lower()

    if "nginx" in image or "httpd" in image or "apache" in image:
        return "/"
    elif "spring" in image or "java" in image:
        return "/actuator/health"
    elif "node" in image or "express" in image:
        return "/health"
    elif "django" in image or "flask" in image:
        return "/healthz"
    else:
        return "/"  # Default
```

#### Handler: Resource Limits and Requests

**Challenge**: Calculate reasonable resource values without LLM.

**Solution**: Heuristic-based scaling:

```python
def generate_resource_limits(container: dict) -> dict:
    """
    Generate resource requests and limits using 2x scaling factor.

    Strategy:
    1. Define base requests (conservative)
    2. Set limits = 2x requests
    3. Adjust based on container image (nginx vs. java)
    """

    image = container.get("image", "").lower()

    # Base values
    base_cpu = "250m"
    base_memory = "64Mi"

    # Adjust for known resource-heavy images
    if any(x in image for x in ["java", "jdk", "tomcat"]):
        base_cpu = "500m"
        base_memory = "256Mi"
    elif any(x in image for x in ["postgres", "mysql", "mongo"]):
        base_cpu = "500m"
        base_memory = "512Mi"

    return {
        "requests": {
            "cpu": base_cpu,
            "memory": base_memory
        },
        "limits": {
            "cpu": scale_cpu(base_cpu, 2),      # 2x requests
            "memory": scale_memory(base_memory, 2)
        }
    }
```

### 3.5 LLM-Guided Fix Generation

#### Multi-LLM Consensus Architecture

**Challenge**: Single LLM may produce unreliable patches.

**Solution**: Multi-LLM consensus with voting:

```python
async def generate_llm_fix(finding: Finding, manifest: dict, models: List[str]) -> JSONPatch:
    """
    Query multiple LLMs and use consensus voting.

    Process:
    1. Send identical prompt to 3 LLMs (e.g., GPT-4o-mini, Llama, Gemini)
    2. Parse JSON patch responses
    3. Vote on patch operations (majority wins)
    4. Fallback to template if consensus fails
    """

    # Parallel LLM requests
    responses = await asyncio.gather(*[
        query_llm(model, finding, manifest)
        for model in models
    ])

    # Parse patches
    patches = [parse_json_patch(r) for r in responses if r is not None]

    # Consensus voting
    if len(patches) >= 2:
        consensus_patch = vote_on_patches(patches)
        return consensus_patch

    # Fallback to template
    return fallback_template_fix(finding, manifest)
```

#### Prompt Engineering

**Structured prompt** for consistent LLM responses:

```python
def build_llm_prompt(finding: Finding, manifest: dict) -> str:
    return f"""
You are a Kubernetes security expert. Fix the following security issue.

SECURITY ISSUE:
Category: {finding.category}
Severity: {finding.severity}
Description: {finding.description}

CURRENT MANIFEST:
```yaml
{yaml.dump(manifest)}
```

INSTRUCTIONS:
1. Generate a JSON Patch (RFC-6902) to fix this issue
2. Use ONLY these operations: add, replace, remove
3. Do NOT modify: image, metadata.name, metadata.namespace, selectors
4. Ensure the fix is production-safe and doesn't break workload functionality

OUTPUT FORMAT (JSON):
{{
  "patches": [
    {{"op": "add", "path": "/spec/...", "value": ...}}
  ],
  "explanation": "Brief explanation of the fix"
}}
"""
```

#### LLM Provider Fallback Chain

**Resilience strategy**:

```python
LLM_FALLBACK_CHAIN = [
    "groq",         # Fast, free tier
    "openrouter",   # Grok Vision, reliable
    "gemini",       # Google, good for structured output
    "openai"        # GPT-4o-mini, high quality (expensive)
]

async def query_with_fallback(prompt: str, models: List[str]) -> str:
    """
    Try LLMs in order until one succeeds.
    """
    for model in models:
        try:
            response = await call_llm_api(model, prompt)
            if validate_response(response):
                return response
        except Exception as e:
            logger.warning(f"LLM {model} failed: {e}")
            continue

    raise Exception("All LLM providers failed")
```

### 3.6 JSON Patch Application

#### RFC-6902 Standard

All fixes are represented as **JSON Patch operations**:

```json
[
  {
    "op": "add",
    "path": "/spec/template/spec/securityContext",
    "value": {"runAsNonRoot": true, "runAsUser": 1000}
  },
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
    "value": false
  },
  {
    "op": "remove",
    "path": "/spec/template/spec/containers/0/securityContext/privileged"
  }
]
```

#### Safe Application Algorithm

```python
def apply_json_patch(manifest: dict, patches: List[JSONPatch]) -> dict:
    """
    Apply JSON Patch operations with validation.

    Safety checks:
    1. Validate path exists (for replace/remove)
    2. Prevent modification of protected fields
    3. Ensure YAML structure remains valid
    4. Rollback on error
    """

    # Create deep copy (immutability)
    result = copy.deepcopy(manifest)

    # Protected paths (never modify)
    protected = [
        "/metadata/name",
        "/metadata/namespace",
        "/spec/selector",
        "/spec/template/spec/containers/*/image"  # Image registry changes require CI/CD
    ]

    for patch in patches:
        # Validate path
        if is_protected_path(patch["path"], protected):
            logger.warning(f"Skipping protected path: {patch['path']}")
            continue

        # Apply operation
        try:
            if patch["op"] == "add":
                apply_add(result, patch["path"], patch["value"])
            elif patch["op"] == "replace":
                apply_replace(result, patch["path"], patch["value"])
            elif patch["op"] == "remove":
                apply_remove(result, patch["path"])
        except Exception as e:
            logger.error(f"Patch application failed: {e}")
            return manifest  # Rollback to original

    return result
```

### 3.7 Patch Deduplication and Filtering

#### Challenge: Multiple findings may produce overlapping patches

**Solution**: Deduplication and conflict resolution:

```python
def deduplicate_patches(patches: List[JSONPatch]) -> List[JSONPatch]:
    """
    Remove duplicate and conflicting patches.

    Rules:
    1. Same path + same operation → keep one
    2. Same path + different operations → keep last (replace > add > remove)
    3. Parent-child paths → keep child (more specific)
    """

    # Group by path
    by_path = {}
    for patch in patches:
        path = patch["path"]
        if path not in by_path:
            by_path[path] = []
        by_path[path].append(patch)

    # Resolve conflicts
    deduplicated = []
    for path, path_patches in by_path.items():
        # Priority: replace > add > remove
        priority = {"replace": 3, "add": 2, "remove": 1}
        best = max(path_patches, key=lambda p: priority[p["op"]])
        deduplicated.append(best)

    return deduplicated
```

#### Dangerous Patch Filtering

**Prevent breaking changes**:

```python
def filter_dangerous_patches(patches: List[JSONPatch], manifest: dict) -> List[JSONPatch]:
    """
    Remove patches that could break the workload.

    Dangerous operations:
    1. Changing image (requires testing)
    2. Modifying selectors (breaks Service matching)
    3. Removing essential fields (e.g., ports)
    4. Adding forbidden capabilities
    """

    safe_patches = []

    for patch in patches:
        # Block image changes
        if "/image" in patch["path"]:
            logger.warning("Skipping image modification")
            continue

        # Block selector changes
        if "/selector" in patch["path"]:
            logger.warning("Skipping selector modification")
            continue

        # Block forbidden capabilities
        if patch["op"] == "add" and "/capabilities/add" in patch["path"]:
            forbidden = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
            if any(cap in patch["value"] for cap in forbidden):
                logger.warning(f"Skipping forbidden capability: {patch['value']}")
                continue

        safe_patches.append(patch)

    return safe_patches
```

### 3.8 Security Context Sanitization

#### Challenge: Invalid security context combinations

**Solution**: Post-patch sanitization:

```python
def sanitize_security_context(manifest: dict) -> dict:
    """
    Remove invalid security context fields and resolve conflicts.

    Invalid combinations:
    1. privileged=true + allowPrivilegeEscalation=false
    2. runAsNonRoot=true + runAsUser=0
    3. readOnlyRootFilesystem=true without writable volumes
    """

    # Pod-level sanitization
    pod_sec_ctx = manifest["spec"]["template"]["spec"].get("securityContext", {})

    # Remove privileged if allowPrivilegeEscalation=false
    if not pod_sec_ctx.get("allowPrivilegeEscalation", True):
        pod_sec_ctx.pop("privileged", None)

    # Ensure runAsUser != 0 if runAsNonRoot=true
    if pod_sec_ctx.get("runAsNonRoot") and pod_sec_ctx.get("runAsUser") == 0:
        pod_sec_ctx["runAsUser"] = 1000

    # Container-level sanitization
    for container in manifest["spec"]["template"]["spec"]["containers"]:
        cont_sec_ctx = container.get("securityContext", {})

        # Same checks as pod-level
        if not cont_sec_ctx.get("allowPrivilegeEscalation", True):
            cont_sec_ctx.pop("privileged", None)

        if cont_sec_ctx.get("runAsNonRoot") and cont_sec_ctx.get("runAsUser") == 0:
            cont_sec_ctx["runAsUser"] = 1000

    return manifest
```

### 3.9 Output Generation

#### Output 1: SECURED_*.yaml

**Fixed Kubernetes manifest**:

```yaml
# SECURED_deployment.yaml
# Original: deployment.yaml
# Fixed by SafeFixK8s on 2025-12-07 10:45:00

apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  annotations:
    safefixk8s.io/original-file: "deployment.yaml"
    safefixk8s.io/fix-timestamp: "2025-12-07T10:45:00Z"
    safefixk8s.io/categories-fixed: "Security/PrivilegedContainer,AuthZ/RunAsRootAllowed,..."
spec:
  # ... secured configuration
```

#### Output 2: EXPLANATION_*.yaml.md

**Human-readable explanation**:

```markdown
# Security Fixes Applied to deployment.yaml

## File Information
- **Original**: deployment.yaml
- **Secured**: SECURED_deployment.yaml
- **Timestamp**: 2025-12-07 10:45:00
- **Pipeline Version**: 1.0.0

## Summary
Applied 12 security fixes across 5 categories:
- 4 HIGH severity issues
- 6 MEDIUM severity issues
- 2 LOW severity issues

## Detailed Fixes

### 1. Security/PrivilegedContainer (HIGH)
**Issue**: Container runs with privileged=true, allowing full host access
**Fix**: Removed privileged flag and set allowPrivilegeEscalation=false
**Impact**: Container now runs with reduced privileges, cannot escalate

### 2. AuthZ/RunAsRootAllowed (HIGH)
**Issue**: Container runs as root user (UID 0)
**Fix**: Set runAsNonRoot=true and runAsUser=1000
**Impact**: Container runs as non-root user, reducing attack surface

...

## Categories Not Fixed (Manual Review Required)

### ImageSupplyChain/ImageTagLatest
**Reason**: Changing image tags requires CI/CD integration and testing
**Recommendation**: Pin to specific version (e.g., nginx:1.25.3-alpine)

## Validation Status
All fixes have been validated and are production-ready.
```

---

## Stage 4: Validation Layer

**Location**: `Validations/validation_gates_improved.py` (1,409 lines)

**Responsibility**: Validate fixed manifests through a 7-gate framework

### 4.1 Architecture: 7-Gate Framework

**Philosophy**: Multi-layered validation catches different types of issues

```
┌──────────────────────────────────────────────────────┐
│ Gate 1: YAML Parsing                                 │
│  - Syntax validation                                 │
│  - Multi-document YAML support                       │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ Gate 2: Schema Auto-Fix                              │
│  - Missing required fields (e.g., selector)          │
│  - Automatic schema correction                       │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ Gate 3: Dangerous Configuration Check                │
│  - Privileged containers                             │
│  - Forbidden capabilities                            │
│  - Suspicious hostPath mounts                        │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ Gate 4: Category Validators                          │
│  - 20+ security category checks                      │
│  - Severity-based rules                              │
│  - Per-category validation logic                     │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ Gate 5: Effective Security Context Resolution        │
│  - Merge pod + container contexts                    │
│  - Validate effective permissions                    │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ Gate 6: Kubeconform Schema Validation (Optional)     │
│  - Kubernetes API schema validation                  │
│  - Version-specific checks                           │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ Gate 7: Diff Analysis                                │
│  - Compare original vs. secured                      │
│  - Document changes                                  │
└──────────────────────────────────────────────────────┘
                        ↓
                 ┌──────────┐
                 │  RESULT  │
                 │ PASS/FAIL│
                 └──────────┘
```

### 4.2 Gate 1: YAML Parsing

**Purpose**: Ensure fixed manifests are valid YAML

```python
def gate1_yaml_parsing(file_path: str) -> Tuple[bool, List[dict], str]:
    """
    Parse YAML and handle multi-document files.

    Returns:
        (success, manifests, error_message)
    """
    try:
        with open(file_path, 'r') as f:
            manifests = list(yaml.safe_load_all(f))

        # Filter None (empty documents)
        manifests = [m for m in manifests if m is not None]

        if not manifests:
            return False, [], "No valid YAML documents found"

        return True, manifests, ""

    except yaml.YAMLError as e:
        return False, [], f"YAML syntax error: {e}"
```

### 4.3 Gate 2: Schema Auto-Fix

**Purpose**: Automatically fix common Kubernetes API schema issues

**Common Issues**:
1. Deployment missing `spec.selector`
2. Service missing `spec.selector`
3. Invalid apiVersion format
4. Missing required metadata

```python
def gate2_schema_autofix(manifest: dict) -> Tuple[dict, List[str]]:
    """
    Auto-fix common schema issues.

    Returns:
        (fixed_manifest, list_of_fixes_applied)
    """
    fixes = []

    # Fix 1: Deployment selector
    if manifest["kind"] == "Deployment":
        if "selector" not in manifest.get("spec", {}):
            # Infer selector from template labels
            labels = manifest["spec"]["template"]["metadata"].get("labels", {})
            manifest["spec"]["selector"] = {"matchLabels": labels}
            fixes.append("Added missing spec.selector from template labels")

    # Fix 2: Service selector
    if manifest["kind"] == "Service":
        if "selector" not in manifest.get("spec", {}):
            # Cannot auto-fix (requires external knowledge)
            fixes.append("WARNING: Service missing selector (manual fix required)")

    # Fix 3: apiVersion format
    if "apiVersion" in manifest:
        if "/" not in manifest["apiVersion"] and manifest["kind"] not in ["Pod", "Service", "Namespace"]:
            # Add default group (e.g., "Deployment" → "apps/v1")
            manifest["apiVersion"] = infer_api_version(manifest["kind"])
            fixes.append(f"Fixed apiVersion to {manifest['apiVersion']}")

    return manifest, fixes
```

### 4.4 Gate 3: Dangerous Configuration Check

**Purpose**: Block manifests with critical security violations

**Blocking Conditions**:

```python
def gate3_dangerous_config_check(manifest: dict) -> Tuple[bool, List[str]]:
    """
    Check for dangerous configurations that should fail validation.

    Returns:
        (passed, list_of_violations)
    """
    violations = []

    # Check 1: Privileged containers
    for container in get_containers(manifest):
        if container.get("securityContext", {}).get("privileged"):
            violations.append(f"Container {container['name']} is privileged (CRITICAL)")

    # Check 2: Forbidden capabilities
    forbidden_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"]
    for container in get_containers(manifest):
        caps = container.get("securityContext", {}).get("capabilities", {}).get("add", [])
        for cap in caps:
            if cap in forbidden_caps:
                violations.append(f"Container {container['name']} has forbidden capability {cap}")

    # Check 3: Suspicious hostPath
    suspicious_paths = ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys"]
    for volume in manifest.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", []):
        if "hostPath" in volume:
            path = volume["hostPath"]["path"]
            if path in suspicious_paths or path.startswith("/etc/"):
                violations.append(f"Suspicious hostPath mount: {path}")

    # Check 4: Host namespaces
    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    if pod_spec.get("hostPID"):
        violations.append("hostPID=true (allows access to host processes)")
    if pod_spec.get("hostIPC"):
        violations.append("hostIPC=true (allows access to host IPC)")
    if pod_spec.get("hostNetwork"):
        violations.append("hostNetwork=true (uses host network namespace)")

    return len(violations) == 0, violations
```

### 4.5 Gate 4: Category Validators

**Purpose**: Validate that specific security categories were properly fixed

**Validator Architecture**:

```python
class CategoryValidator:
    """
    Base class for category-specific validators.
    """

    def __init__(self, category: str, severity: str):
        self.category = category
        self.severity = severity

    def validate(self, manifest: dict, finding: Finding) -> ValidationResult:
        """
        Validate that the finding was properly fixed.

        Returns ValidationResult with:
        - passed: bool
        - message: str
        - severity: str
        """
        raise NotImplementedError
```

**Example Validators**:

#### Validator: Security/PrivilegedContainer

```python
class PrivilegedContainerValidator(CategoryValidator):
    def validate(self, manifest: dict, finding: Finding) -> ValidationResult:
        """
        Ensure no container has privileged=true
        """
        for container in get_containers(manifest):
            if container.get("securityContext", {}).get("privileged"):
                return ValidationResult(
                    passed=False,
                    message=f"Container {container['name']} still privileged",
                    severity="CRITICAL"
                )

        return ValidationResult(
            passed=True,
            message="No privileged containers found",
            severity="PASS"
        )
```

#### Validator: Security/AllowPrivilegeEscalation

```python
class AllowPrivilegeEscalationValidator(CategoryValidator):
    def validate(self, manifest: dict, finding: Finding) -> ValidationResult:
        """
        Ensure allowPrivilegeEscalation=false for all containers
        """
        for container in get_containers(manifest):
            ape = container.get("securityContext", {}).get("allowPrivilegeEscalation")

            # Must be explicitly false
            if ape is None or ape is True:
                return ValidationResult(
                    passed=False,
                    message=f"Container {container['name']} allowPrivilegeEscalation not set to false",
                    severity="HIGH"
                )

        return ValidationResult(
            passed=True,
            message="All containers have allowPrivilegeEscalation=false",
            severity="PASS"
        )
```

#### Validator: Security/CapabilitiesNotDropped

```python
class CapabilitiesValidator(CategoryValidator):
    def validate(self, manifest: dict, finding: Finding) -> ValidationResult:
        """
        Ensure capabilities are dropped (ideally ALL)
        """
        for container in get_containers(manifest):
            caps = container.get("securityContext", {}).get("capabilities", {})
            drop = caps.get("drop", [])

            # Best practice: drop ALL
            if "ALL" not in drop:
                return ValidationResult(
                    passed=False,
                    message=f"Container {container['name']} does not drop ALL capabilities",
                    severity="MEDIUM"
                )

        return ValidationResult(
            passed=True,
            message="All containers drop ALL capabilities",
            severity="PASS"
        )
```

#### Validator: ResourceConfig/LimitsMissing

```python
class ResourceLimitsValidator(CategoryValidator):
    def validate(self, manifest: dict, finding: Finding) -> ValidationResult:
        """
        Ensure resource limits are defined
        """
        for container in get_containers(manifest):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})

            if not limits.get("memory") or not limits.get("cpu"):
                return ValidationResult(
                    passed=False,
                    message=f"Container {container['name']} missing resource limits",
                    severity="MEDIUM"
                )

        return ValidationResult(
            passed=True,
            message="All containers have resource limits",
            severity="PASS"
        )
```

**Validation Mapping**:

```python
CATEGORY_VALIDATORS = {
    "Security/PrivilegedContainer": PrivilegedContainerValidator,
    "Security/AllowPrivilegeEscalation": AllowPrivilegeEscalationValidator,
    "Security/CapabilitiesNotDropped": CapabilitiesValidator,
    "Security/CapabilitiesAdded": CapabilitiesValidator,
    "Security/SeccompProfileMissing": SeccompValidator,
    "Security/ApparmorProfileMissing": ApparmorValidator,
    "Security/ReadOnlyRootFilesystemFalse": ReadOnlyRootFSValidator,
    "AuthZ/RunAsRootAllowed": RunAsRootValidator,
    "ResourceConfig/LimitsMissing": ResourceLimitsValidator,
    "ResourceConfig/RequestsMissing": ResourceRequestsValidator,
    "ResourceConfig/LivenessProbeMissing": LivenessProbeValidator,
    "ResourceConfig/ReadinessProbeMissing": ReadinessProbeValidator,
    # ... 20+ total validators
}
```

### 4.6 Gate 5: Effective Security Context Resolution

**Purpose**: Validate the **effective** security context by merging pod and container contexts

**Challenge**: Security contexts can be defined at both pod and container level. Container settings override pod settings.

**Solution**: Context merging algorithm:

```python
def gate5_effective_context_resolution(manifest: dict) -> dict:
    """
    Resolve effective security context for each container.

    Rules:
    1. Container context overrides pod context
    2. If field not set in container, inherit from pod
    3. Some fields only exist at pod level (fsGroup, seccompProfile)
    """

    pod_sec_ctx = manifest.get("spec", {}).get("template", {}).get("spec", {}).get("securityContext", {})

    effective_contexts = {}

    for container in get_containers(manifest):
        cont_sec_ctx = container.get("securityContext", {})

        # Merge contexts
        effective = {
            # Pod-only fields
            "fsGroup": pod_sec_ctx.get("fsGroup"),
            "fsGroupChangePolicy": pod_sec_ctx.get("fsGroupChangePolicy"),
            "supplementalGroups": pod_sec_ctx.get("supplementalGroups"),

            # Container overrides pod
            "runAsUser": cont_sec_ctx.get("runAsUser", pod_sec_ctx.get("runAsUser")),
            "runAsGroup": cont_sec_ctx.get("runAsGroup", pod_sec_ctx.get("runAsGroup")),
            "runAsNonRoot": cont_sec_ctx.get("runAsNonRoot", pod_sec_ctx.get("runAsNonRoot")),

            # Container-specific
            "allowPrivilegeEscalation": cont_sec_ctx.get("allowPrivilegeEscalation"),
            "capabilities": cont_sec_ctx.get("capabilities"),
            "privileged": cont_sec_ctx.get("privileged"),
            "readOnlyRootFilesystem": cont_sec_ctx.get("readOnlyRootFilesystem"),

            # Seccomp/AppArmor (complex inheritance)
            "seccompProfile": resolve_seccomp(cont_sec_ctx, pod_sec_ctx),
        }

        effective_contexts[container["name"]] = effective

    return effective_contexts
```

**Validation using effective context**:

```python
def validate_effective_context(effective_ctx: dict, container_name: str) -> List[ValidationResult]:
    """
    Validate based on effective (merged) context.
    """
    results = []

    # Check runAsNonRoot
    if not effective_ctx.get("runAsNonRoot"):
        results.append(ValidationResult(
            passed=False,
            message=f"Container {container_name} effective runAsNonRoot is not true",
            severity="HIGH"
        ))

    # Check runAsUser != 0
    if effective_ctx.get("runAsUser") == 0:
        results.append(ValidationResult(
            passed=False,
            message=f"Container {container_name} effective runAsUser is 0 (root)",
            severity="HIGH"
        ))

    # Check allowPrivilegeEscalation
    if effective_ctx.get("allowPrivilegeEscalation") is not False:
        results.append(ValidationResult(
            passed=False,
            message=f"Container {container_name} allowPrivilegeEscalation not explicitly false",
            severity="HIGH"
        ))

    return results
```

### 4.7 Gate 6: Kubeconform Integration (Optional)

**Purpose**: Validate against Kubernetes API schemas

**Integration**:

```python
def gate6_kubeconform_validation(manifest_file: str, k8s_version: str = "1.28.0") -> Tuple[bool, str]:
    """
    Run kubeconform to validate Kubernetes schema.

    External tool: kubeconform (https://github.com/yannh/kubeconform)
    """

    cmd = [
        "kubeconform",
        "-strict",                     # Strict mode
        "-kubernetes-version", k8s_version,
        "-schema-location", "default",  # Use default schema registry
        "-summary",
        manifest_file
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return True, "Schema validation passed"
        else:
            return False, result.stderr

    except FileNotFoundError:
        # Kubeconform not installed, skip
        return True, "Kubeconform not available (skipped)"
    except Exception as e:
        return False, f"Kubeconform error: {e}"
```

### 4.8 Gate 7: Diff Analysis

**Purpose**: Document changes between original and secured manifests

**Algorithm**:

```python
def gate7_diff_analysis(original_file: str, secured_file: str) -> dict:
    """
    Generate detailed diff between original and secured manifests.

    Returns:
        {
            "fields_added": [...],
            "fields_modified": [...],
            "fields_removed": [...],
            "summary": "..."
        }
    """

    original = yaml.safe_load(open(original_file))
    secured = yaml.safe_load(open(secured_file))

    diff = {
        "fields_added": [],
        "fields_modified": [],
        "fields_removed": []
    }

    # Deep comparison
    compare_dicts(original, secured, "", diff)

    # Generate summary
    diff["summary"] = f"""
    Added {len(diff['fields_added'])} fields
    Modified {len(diff['fields_modified'])} fields
    Removed {len(diff['fields_removed'])} fields
    """

    return diff

def compare_dicts(original: dict, secured: dict, path: str, diff: dict):
    """
    Recursively compare two dictionaries.
    """
    # Fields in secured but not in original
    for key in secured:
        new_path = f"{path}/{key}" if path else key

        if key not in original:
            diff["fields_added"].append(new_path)
        elif isinstance(secured[key], dict) and isinstance(original[key], dict):
            compare_dicts(original[key], secured[key], new_path, diff)
        elif secured[key] != original[key]:
            diff["fields_modified"].append({
                "path": new_path,
                "old": original[key],
                "new": secured[key]
            })

    # Fields in original but not in secured
    for key in original:
        if key not in secured:
            new_path = f"{path}/{key}" if path else key
            diff["fields_removed"].append(new_path)
```

### 4.9 Overall Validation Status

**Status Determination**:

```python
def determine_overall_status(gate_results: dict) -> str:
    """
    Determine overall validation status based on all gates.

    Status:
    - PASS: All gates passed, no critical/high issues
    - NEEDS_REVIEW: Some medium/low issues or warnings
    - FAIL: Critical/high issues present
    """

    # Check for gate failures
    if not gate_results["gate1_yaml_parsing"]["passed"]:
        return "FAIL"

    if not gate_results["gate3_dangerous_config"]["passed"]:
        return "FAIL"

    # Count violations by severity
    violations = gate_results["gate4_category_validators"]["violations"]

    critical_count = sum(1 for v in violations if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in violations if v["severity"] == "HIGH")
    medium_count = sum(1 for v in violations if v["severity"] == "MEDIUM")

    if critical_count > 0 or high_count > 0:
        return "FAIL"
    elif medium_count > 0:
        return "NEEDS_REVIEW"
    else:
        return "PASS"
```

### 4.10 Output Generation

#### Output 1: SUMMARY_VALIDATION.csv

**High-level summary**:

```csv
File,Status,Critical,High,Medium,Low,Message
SECURED_deployment.yaml,PASS,0,0,0,0,All validations passed
SECURED_service.yaml,NEEDS_REVIEW,0,0,2,1,Resource limits recommended
SECURED_pod.yaml,FAIL,1,2,3,0,Privileged container detected
```

#### Output 2: REPORT_VALIDATE_*.json

**Detailed validation report**:

```json
{
  "file": "SECURED_deployment.yaml",
  "original_file": "deployment.yaml",
  "timestamp": "2025-12-07T11:00:00Z",
  "overall_status": "PASS",
  "gates": {
    "gate1_yaml_parsing": {
      "passed": true,
      "message": "Valid YAML"
    },
    "gate2_schema_autofix": {
      "fixes_applied": ["Added missing spec.selector"],
      "warnings": []
    },
    "gate3_dangerous_config": {
      "passed": true,
      "violations": []
    },
    "gate4_category_validators": {
      "total_categories": 12,
      "passed": 12,
      "failed": 0,
      "violations": []
    },
    "gate5_effective_context": {
      "containers": {
        "nginx": {
          "runAsNonRoot": true,
          "runAsUser": 1000,
          "allowPrivilegeEscalation": false,
          "capabilities": {"drop": ["ALL"]}
        }
      }
    },
    "gate6_kubeconform": {
      "passed": true,
      "message": "Schema validation passed"
    },
    "gate7_diff": {
      "fields_added": [
        "/spec/template/spec/securityContext",
        "/spec/template/spec/containers/0/securityContext"
      ],
      "fields_modified": [],
      "fields_removed": []
    }
  },
  "human_summary": "All security validations passed. Manifest is production-ready."
}
```

**Human Summary Generation**:

```python
def generate_human_summary(validation_results: dict) -> str:
    """
    Generate human-readable summary for the validation report.
    """

    status = validation_results["overall_status"]

    if status == "PASS":
        return "All security validations passed. Manifest is production-ready."

    elif status == "NEEDS_REVIEW":
        violations = validation_results["gates"]["gate4_category_validators"]["violations"]
        medium = [v for v in violations if v["severity"] == "MEDIUM"]
        return f"Manifest mostly secure. {len(medium)} medium-severity issues require review."

    elif status == "FAIL":
        violations = validation_results["gates"]["gate4_category_validators"]["violations"]
        critical = [v for v in violations if v["severity"] == "CRITICAL"]
        high = [v for v in violations if v["severity"] == "HIGH"]

        summary = f"Validation failed: {len(critical)} critical, {len(high)} high severity issues.\n\n"

        # List top 3 issues
        for v in (critical + high)[:3]:
            summary += f"- [{v['severity']}] {v['category']}: {v['message']}\n"

        return summary
```

---

## Cross-Cutting Concerns

### 5.1 Logging and Observability

**Multi-Level Logging**:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.FileHandler("output/pipeline.log"),
        logging.StreamHandler()
    ]
)

# Stage-specific loggers
detection_logger = logging.getLogger("detection")
normalization_logger = logging.getLogger("normalization")
repair_logger = logging.getLogger("repair")
validation_logger = logging.getLogger("validation")
```

**Structured Logging**:

```python
def log_stage_start(stage_name: str, input_path: str):
    logger.info(f"{'='*60}")
    logger.info(f"STAGE: {stage_name}")
    logger.info(f"Input: {input_path}")
    logger.info(f"{'='*60}")

def log_stage_end(stage_name: str, duration: float, success: bool):
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"STAGE {stage_name} {status} (Duration: {duration:.2f}s)")
```

### 5.2 Error Handling

**Exception Hierarchy**:

```python
class SafeFixK8sError(Exception):
    """Base exception for SafeFixK8s"""
    pass

class DetectionError(SafeFixK8sError):
    """Detection stage error"""
    pass

class NormalizationError(SafeFixK8sError):
    """Normalization stage error"""
    pass

class RepairError(SafeFixK8sError):
    """Repair stage error"""
    pass

class ValidationError(SafeFixK8sError):
    """Validation stage error"""
    pass
```

**Graceful Degradation**:

```python
def run_full_pipeline(input_dir, output_dir):
    """
    Run all stages with error recovery.
    """

    try:
        # Stage 1
        run_detection(input_dir, output_dir)
    except DetectionError as e:
        logger.error(f"Detection failed: {e}")
        logger.warning("Continuing with existing scan results if available...")

    try:
        # Stage 2
        run_normalization(output_dir / "detection" / "raw", input_dir, output_dir)
    except NormalizationError as e:
        logger.error(f"Normalization failed: {e}")
        return False

    # ... continue with stages 3 & 4
```

### 5.3 Performance Optimization

#### Parallel Processing

**Detection Layer**:
- Tools run in **parallel groups**
- ~3x faster than sequential execution

**Validation Layer**:
- Files validated in **parallel**
- Configurable worker pool size

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def validate_files_parallel(files: List[str], max_workers: int = 5) -> dict:
    """
    Validate multiple files in parallel.
    """
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {
            executor.submit(validate_file, f): f
            for f in files
        }

        # Collect results as they complete
        for future in as_completed(future_to_file):
            file = future_to_file[future]
            try:
                result = future.result()
                results[file] = result
            except Exception as e:
                logger.error(f"Validation failed for {file}: {e}")
                results[file] = {"status": "ERROR", "message": str(e)}

    return results
```

#### Caching

**LLM Response Caching**:

```python
import hashlib
import json

LLM_CACHE = {}

def query_llm_with_cache(prompt: str, model: str) -> str:
    """
    Cache LLM responses by prompt hash.
    """
    # Generate cache key
    cache_key = hashlib.sha256(f"{model}:{prompt}".encode()).hexdigest()

    # Check cache
    if cache_key in LLM_CACHE:
        logger.debug("LLM cache hit")
        return LLM_CACHE[cache_key]

    # Call LLM
    response = call_llm_api(model, prompt)

    # Store in cache
    LLM_CACHE[cache_key] = response

    return response
```

---

## Design Patterns and Algorithms

### 6.1 Strategy Pattern (Fix Strategies)

**Problem**: Different categories require different fix approaches

**Solution**: Strategy pattern with pluggable fix handlers

```python
class FixStrategy(ABC):
    @abstractmethod
    def apply_fix(self, manifest: dict, finding: Finding) -> List[JSONPatch]:
        pass

class DeterministicStrategy(FixStrategy):
    def apply_fix(self, manifest: dict, finding: Finding) -> List[JSONPatch]:
        handler = get_deterministic_handler(finding.category)
        return handler(manifest, finding)

class TemplateStrategy(FixStrategy):
    def apply_fix(self, manifest: dict, finding: Finding) -> List[JSONPatch]:
        template = get_template(finding.category)
        return template.render(manifest, finding)

class LLMStrategy(FixStrategy):
    def apply_fix(self, manifest: dict, finding: Finding) -> List[JSONPatch]:
        return query_llm_for_patch(manifest, finding)
```

### 6.2 Chain of Responsibility (Validation Gates)

**Problem**: Multiple validation checks must be applied in sequence

**Solution**: Chain of responsibility with early exit

```python
class ValidationGate(ABC):
    def __init__(self, next_gate=None):
        self.next_gate = next_gate

    @abstractmethod
    def validate(self, manifest: dict, context: dict) -> ValidationResult:
        pass

    def handle(self, manifest: dict, context: dict) -> ValidationResult:
        result = self.validate(manifest, context)

        if not result.passed or self.next_gate is None:
            return result

        # Pass to next gate
        return self.next_gate.handle(manifest, context)

# Build chain
chain = (
    YAMLParsingGate(
        SchemaAutoFixGate(
            DangerousConfigGate(
                CategoryValidatorGate()
            )
        )
    )
)

result = chain.handle(manifest, context)
```

### 6.3 Builder Pattern (Patch Construction)

**Problem**: JSON Patches are complex to construct

**Solution**: Builder pattern for patch generation

```python
class PatchBuilder:
    def __init__(self):
        self.patches = []

    def add(self, path: str, value: any) -> 'PatchBuilder':
        self.patches.append({"op": "add", "path": path, "value": value})
        return self

    def replace(self, path: str, value: any) -> 'PatchBuilder':
        self.patches.append({"op": "replace", "path": path, "value": value})
        return self

    def remove(self, path: str) -> 'PatchBuilder':
        self.patches.append({"op": "remove", "path": path})
        return self

    def build(self) -> List[JSONPatch]:
        return self.patches

# Usage
patches = (
    PatchBuilder()
    .add("/spec/template/spec/securityContext", {"runAsNonRoot": True})
    .replace("/spec/replicas", 3)
    .remove("/spec/template/spec/containers/0/securityContext/privileged")
    .build()
)
```

---

## Performance Optimization

### 7.1 Execution Time Breakdown

**Typical pipeline execution** (10 Kubernetes manifests):

- **Detection**: 3-5 minutes (parallel tool execution)
- **Normalization**: 5-10 seconds (pure Python)
- **Repair**: 20-30 seconds (deterministic) + 10-20 seconds (LLM calls)
- **Validation**: 5-10 seconds (parallel file validation)

**Total**: ~4-6 minutes for full pipeline

### 7.2 Optimization Strategies

1. **Parallel Tool Execution**: 3x speedup in detection
2. **Deterministic-First Repairs**: 70% fewer LLM calls
3. **LLM Response Caching**: Avoid duplicate API calls
4. **Batch Processing**: Process multiple files in parallel
5. **Incremental Execution**: Run only changed stages

---

## Error Handling and Resilience

### 8.1 Tool Failure Isolation

**Problem**: One scanner failure shouldn't stop the pipeline

**Solution**: Per-tool error handling with fallback

```python
for tool in ["checkov", "trivy", "kubescape", ...]:
    try:
        run_tool(tool)
    except ToolError as e:
        logger.error(f"Tool {tool} failed: {e}")
        write_empty_output(tool)  # Write empty JSON for consistent parsing
        continue
```

### 8.2 LLM Fallback Chain

**Problem**: LLM APIs may fail or produce invalid responses

**Solution**: Multi-provider fallback with template backup

```python
def generate_fix_with_fallback(finding: Finding, manifest: dict) -> List[JSONPatch]:
    """
    Try LLM providers in order, fallback to template.
    """

    # Try LLMs
    for provider in ["groq", "openrouter", "gemini", "openai"]:
        try:
            patch = query_llm(provider, finding, manifest)
            if validate_patch(patch):
                return patch
        except Exception as e:
            logger.warning(f"LLM {provider} failed: {e}")
            continue

    # All LLMs failed, use template
    logger.warning("All LLMs failed, using template fallback")
    return template_fix(finding, manifest)
```

### 8.3 Data Validation

**Input Validation**:

```python
def validate_input_manifest(manifest: dict) -> bool:
    """
    Validate Kubernetes manifest structure.
    """
    required_fields = ["apiVersion", "kind", "metadata"]

    for field in required_fields:
        if field not in manifest:
            raise ValueError(f"Missing required field: {field}")

    return True
```

**Output Validation**:

```python
def validate_json_patch(patch: dict) -> bool:
    """
    Validate JSON Patch conforms to RFC-6902.
    """
    required_fields = ["op", "path"]

    if not all(f in patch for f in required_fields):
        return False

    if patch["op"] not in ["add", "replace", "remove"]:
        return False

    if not patch["path"].startswith("/"):
        return False

    return True
```

---

## Conclusion

SafeFixK8s implements a sophisticated, production-grade pipeline for automated Kubernetes security remediation. The methodology combines:

1. **Multi-tool consensus** for comprehensive detection
2. **Intelligent normalization** with false positive filtering
3. **Hybrid repair strategies** optimizing for cost and reliability
4. **Rigorous validation** through a 7-gate framework

The system is designed for **extensibility**, **reliability**, and **transparency**, making it suitable for both research and production use.

---

**Document Version**: 1.0
**Last Updated**: 2025-12-07
**Author**: SafeFixK8s Project
