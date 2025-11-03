# SafeFix-K8s Perfect Normalizer v9.0

## 🎯 Overview

The **Perfect Normalizer v9.0** is an enterprise-grade finding aggregation and normalization engine that transforms raw security tool outputs into a clean, LLM-ready payload with intelligent categorization, severity classification, and remediation context.

## ✨ Key Enhancements

### 1. **Comprehensive Tool Support (13+ Tools)**
- ✅ **Checkov** - Policy-as-code security scanner
- ✅ **Trivy** - Vulnerability and misconfiguration scanner
- ✅ **KubeAudit** - Kubernetes security auditor
- ✅ **KubeLinter** - Static analysis for Kubernetes
- ✅ **Polaris** - Best practices validator (ENHANCED)
- ✅ **KubeScore** - Static code analysis
- ✅ **Kubescape** - CISA framework scanner (ENHANCED)
- ✅ **Conftest** - OPA policy testing
- ✅ **KubeConform** - Schema validation
- ✅ **RBAC-Police** - RBAC privilege scanner
- ✅ **Yamllint** - YAML syntax checker
- ✅ **Gitleaks** - Secret detection
- ✅ **Pluto** - Deprecated API finder

### 2. **Enhanced Categorization (16 Categories)**

#### 🔴 CRITICAL (Security-Breaking)
- **PRIVILEGED** - Containers running with privileged=true
- **PRIV_ESCALATION** - allowPrivilegeEscalation enabled
- **CAP_SYS_ADMIN** - Dangerous Linux capabilities
- **HOSTPATH** - Host filesystem/docker socket mounting

#### 🟠 HIGH (Severe Security Risks)
- **RUN_AS_NONROOT_FALSE** - Running as root user
- **READONLY_ROOTFS_FALSE** - Writable root filesystem
- **NO_SECCOMP** - Missing seccomp profiles
- **NO_APPARMOR** - Missing AppArmor policies
- **HARD_CODED_CREDS** - Hardcoded secrets/credentials
- **PLAIN_SECRET** - Unencrypted Kubernetes secrets
- **RBAC_OVER_PERMISSIVE** - Wildcard RBAC permissions

#### 🟡 MEDIUM (Security Concerns)
- **IMAGE_LATEST** - Using :latest tag
- **HOST_NAMESPACE** - hostPID/hostIPC/hostNetwork
- **NETWORK_POLICY_MISSING** - No NetworkPolicy defined
- **SERVICEACCOUNT_TOKEN_AUTO** - Auto-mounted SA tokens
- **CNI_EMBEDDED_PRIVILEGED** - CNI config with privileged
- **POD_DEFAULT_NAMESPACE** - Pods in default namespace

#### 🔵 LOW (Quality/DevOps Best Practices)
- **NO_PROBES** - Missing liveness/readiness probes
- **NO_RES_LIMITS** - Missing resource limits
- **DEPRECATED_API** - Deprecated Kubernetes APIs
- **SCHEMA_INVALID** - Invalid YAML schema
- **YAML_FORMATTING** - YAML syntax issues

### 3. **Intelligent Rule Mapping**

Comprehensive rule ID mappings for automatic categorization:
```python
RULEID_MAP = {
    # Checkov
    "CKV_K8S_22": "PRIVILEGED",
    "CKV_K8S_26": "PRIV_ESCALATION",
    "CKV_K8S_37": "CAP_SYS_ADMIN",
    
    # Kubescape
    "C-0057": "PRIVILEGED",
    "C-0016": "PRIV_ESCALATION",
    "C-0046": "CAP_SYS_ADMIN",
    
    # Polaris
    "runAsPrivileged": "PRIVILEGED",
    "cpuLimitsMissing": "NO_RES_LIMITS",
    # ... 40+ mappings total
}
```

### 4. **Deep Tool Parsing**

#### Polaris Parser
Extracts findings from:
- `Results` object (for ConfigMaps, Secrets)
- `PodResult.ContainerResults` (for Pods, Deployments)
- Severity levels (danger, warning, info)
- Category metadata

#### Kubescape Parser
Extracts from control-level structure:
- Failed controls with control IDs
- Rule-level failures
- Fix path suggestions
- Resource ID mapping

### 5. **Enhanced Aggregation**

```json
{
  "file": "tests/nginx_privileged_deployment.yaml",
  "category": "PRIVILEGED",
  "severity": "CRITICAL",
  "tools": ["Checkov", "Trivy", "Kubescape"],
  "support_count": 3,
  "rule_ids": ["CKV_K8S_22", "C-0057", "KSV017"],
  "examples": [
    "Container runs with privileged: true",
    "Privileged container detected",
    "Security context allows privileged escalation"
  ],
  "occurrences": 5
}
```

**Sorting Priority:**
1. Severity (CRITICAL → HIGH → MEDIUM → LOW)
2. Support count (descending - multi-tool findings first)
3. File name (alphabetical)
4. Category (alphabetical)

### 6. **Rich LLM Payload**

Each item includes:
```json
{
  "file": "tests/nginx_privileged_deployment.yaml",
  "category": "PRIVILEGED",
  "severity": "CRITICAL",
  "tools": ["Checkov", "Trivy"],
  "support_count": 2,
  "rule_ids": ["CKV_K8S_22", "C-0057"],
  "hints": ["Container runs privileged", "..."],
  "policy": "least-privilege",
  "resource": {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "nginx-deployment",
      "namespace": "default"
    }
  },
  "snippet": "securityContext:\n  privileged: true",
  "span": {"start_line": 10, "end_line": 12},
  "jsonpath": "$.spec.template.spec.containers[0].securityContext",
  "occurrences": 3
}
```

### 7. **Comprehensive Metadata**

Output includes operational statistics:
```json
{
  "generated_at": "2025-11-03T10:57:17Z",
  "version": "sfk-v9.0-perfect",
  "metadata": {
    "raw_findings_count": 1336,
    "aggregated_count": 234,
    "llm_items_count": 131,
    "severity_distribution": {
      "CRITICAL": 57,
      "HIGH": 84,
      "MEDIUM": 49,
      "LOW": 44
    },
    "filters": {
      "min_support": 1,
      "only_security": true
    }
  }
}
```

## 📊 Performance Metrics

### Current Run Results
- **Raw Findings Extracted:** 1,336
- **Aggregated Findings:** 234 unique (file, category) pairs
- **LLM Payload Items:** 131 (security only)
- **Multi-Tool Confirmed:** 47 items (36%)
- **Processing Time:** ~2 seconds

### Severity Breakdown
| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | 38    | 29%        |
| HIGH     | 59    | 45%        |
| MEDIUM   | 34    | 26%        |
| **TOTAL**| **131** | **100%** |

### Tool Coverage Distribution
- **Single Tool:** 84 findings (64%)
- **2 Tools:** 32 findings (24%)
- **3+ Tools:** 15 findings (12%)

## 🚀 Usage

### Basic Usage
```bash
python Normalizer/normalize.py \
  --raw Detection/output/raw \
  --out output
```

### Advanced Options
```bash
python Normalizer/normalize.py \
  --raw Detection/output/raw \
  --out output \
  --min-support 2 \              # Require 2+ tools
  --only-security 1 \             # Exclude quality checks
  --emit-normalized 1             # Also emit debug output
```

### Parameters
- `--raw`: Directory containing raw tool outputs (JSON files)
- `--out`: Output directory for llm_payload.json
- `--min-support`: Minimum number of tools required (default: 1)
- `--only-security`: Skip quality-only categories (default: 1)
- `--emit-normalized`: Also generate normalized_findings.json (default: 0)

## 🏗️ Architecture

```
┌─────────────────┐
│  Detection/     │
│  output/raw/    │ ──► parse_raw_dir()
│  - checkov.json │         │
│  - trivy.json   │         ▼
│  - polaris.json │    [Raw Findings]
│  ... (13 files) │         │
└─────────────────┘         │
                            ▼
                    ┌──────────────┐
                    │  aggregate() │
                    │  - Correlate │
                    │  - Categorize│
                    │  - Prioritize│
                    └──────────────┘
                            │
                            ▼
                    [Aggregated Items]
                            │
                            ▼
                  ┌──────────────────┐
                  │ build_llm_items()│
                  │ - File location  │
                  │ - Snippet extract│
                  │ - JSONPath gen   │
                  │ - Resource ID    │
                  └──────────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │ llm_payload  │
                    │    .json     │ ◄── LLM Ready!
                    └──────────────┘
```

## 🎓 Key Improvements from v8.0

1. ✅ **Deep Polaris Parsing** - Now extracts from Results AND PodResult
2. ✅ **Deep Kubescape Parsing** - Control and rule-level extraction
3. ✅ **Severity Classification** - 4-tier system (CRITICAL/HIGH/MEDIUM/LOW)
4. ✅ **Enhanced Categorization** - 16 categories vs 15 previously
5. ✅ **Smart Rule Mapping** - 40+ rule IDs automatically mapped
6. ✅ **Deduplication** - Unique examples list per category
7. ✅ **Severity-First Sorting** - Critical issues surface first
8. ✅ **Rich Metadata** - Comprehensive statistics in output
9. ✅ **Error Resilience** - Graceful handling of missing/malformed data
10. ✅ **Occurrence Tracking** - Count how many times each issue appears

## 🔍 Example Output Snippet

```json
{
  "file": "tests/13.nginx_privileged_deployment.yaml",
  "category": "PRIVILEGED",
  "severity": "CRITICAL",
  "tools": ["Checkov", "Trivy", "Kubescape"],
  "support_count": 3,
  "rule_ids": ["CKV_K8S_22", "C-0057", "KSV017"],
  "hints": [
    "Container runs with privileged: true",
    "Privileged container detected",
    "Security context allows privileged escalation"
  ],
  "policy": "least-privilege",
  "resource": {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "nginx-deployment",
      "namespace": ""
    }
  },
  "snippet": "securityContext:\n  privileged: true",
  "span": {"start_line": 10, "end_line": 12},
  "jsonpath": "$.spec.template.spec.containers[0].securityContext",
  "occurrences": 5
}
```

## 📈 Integration with LLM Layer

The Perfect Normalizer output is optimized for LLM consumption:

1. **Structured Context** - Clear category, severity, and tool consensus
2. **Code Snippets** - Exact problematic code with line numbers
3. **Remediation Hints** - Multiple tool perspectives on the issue
4. **JSONPath** - Precise location for automated fixes
5. **Resource Identity** - Full apiVersion/kind/metadata for context

## 🛠️ Maintenance

### Adding New Categories
1. Add to `CANONICAL` dict with regex patterns
2. Add to severity sets (CRITICAL/HIGH/MEDIUM)
3. Update `CATEGORY_HINT_REGEX` for snippet extraction
4. Add JSONPath logic in `best_effort_jsonpath()`

### Adding New Tools
1. Create dedicated parser function (e.g., `parse_newtool()`)
2. Add to `parse_by_name()` routing
3. Add tool name to `TOOL_ALIASES`
4. Add rule ID mappings to `RULEID_MAP`

## 📝 Version History

### v9.0 (Perfect Edition) - 2025-11-03
- Deep Polaris and Kubescape parsing
- 4-tier severity system
- 40+ rule ID mappings
- Rich metadata output
- Occurrence tracking
- Deduplication enhancements

### v8.0 - Previous stable release
- Basic tool parsing
- 15 categories
- Simple aggregation

## 🤝 Contributing

Improvements welcome! Focus areas:
- Additional tool integrations
- More granular categorization
- Better JSONPath inference
- Performance optimizations

---

**Built for SafeFix-K8s BSc Thesis Project**  
*Making Kubernetes Security Accessible Through AI*
