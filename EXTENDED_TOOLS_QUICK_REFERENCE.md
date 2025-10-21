# Extended Tools - Quick Reference

## Tool Comparison Matrix

| Feature | kube-bench | rbac-police | pluto |
|---------|-----------|-------------|-------|
| **Purpose** | CIS Benchmark compliance | RBAC permissions audit | API deprecation detection |
| **Input** | Cluster nodes (ideal) or manifests | RBAC manifests or cluster | Any K8s manifests |
| **Cluster Required** | Yes (for full results) | No (but recommended) | No |
| **Output Format** | JSON | JSON | JSON |
| **Speed** | Medium (5-15s) | Fast (3-7s) | Fast (2-5s) |
| **Offline Capable** | Limited | Yes (with manifests) | Yes |

---

## When to Use Each Tool

### Use kube-bench when:
- ✅ Auditing actual cluster node security
- ✅ Checking CIS Kubernetes Benchmark compliance
- ✅ Validating control plane configuration
- ✅ Assessing kubelet security settings
- ❌ NOT ideal for manifest-only scanning

### Use rbac-police when:
- ✅ Analyzing RBAC configurations
- ✅ Finding overly permissive roles
- ✅ Detecting privilege escalation paths
- ✅ Auditing service account permissions
- ✅ Reviewing cluster-admin bindings

### Use pluto when:
- ✅ Planning Kubernetes upgrades
- ✅ Finding deprecated API versions
- ✅ Preventing breaking changes
- ✅ Checking API compatibility
- ✅ Before deploying to newer clusters

---

## PowerShell Quick Commands

### Run All Extended Tools
```powershell
cd detection
. .\detectors.ps1
Det-RunExtended "..\tests"
```

### Run Specific Extended Tool
```powershell
# CIS Benchmarks
Det-KubeBench "..\cluster-configs"

# RBAC Analysis
Det-RBACPolice "..\rbac-manifests"

# API Deprecation
Det-Pluto "..\all-manifests"
```

### Custom Output Paths
```powershell
Det-KubeBench -Path "..\tests" -Out "C:\reports\kube-bench.json"
Det-RBACPolice -Path "..\tests" -Out "C:\reports\rbac.json"
Det-Pluto -Path "..\tests" -Out "C:\reports\pluto.json"
```

---

## Installation Checklist

### Docker Images (Recommended)
```powershell
docker pull aquasec/kube-bench:latest
docker pull quay.io/reactiveops/rbac-police:latest
docker pull us-docker.pkg.dev/fairwinds-ops/oss/pluto:latest
```

### Local Installation (Optional)

**kube-bench:**
1. Download: https://github.com/aquasecurity/kube-bench/releases
2. Extract binary
3. Add to PATH
4. Verify: `kube-bench version`

**rbac-police (kubectl plugin):**
1. Install krew: https://krew.sigs.k8s.io/docs/user-guide/setup/install/
2. Run: `kubectl krew install rbac-police`
3. Verify: `kubectl rbac-police --help`

**pluto:**
1. Download: https://github.com/FairwindsOps/pluto/releases
2. Extract binary
3. Add to PATH
4. Verify: `pluto version`

---

## Configuration Examples

### kube-bench on Cluster Nodes
```powershell
# SSH to cluster node, then:
kube-bench run --json --outputfile results.json

# Or with Docker on node:
docker run --rm --pid=host aquasec/kube-bench:latest run --json
```

### rbac-police with Cluster Context
```powershell
# Requires kubectl context configured
kubectl rbac-police --format json --output rbac-results.json
```

### pluto for Specific K8s Version
```powershell
# Check compatibility with K8s 1.29
pluto detect-files -d ./manifests --target-versions k8s=v1.29.0 --output json
```

---

## Common Output Patterns

### kube-bench Output Structure
```json
{
  "Controls": [{
    "id": "1.1.1",
    "text": "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
    "tests": [{
      "result": "PASS"
    }]
  }],
  "Totals": {
    "total_pass": 45,
    "total_fail": 5,
    "total_warn": 3
  }
}
```

### rbac-police Output Structure
```json
{
  "findings": [{
    "role": "cluster-admin-binding",
    "severity": "high",
    "message": "ClusterRoleBinding grants cluster-admin to default:serviceaccount"
  }]
}
```

### pluto Output Structure
```json
{
  "items": [{
    "name": "my-ingress",
    "api": "extensions/v1beta1",
    "deprecated": true,
    "removed": true,
    "replacementAPI": "networking.k8s.io/v1"
  }],
  "target-versions": {
    "k8s": "v1.25.0"
  }
}
```

---

## Troubleshooting

### kube-bench returns empty results
**Problem:** Running on manifests without cluster access

**Solutions:**
1. Run on actual cluster nodes
2. Use Docker with host mounts: `docker run --pid=host -v /etc:/node/etc:ro -v /var:/node/var:ro aquasec/kube-bench:latest`
3. Skip if only manifest scanning is needed

### rbac-police finds nothing
**Problem:** No RBAC manifests in scan directory

**Solutions:**
1. Ensure directory contains Role, RoleBinding, ClusterRole, ClusterRoleBinding files
2. Check YAML syntax and `kind:` fields
3. Point to correct directory with RBAC resources

### pluto output is empty
**Problem:** No deprecated APIs found

**Solutions:**
This is actually good news! It means your manifests are up-to-date. However:
1. Verify pluto is scanning correct directory
2. Check that YAML files are valid Kubernetes resources
3. Ensure output file was created (check file size)

---

## Integration Tips

### 1. CI/CD Pipeline
```yaml
# Example GitHub Actions
- name: Run Extended Scan
  run: |
    cd detection
    powershell -Command ". .\detectors.ps1; Det-RunExtended '../manifests'"

- name: Check for Critical Issues
  run: |
    python check_findings.py --severity critical --fail-on-findings
```

### 2. Pre-Deployment Check
```powershell
# Before deploying
Det-Pluto "..\production-manifests"
$pluto = Get-Content .\output\raw\pluto_raw.json | ConvertFrom-Json
if ($pluto.items.Count -gt 0) {
  Write-Error "Deprecated APIs found! Fix before deploying."
  exit 1
}
```

### 3. Monthly Compliance Audit
```powershell
# Scheduled task
$date = Get-Date -Format "yyyy-MM-dd"
$reportDir = "C:\compliance-reports\$date"
New-Item -ItemType Directory -Path $reportDir
Det-RunExtended "C:\k8s-production"
Copy-Item .\output\raw\* $reportDir
```

---

## Resource Requirements

| Tool | CPU | Memory | Disk I/O | Network |
|------|-----|--------|----------|---------|
| kube-bench | Low | Low | Medium | None |
| rbac-police | Low | Low | Low | None (manifest mode) |
| pluto | Low | Low | Low | None |

All three extended tools are lightweight and add minimal overhead to scan time.

---

## Support & Documentation

### Official Documentation
- **kube-bench**: https://github.com/aquasecurity/kube-bench
- **rbac-police**: https://github.com/FairwindsOps/rbac-police  
- **pluto**: https://pluto.docs.fairwinds.com/

### SafeFixK8s Documentation
- See `EXTENDED_TOOLS.md` for detailed implementation guide
- See `README.md` for overall framework documentation
- See `HOW_TO_USE.md` for step-by-step usage instructions

---

**Last Updated:** October 2025  
**Version:** 2.0 (Extended Tools)
