# kube-bench Quick Reference Guide

## Overview
kube-bench is a tool that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.

**Version:** 0.13.0  
**Purpose:** CIS Kubernetes Benchmark compliance checking  
**Requirement:** Must run on actual Kubernetes cluster nodes

---

## Installation

### Automated Installation

**Windows:**
```powershell
# Run as Administrator
.\install-kube-bench.ps1
```

**Linux/macOS:**
```bash
# Run with sudo
sudo ./install-kube-bench.sh
```

### Verify Installation

```bash
# Check version
kube-bench version

# Expected output:
# v0.13.0
```

---

## Basic Usage

### Quick Scan Commands

**On Master Node:**
```bash
sudo kube-bench run --targets master
```

**On Worker Node:**
```bash
sudo kube-bench run --targets node
```

**On Etcd Node:**
```bash
sudo kube-bench run --targets etcd
```

**Full Cluster Scan (run on control plane):**
```bash
sudo kube-bench run --targets master,node,etcd,policies
```

### Output Formats

**Human-readable (default):**
```bash
sudo kube-bench run --targets master
```

**JSON format:**
```bash
sudo kube-bench run --targets master --json
```

**JSON to file:**
```bash
sudo kube-bench run --targets master --json --outputfile /tmp/kube-bench-results.json
```

**JUnit format:**
```bash
sudo kube-bench run --targets master --junit
```

---

## Advanced Usage

### Check Specific Benchmark Version

```bash
# Use CIS Kubernetes v1.27
sudo kube-bench run --benchmark cis-1.27

# Use CIS Kubernetes v1.8
sudo kube-bench run --benchmark cis-1.8
```

### Run Specific Tests

```bash
# Run only test 1.2.1
sudo kube-bench run --targets master --check 1.2.1

# Run tests in section 1.2
sudo kube-bench run --targets master --check 1.2
```

### Skip Specific Tests

```bash
# Skip test 1.2.1
sudo kube-bench run --targets master --skip 1.2.1
```

### Filter by Severity

```bash
# Show only FAIL results
sudo kube-bench run --targets master | grep FAIL

# Show only WARN results
sudo kube-bench run --targets master | grep WARN
```

---

## Configuration

### Default Configuration Locations

**Windows:**
- `C:\Program Files\kube-bench\cfg\`

**Linux:**
- `/etc/kube-bench/`
- `/opt/kube-bench/cfg/`

### Configuration Files Structure

```
cfg/
├── config.yaml              # Main configuration
├── cis-1.27/                # CIS Kubernetes v1.27 benchmark
│   ├── master.yaml          # Master node tests
│   ├── node.yaml            # Worker node tests
│   ├── etcd.yaml            # Etcd tests
│   └── policies.yaml        # Policy tests
├── cis-1.8/                 # CIS Kubernetes v1.8 benchmark
└── ...
```

### Custom Configuration

```bash
# Use custom config directory
sudo kube-bench run --config-dir /path/to/custom/cfg --targets master

# Use custom config file
sudo kube-bench run --config /path/to/config.yaml --targets master
```

---

## Target Components

### 1. Master (Control Plane)

Checks for:
- API Server configuration
- Scheduler configuration
- Controller Manager configuration
- Kubernetes configuration files
- PKI certificates and keys

**Command:**
```bash
sudo kube-bench run --targets master --json
```

### 2. Node (Worker)

Checks for:
- Kubelet configuration
- Kubelet service
- Configuration files
- Kernel parameters

**Command:**
```bash
sudo kube-bench run --targets node --json
```

### 3. Etcd

Checks for:
- Etcd configuration
- Etcd data directory permissions
- TLS settings

**Command:**
```bash
sudo kube-bench run --targets etcd --json
```

### 4. Policies

Checks for:
- Pod Security Standards
- Network Policies
- RBAC settings

**Command:**
```bash
sudo kube-bench run --targets policies --json
```

---

## Understanding Results

### Test Result Types

1. **[PASS]** - Test passed successfully
2. **[FAIL]** - Test failed, action required
3. **[WARN]** - Manual verification required
4. **[INFO]** - Informational, no action required

### Example Output

```
[INFO] 1 Master Node Security Configuration
[INFO] 1.1 Master Node Configuration Files
[PASS] 1.1.1 Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Automated)
[FAIL] 1.1.2 Ensure that the API server pod specification file ownership is set to root:root (Automated)
[WARN] 1.1.3 Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive (Manual)
```

### Remediation

Each FAIL includes remediation steps:

```
[FAIL] 1.1.2 Ensure that the API server pod specification file ownership is set to root:root (Automated)

Remediation:
Run the below command on the master node.
chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml
```

---

## Common Use Cases

### 1. Pre-Production Cluster Audit

```bash
# Run full scan and save results
sudo kube-bench run --targets master,node,etcd,policies --json > cluster-audit-$(date +%Y%m%d).json
```

### 2. Continuous Compliance Monitoring

```bash
# Run daily via cron
0 2 * * * sudo kube-bench run --targets master,node --json --outputfile /var/log/kube-bench-$(date +%Y%m%d).json
```

### 3. Compare Before/After Changes

```bash
# Before
sudo kube-bench run --targets master --json > before.json

# Make changes...

# After
sudo kube-bench run --targets master --json > after.json

# Compare
diff before.json after.json
```

### 4. CI/CD Integration

```yaml
# Example GitLab CI job
kube-bench-scan:
  stage: security
  script:
    - kube-bench run --targets master,node --json
  artifacts:
    paths:
      - kube-bench-results.json
  only:
    - main
```

---

## Integration with SafeFixK8s

### Running kube-bench via SafeFixK8s

```powershell
cd detection
. .\detectors.ps1

# Run kube-bench (will create placeholder if not on cluster node)
Det-KubeBench "..\tests"

# Run all extended tools
Det-RunExtended "..\tests"
```

### Expected Behavior

**On non-cluster machine (development):**
- Creates placeholder JSON with installation instructions
- No actual CIS benchmark tests performed

**On cluster node (production):**
- Runs actual CIS benchmark tests
- Outputs real compliance results
- Requires elevated permissions

---

## Troubleshooting

### Issue: "command not found"

**Solution:**
```bash
# Verify installation
which kube-bench

# Add to PATH (Linux/macOS)
export PATH=$PATH:/usr/local/bin

# Add to PATH (Windows)
$env:Path += ";C:\Program Files\kube-bench\bin"
```

### Issue: "Warning: Kubernetes version was not auto-detected"

**Cause:** Not running on actual Kubernetes node

**Solution:** Run on master or worker node with kubectl configured

### Issue: Permission Denied

**Solution:**
```bash
# Run with sudo
sudo kube-bench run --targets master
```

### Issue: Missing Configuration Files

**Solution:**
```bash
# Download configuration files
git clone https://github.com/aquasecurity/kube-bench.git
sudo cp -r kube-bench/cfg /etc/kube-bench/
```

### Issue: Tests Skip or No Output

**Check:**
1. Are you on the correct node type? (master vs worker)
2. Is Kubernetes installed and running?
3. Are configuration files present?

---

## Best Practices

1. **Run on appropriate nodes**: Master tests on master, node tests on workers
2. **Use JSON output**: Easier to parse and integrate with other tools
3. **Schedule regular scans**: Weekly or monthly compliance checks
4. **Review WARN results**: Many require manual verification
5. **Document exceptions**: Not all FAILs may be applicable to your setup
6. **Track progress**: Compare scans over time to measure improvement
7. **Automate remediation**: Script common fixes where possible

---

## Additional Resources

- **Official Documentation**: https://github.com/aquasecurity/kube-bench
- **CIS Kubernetes Benchmark**: https://www.cisecurity.org/benchmark/kubernetes
- **Kubernetes Security Best Practices**: https://kubernetes.io/docs/concepts/security/

---

## Summary

| Command | Purpose |
|---------|---------|
| `kube-bench version` | Check installed version |
| `sudo kube-bench run --targets master` | Scan control plane |
| `sudo kube-bench run --targets node` | Scan worker node |
| `sudo kube-bench run --targets master --json` | JSON output |
| `sudo kube-bench run --check 1.2` | Run specific section |
| `sudo kube-bench run --skip 1.2.1` | Skip specific test |

**Remember:** kube-bench must run **on** Kubernetes cluster nodes, not against YAML files!
