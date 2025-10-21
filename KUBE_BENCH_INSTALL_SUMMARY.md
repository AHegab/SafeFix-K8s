# kube-bench Installation Summary

## What Was Created

### 1. Installation Scripts

#### **install-kube-bench.ps1** (Windows)
- **Location**: Root directory
- **Purpose**: Automated kube-bench v0.13.0 installation for Windows
- **Features**:
  - Downloads from GitHub releases
  - Verifies SHA256 checksum
  - Extracts tar.gz archive
  - Installs to `C:\Program Files\kube-bench`
  - Adds to system PATH
  - Includes version verification

**Usage:**
```powershell
# Run as Administrator
.\install-kube-bench.ps1
```

#### **install-kube-bench.sh** (Linux/macOS)
- **Location**: Root directory
- **Purpose**: Automated kube-bench v0.13.0 installation for Unix systems
- **Features**:
  - Auto-detects OS and architecture (amd64/arm64)
  - Downloads from GitHub releases
  - Verifies SHA256 checksum
  - Extracts tar.gz archive
  - Installs to `/usr/local/bin`
  - Copies configuration to `/etc/kube-bench`

**Usage:**
```bash
# Make executable
chmod +x install-kube-bench.sh

# Run with sudo
sudo ./install-kube-bench.sh
```

### 2. Documentation

#### **KUBE_BENCH_GUIDE.md**
- **Location**: Root directory
- **Purpose**: Comprehensive kube-bench usage guide
- **Covers**:
  - Installation verification
  - Basic and advanced usage
  - Configuration management
  - Target components (master, node, etcd, policies)
  - Output formats (human, JSON, JUnit)
  - Common use cases
  - Troubleshooting
  - Integration with SafeFixK8s
  - Best practices

#### **README.md** (Updated)
- **Added Sections**:
  - Extended Tools Installation (kube-bench, pluto, rbac-police)
  - Tool-specific notes for kube-bench
  - Usage examples on cluster nodes
  - Configuration locations

#### **EXTENDED_TOOLS_STATUS.md** (Existing)
- Already documents kube-bench status and limitations
- Explains why it outputs placeholder (requires cluster node)

---

## Installation Details

### kube-bench v0.13.0

**Release Information:**
- **Version**: 0.13.0
- **Source**: https://github.com/aquasecurity/kube-bench/releases/tag/v0.13.0
- **Supported Platforms**:
  - Windows (amd64)
  - Linux (amd64, arm64)
  - macOS (amd64, arm64)

**Installation Paths:**

| Platform | Executable | Configuration |
|----------|-----------|---------------|
| Windows  | `C:\Program Files\kube-bench\bin\kube-bench.exe` | `C:\Program Files\kube-bench\cfg\` |
| Linux    | `/usr/local/bin/kube-bench` | `/etc/kube-bench/` |
| macOS    | `/usr/local/bin/kube-bench` | `/etc/kube-bench/` |

**Verification:**
```bash
# Check version
kube-bench version

# Expected output
v0.13.0
```

---

## How It Works

### Installation Process

1. **Download** - Fetches binary and checksum from GitHub releases
2. **Verify** - Validates SHA256 checksum for security
3. **Extract** - Unpacks tar.gz archive
4. **Install** - Copies executable to system location
5. **Configure** - Sets up PATH and configuration files
6. **Test** - Verifies installation with version check

### Checksum Verification

The scripts verify integrity by:
1. Downloading official checksums file
2. Extracting expected SHA256 hash
3. Computing actual file hash
4. Comparing both hashes
5. Aborting if mismatch detected

This ensures the downloaded binary hasn't been tampered with.

---

## Usage in SafeFixK8s

### Current Behavior

**Without kube-bench installed:**
```powershell
cd detection
. .\detectors.ps1
Det-KubeBench "..\tests"

# Output: Valid placeholder JSON
# [{"tool":"kube-bench","note":"kube-bench not installed...","install":"..."}]
```

**With kube-bench installed (on cluster node):**
```powershell
Det-KubeBench "..\tests"

# Output: Actual CIS benchmark results (if running on K8s node)
# Otherwise: Placeholder explaining cluster node requirement
```

### Integration Flow

```
SafeFixK8s Det-KubeBench
    ↓
Check if kube-bench installed locally
    ↓
    ├─→ YES: Run kube-bench run --json
    │   ├─→ On cluster node: Real CIS results
    │   └─→ Not on cluster: Placeholder with explanation
    │
    └─→ NO: Create placeholder with install instructions
```

---

## Quick Start

### For Development/Testing (Manifest Scanning)

```powershell
# Install SafeFixK8s tools
cd SafeFixK8s
.\setup-images.ps1

# Run core tools (no kube-bench needed)
cd detection
. .\detectors.ps1
Det-RunLean "..\tests"

# Optional: Install kube-bench for completeness
.\install-kube-bench.ps1

# Run with all tools (kube-bench will create placeholder)
Det-RunExtended "..\tests"
```

### For Production (Cluster Scanning)

```bash
# On Kubernetes master node:

# 1. Install kube-bench
sudo ./install-kube-bench.sh

# 2. Run CIS benchmark scan
sudo kube-bench run --targets master --json > master-results.json

# On Kubernetes worker node:

# 1. Install kube-bench
sudo ./install-kube-bench.sh

# 2. Run node scan
sudo kube-bench run --targets node --json > node-results.json
```

---

## Key Commands Reference

### Installation
```powershell
# Windows (PowerShell as Admin)
.\install-kube-bench.ps1

# Linux/macOS (with sudo)
sudo ./install-kube-bench.sh
```

### Verification
```bash
# Check version
kube-bench version

# Check installation path
which kube-bench  # Linux/macOS
where kube-bench  # Windows
```

### Basic Scans
```bash
# Master node
sudo kube-bench run --targets master

# Worker node
sudo kube-bench run --targets node

# JSON output
sudo kube-bench run --targets master --json

# Save to file
sudo kube-bench run --targets master --json --outputfile results.json
```

### SafeFixK8s Integration
```powershell
cd detection
. .\detectors.ps1

# Individual tool
Det-KubeBench "..\tests"

# All extended tools
Det-RunExtended "..\tests"
```

---

## Important Notes

### ⚠️ kube-bench Limitations

1. **Requires Cluster Node Access**
   - Must run ON Kubernetes nodes, not against YAML files
   - Checks runtime configuration, not static manifests
   - Needs elevated permissions (sudo/Administrator)

2. **Not for Manifest-Only Scanning**
   - Cannot analyze YAML files directly
   - Inspects actual cluster components
   - Checks node filesystem and processes

3. **Use Case Clarification**
   - ✅ Production cluster compliance audits
   - ✅ CIS benchmark validation
   - ✅ Node security configuration checks
   - ❌ Development manifest analysis
   - ❌ CI/CD static YAML scanning

### ✅ When to Use kube-bench

- **Pre-production audits**: Before going live
- **Compliance checks**: Regular CIS benchmark validation
- **Security hardening**: Identify misconfigurations
- **Post-deployment**: Verify cluster security posture

### ✅ When NOT to Use kube-bench

- **Local development**: Use other tools (Polaris, Trivy, etc.)
- **CI/CD pipelines**: Use manifest scanners
- **Offline analysis**: No cluster access available
- **YAML validation**: Use KubeLinter, Polaris instead

---

## Next Steps

1. **Install kube-bench** (optional for SafeFixK8s):
   ```powershell
   # Windows
   .\install-kube-bench.ps1
   
   # Or Linux/macOS
   sudo ./install-kube-bench.sh
   ```

2. **Verify installation**:
   ```bash
   kube-bench version
   ```

3. **Update SafeFixK8s detectors** (already done):
   - Det-KubeBench function creates valid JSON output
   - Handles both installed and not-installed scenarios
   - Provides helpful installation guidance

4. **Test in your environment**:
   ```powershell
   cd detection
   . .\detectors.ps1
   Det-RunExtended "..\tests"
   ```

5. **For cluster scanning** (when ready):
   - Copy kube-bench to cluster nodes
   - Run with appropriate targets (master/node/etcd)
   - Integrate results into your compliance workflow

---

## Troubleshooting

### Windows Issues

**PowerShell Execution Policy:**
```powershell
# Check policy
Get-ExecutionPolicy

# Set policy (if needed)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Administrator Rights:**
- Right-click PowerShell → "Run as Administrator"
- Or: Use `sudo` (if installed)

**PATH not updated:**
```powershell
# Reload PATH in current session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
```

### Linux/macOS Issues

**Permission denied:**
```bash
# Make script executable
chmod +x install-kube-bench.sh

# Run with sudo
sudo ./install-kube-bench.sh
```

**tar not found:**
```bash
# Install tar (Ubuntu/Debian)
sudo apt-get install tar

# Install tar (CentOS/RHEL)
sudo yum install tar
```

---

## Summary Checklist

- ✅ Created `install-kube-bench.ps1` for Windows
- ✅ Created `install-kube-bench.sh` for Linux/macOS
- ✅ Both scripts verify checksums for security
- ✅ Scripts install to standard system locations
- ✅ Scripts add kube-bench to PATH
- ✅ Created comprehensive `KUBE_BENCH_GUIDE.md`
- ✅ Updated `README.md` with installation steps
- ✅ Det-KubeBench function handles all scenarios
- ✅ Valid JSON output in all cases (real results or placeholder)
- ✅ Clear documentation of limitations and use cases

**Status**: Installation scripts ready to use! 🎉
