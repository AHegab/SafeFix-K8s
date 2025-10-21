# rbac-police Installation & Integration

## ✅ Installation Complete

rbac-police has been successfully installed and integrated into the SafeFixK8s pipeline.

### Installation Location
```
SafeFixK8s\tools\rbac-police\
├── bin\
│   └── rbac-police.exe    (50.6 MB)
└── lib\                   (20+ Rego policy files)
```

## How It Works

### Three-Tier Detection Approach

1. **Tier 1: Full Tool Analysis** (Active ✅)
   - Uses actual rbac-police tool with 20+ Rego policies
   - Evaluates RBAC permissions comprehensively
   - Detects privilege escalation paths
   
2. **Tier 2: Enhanced Basic Checks** (Fallback)
   - 11 comprehensive detection patterns
   - Pattern matching for common RBAC issues
   - Works without tool installation
   
3. **Tier 3: Graceful Degradation**
   - Informative placeholders when no RBAC files found
   - Clear messaging about tool availability

## Detection Capabilities

### With Tool (Current Setup)
- ✅ Wildcard permissions (verbs, resources, apiGroups)
- ✅ Privilege escalation paths (escalate, bind, impersonate)
- ✅ Dangerous permissions (exec, attach, secrets)
- ✅ Token security issues
- ✅ Node security issues
- ✅ Workload manipulation risks
- ✅ 20+ Rego policy evaluations

### Example Detection
```json
{
  "tool": "rbac-police",
  "file": "28.role_overly_permissive.yaml",
  "role": "frontend-role",
  "resource": "pods",
  "issue": "Combination of get and delete verbs - more permissions than necessary",
  "severity": "LOW",
  "type": "excessive-permissions",
  "recommendation": "Apply principle of least privilege - only grant necessary verbs"
}
```

## Usage

### Run RBAC Analysis
```powershell
cd detection
. .\detectors.ps1

# Analyze RBAC manifests
Det-RBACPolice "..\tests"

# Run full extended pipeline (11 tools)
Det-RunExtended "..\tests"
```

### Check Output
```powershell
# View raw findings
cat output\raw\rbacpolice_raw.json

# View normalized findings (after running normalizer)
cat ..\output\normalized_findings.json
```

## Build Instructions (For Reference)

### What You Did:
```bash
# 1. Installed Go from https://go.dev/doc/install

# 2. Built rbac-police from source
cd rbac-police
go build -o rbac-police.exe

# 3. Created installation directories
mkdir tools\rbac-police\bin
mkdir tools\rbac-police\lib

# 4. Copied files
copy rbac-police\rbac-police.exe tools\rbac-police\bin\
xcopy /E rbac-police\lib tools\rbac-police\lib\
```

### For Future Builds:
```powershell
# Update to latest version
cd rbac-police
git pull
go build -o rbac-police.exe
copy rbac-police.exe ..\tools\rbac-police\bin\rbac-police.exe
```

## Supported RBAC Manifests

The tool analyzes:
- ✅ **Role** - Namespace-scoped permissions
- ✅ **ClusterRole** - Cluster-wide permissions
- ✅ **RoleBinding** - Binds roles to users/groups/service accounts
- ✅ **ClusterRoleBinding** - Cluster-wide role bindings
- ✅ **ServiceAccount** - Identity for pods

## Policy Library

Located in `tools\rbac-police\lib\`:
- `escalate_bindroles_on_clusterroles.rego` - Detects bind/escalate abuse
- `wildcard_verbs.rego` - Detects wildcard permissions
- `create_pods.rego` - Detects pod creation risks
- `modify_workloads.rego` - Detects workload manipulation
- `obtain_token_*.rego` - Token security policies
- ...and 15+ more policies

## Integration Details

### Detection Function Path Search
1. ✅ Local tools directory: `SafeFixK8s\tools\rbac-police\bin\rbac-police.exe`
2. System PATH: `rbac-police` command
3. Fallback: Enhanced basic checks

### Library Path Search
1. ✅ Local tools directory: `SafeFixK8s\tools\rbac-police\lib\`
2. Program Files: `C:\Program Files\rbac-police\lib`
3. Source directory: `SafeFixK8s\rbac-police\lib\`

## Troubleshooting

### Tool Not Found
```powershell
# Verify installation
dir tools\rbac-police\bin\rbac-police.exe

# Test manually
.\tools\rbac-police\bin\rbac-police.exe help
```

### Library Not Found
```powershell
# Verify library
dir tools\rbac-police\lib\*.rego

# Should show 20+ .rego policy files
```

### Rebuild Binary
```powershell
cd rbac-police
go build -o rbac-police.exe
copy rbac-police.exe ..\tools\rbac-police\bin\rbac-police.exe -Force
```

## References

- **Source Code**: `SafeFixK8s\rbac-police\`
- **GitHub**: https://github.com/PaloAltoNetworks/rbac-police
- **Policy Documentation**: `rbac-police\docs\policies.md`
- **Usage Guide**: `rbac-police\README.md`

## Status

✅ **rbac-police is fully integrated and operational**

- Tool installed: Yes (local tools directory)
- Policy library: Yes (20+ Rego files)
- Integration: Complete (three-tier approach)
- Testing: Validated (detects excessive permissions)
- Ready for production use: Yes
