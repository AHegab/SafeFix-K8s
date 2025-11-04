import json
from pathlib import Path
from collections import defaultdict

# Load conftest results
with open('Detection/output/raw/conftest_raw.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

# Count what Conftest IS finding
conftest_findings = defaultdict(int)

for result in data:
    filename = Path(result.get('filename', '')).name
    if not filename:
        continue
    
    all_issues = result.get('warnings', []) + result.get('failures', [])
    
    for issue in all_issues:
        msg = issue.get('msg', '').lower() if isinstance(issue, dict) else str(issue).lower()
        
        # Categorize by what it detects
        if 'cpu limit' in msg or 'cpu request' in msg:
            conftest_findings['Resource limits (CPU)'] += 1
        if 'memory limit' in msg or 'memory request' in msg:
            conftest_findings['Resource limits (Memory)'] += 1
        if 'livenessprobe' in msg or 'readinessprobe' in msg:
            conftest_findings['Health probes'] += 1
        if 'privileged' in msg:
            conftest_findings['Privileged containers'] += 1
        if 'allowprivilegeescalation' in msg:
            conftest_findings['Privilege escalation'] += 1
        if 'runasnonroot' in msg:
            conftest_findings['RunAsNonRoot'] += 1
        if 'readonlyrootfilesystem' in msg:
            conftest_findings['Read-only filesystem'] += 1
        if 'capabilities' in msg:
            conftest_findings['Capabilities'] += 1
        if 'securitycontext' in msg:
            conftest_findings['Security context'] += 1
        if 'seccomp' in msg:
            conftest_findings['Seccomp'] += 1
        if 'apparmor' in msg:
            conftest_findings['AppArmor'] += 1
        if 'automount' in msg:
            conftest_findings['Service account token'] += 1
        if 'namespace' in msg:
            conftest_findings['Namespace'] += 1
        if 'docker.sock' in msg or 'hostpath' in msg:
            conftest_findings['Docker socket / hostPath'] += 1
        if 'latest' in msg or ('tag' in msg and 'no tag' in msg):
            conftest_findings['Image tags'] += 1
        if 'imagepullpolicy' in msg:
            conftest_findings['ImagePullPolicy'] += 1
        if 'secret' in msg:
            conftest_findings['Secrets'] += 1
        if 'cni' in msg or 'embedded config' in msg:
            conftest_findings['CNI config'] += 1
        if 'networkpolicy' in msg:
            conftest_findings['NetworkPolicy'] += 1

print("=" * 70)
print("WHAT CONFTEST IS DETECTING")
print("=" * 70)
for category, count in sorted(conftest_findings.items(), key=lambda x: -x[1]):
    print(f"{count:3d} messages - {category}")

print(f"\nTotal Conftest messages: {sum(conftest_findings.values())}")

# Now check what categories Conftest has NO policies for
print("\n" + "=" * 70)
print("CATEGORIES CONFTEST CANNOT DETECT (No OPA policies)")
print("=" * 70)

missing_policies = [
    "Ingress backend not found",
    "No TLS configured (Ingress)", 
    "No network policy",
    "Single replica (non-HA)",
    "Deployment selector missing",
    "Image not pinned by digest",
]

for cat in missing_policies:
    print(f"❌ {cat}")

print("\n💡 To increase Conftest detections, we need to:")
print("1. Create new OPA policies for missing categories")
print("2. Or accept that Conftest focuses on security/best practices")
