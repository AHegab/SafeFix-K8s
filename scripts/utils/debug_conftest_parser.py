import json
from pathlib import Path
from collections import defaultdict
import csv

# Load Conftest results
with open('Detection/output/raw/conftest_raw.json', 'r', encoding='utf-8-sig') as f:
    conftest_data = json.load(f)

# Load current CSV to see what we're missing
with open('output/Coverage_Matrix_Updated.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    csv_rows = list(reader)

# Build what Conftest SHOULD be detecting based on its messages
conftest_by_file = defaultdict(set)

for result in conftest_data:
    filename = Path(result.get('filename', '')).name
    if not filename:
        continue
    
    all_issues = result.get('warnings', []) + result.get('failures', [])
    
    for issue in all_issues:
        msg_orig = issue.get('msg', '') if isinstance(issue, dict) else str(issue)
        msg = msg_orig.lower()
        
        # Map to exact vulnerability category names from VULN_CATEGORIES
        if 'cpu limit' in msg or 'missing cpu limit' in msg or 'must set cpu limit' in msg:
            conftest_by_file[filename].add('No CPU limit')
        if 'cpu request' in msg or 'missing cpu request' in msg or 'must set cpu request' in msg:
            conftest_by_file[filename].add('No CPU request')
        if 'memory limit' in msg or 'missing memory limit' in msg or 'must set memory limit' in msg:
            conftest_by_file[filename].add('No memory limit')
        if 'memory request' in msg or 'missing memory request' in msg or 'must set memory request' in msg:
            conftest_by_file[filename].add('No memory request')
        if 'livenessprobe' in msg or 'missing livenessprobe' in msg:
            conftest_by_file[filename].add('No livenessProbe')
        if 'readinessprobe' in msg or 'missing readinessprobe' in msg:
            conftest_by_file[filename].add('No readinessProbe')
        if ('privileged' in msg and 'container' in msg) or 'is privileged' in msg or 'must not be privileged' in msg:
            conftest_by_file[filename].add('Privileged container')
        if 'allowprivilegeescalation' in msg or 'must set allowprivilegeescalation' in msg:
            conftest_by_file[filename].add('Privilege escalation allowed')
        if 'runasnonroot' in msg or 'must set runasnonroot' in msg:
            conftest_by_file[filename].add('Runs as root user')
        if 'readonlyrootfilesystem' in msg:
            conftest_by_file[filename].add('Filesystem not read-only')
        if 'capabilities' in msg or 'drop all' in msg:
            conftest_by_file[filename].add('Default capabilities not dropped')
        if ('securitycontext' in msg and ('define' in msg or 'missing' in msg)) or 'must define spec.securitycontext' in msg:
            conftest_by_file[filename].add('No security context')
        if 'seccomp' in msg:
            conftest_by_file[filename].add('No seccomp profile')
        if 'apparmor' in msg:
            conftest_by_file[filename].add('No AppArmor profile')
        if 'serviceaccounttoken' in msg or 'automount' in msg:
            conftest_by_file[filename].add('Default service account token mounted')
        if 'default namespace' in msg or 'no namespace' in msg or 'namespace set (defaults to' in msg or 'resource in default namespace' in msg:
            conftest_by_file[filename].add('Default namespace')
        if 'docker.sock' in msg or 'docker socket' in msg or 'hostpath' in msg or 'mounting docker.sock' in msg:
            conftest_by_file[filename].add('Docker socket mounted')
        if ('latest' in msg and ('tag' in msg or 'image' in msg or 'uses' in msg)) or 'has no tag' in msg:
            conftest_by_file[filename].add('Using latest tag')
        if 'digest' in msg or 'immutable tag' in msg:
            conftest_by_file[filename].add('Image not pinned by digest')
        if 'imagepullpolicy' in msg or 'pull policy' in msg or 'should be' in msg:
            conftest_by_file[filename].add('ImagePullPolicy not Always')
        if ('secret' in msg and ('plain' in msg or 'unencrypted' in msg or 'opaque' in msg or 'must be encrypted' in msg)) or 'without encryption' in msg:
            conftest_by_file[filename].add('Unencrypted Secret')
        if ('cni' in msg and 'privileged' in msg) or 'embedded config' in msg or 'cni config in' in msg:
            conftest_by_file[filename].add('Privileged CNI plugin config')
        if 'networkpolicy' in msg and ('selector' in msg or 'endpointselector' in msg or "use 'selector'" in msg):
            conftest_by_file[filename].add('NetworkPolicy missing selectors')

# Count total detections
total_should_detect = sum(len(vulns) for vulns in conftest_by_file.values())

print(f"Conftest SHOULD detect: {total_should_detect} vulnerability instances")
print(f"Conftest IS detecting (per CSV): 152 instances")
print(f"Gap: {total_should_detect - 152} instances\n")

# Find what's being missed
print("Files where Conftest has messages but they're not in CSV:")
print("=" * 70)

for filename, vulns in sorted(conftest_by_file.items()):
    # Check CSV
    csv_vulns = set()
    for row in csv_rows:
        if row['File'] == filename and row.get('Conftest (OPA)', '').strip():
            csv_vulns.add(row['Vulns'])
    
    missing = vulns - csv_vulns
    if missing:
        print(f"\n{filename}:")
        print(f"  Should have: {len(vulns)} detections")
        print(f"  CSV has: {len(csv_vulns)} detections")
        print(f"  Missing from CSV:")
        for m in sorted(missing):
            print(f"    - {m}")
