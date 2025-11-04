import json
from pathlib import Path
from collections import defaultdict

# Load conftest results
with open('Detection/output/raw/conftest_raw.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

results = defaultdict(set)
unmapped_messages = []

for result in data:
    filename = Path(result.get('filename', '')).name
    if not filename:
        continue
    
    all_issues = result.get('warnings', []) + result.get('failures', [])
    
    for issue in all_issues:
        msg = issue.get('msg', '').lower() if isinstance(issue, dict) else str(issue).lower()
        matched = False
        
        # Try each pattern
        if 'cpu limit' in msg or 'missing cpu limit' in msg or 'must set cpu limit' in msg:
            results[filename].add('No CPU limit')
            matched = True
        if 'cpu request' in msg or 'missing cpu request' in msg or 'must set cpu request' in msg:
            results[filename].add('No CPU request')
            matched = True
        if 'memory limit' in msg or 'missing memory limit' in msg or 'must set memory limit' in msg:
            results[filename].add('No memory limit')
            matched = True
        if 'memory request' in msg or 'missing memory request' in msg or 'must set memory request' in msg:
            results[filename].add('No memory request')
            matched = True
        if 'livenessprobe' in msg or 'missing livenessprobe' in msg:
            results[filename].add('No livenessProbe')
            matched = True
        if 'readinessprobe' in msg or 'missing readinessprobe' in msg:
            results[filename].add('No readinessProbe')
            matched = True
        if ('privileged' in msg and 'container' in msg) or 'is privileged' in msg or 'must not be privileged' in msg:
            results[filename].add('Privileged container')
            matched = True
        if 'allowprivilegeescalation' in msg or 'must set allowprivilegeescalation' in msg:
            results[filename].add('Privilege escalation allowed')
            matched = True
        if 'runasnonroot' in msg or 'must set runasnonroot' in msg:
            results[filename].add('Runs as root user')
            matched = True
        if 'readonlyrootfilesystem' in msg:
            results[filename].add('Filesystem not read-only')
            matched = True
        if 'capabilities' in msg or 'drop all' in msg:
            results[filename].add('Default capabilities not dropped')
            matched = True
        if ('securitycontext' in msg and ('define' in msg or 'missing' in msg)) or 'must define spec.securitycontext' in msg:
            results[filename].add('No security context')
            matched = True
        if 'seccomp' in msg:
            results[filename].add('No seccomp profile')
            matched = True
        if 'apparmor' in msg:
            results[filename].add('No AppArmor profile')
            matched = True
        if 'serviceaccounttoken' in msg or 'automount' in msg:
            results[filename].add('Default service account token mounted')
            matched = True
        if 'default namespace' in msg or 'no namespace' in msg or 'namespace set (defaults to' in msg or 'resource in default namespace' in msg:
            results[filename].add('Default namespace')
            matched = True
        if 'docker.sock' in msg or 'docker socket' in msg or 'hostpath' in msg:
            results[filename].add('Docker socket mounted')
            matched = True
        if ('latest' in msg and ('tag' in msg or 'image' in msg or 'uses' in msg)) or 'has no tag' in msg:
            results[filename].add('Using latest tag')
            matched = True
        if 'digest' in msg or 'immutable tag' in msg:
            results[filename].add('Image not pinned by digest')
            matched = True
        if 'imagepullpolicy' in msg or 'pull policy' in msg or 'should be' in msg:
            results[filename].add('ImagePullPolicy not Always')
            matched = True
        if ('secret' in msg and ('plain' in msg or 'unencrypted' in msg or 'opaque' in msg or 'must be encrypted' in msg)) or 'without encryption' in msg:
            results[filename].add('Unencrypted Secret')
            matched = True
        if ('cni' in msg and 'privileged' in msg) or 'embedded config' in msg or 'cni config in' in msg:
            results[filename].add('Privileged CNI plugin config')
            matched = True
        if 'networkpolicy' in msg and ('selector' in msg or 'endpointselector' in msg or "use 'selector'" in msg):
            results[filename].add('NetworkPolicy missing selectors')
            matched = True
            
        if not matched:
            unmapped_messages.append((filename, issue.get('msg', '')))

# Count total detections
total_detections = sum(len(vulns) for vulns in results.values())

print(f"Total detections mapped: {total_detections}")
print(f"Total unmapped messages: {len(unmapped_messages)}")

if unmapped_messages:
    print("\n=== UNMAPPED MESSAGES ===")
    for filename, msg in unmapped_messages[:20]:  # Show first 20
        print(f"{filename}: {msg}")
