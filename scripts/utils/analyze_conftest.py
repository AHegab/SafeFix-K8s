import json
from collections import defaultdict

# Load conftest results
with open('Detection/output/raw/conftest_raw.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

# Extract all messages
all_msgs = []
for result in data:
    all_msgs.extend(result.get('warnings', []) + result.get('failures', []))

print(f"Total messages: {len(all_msgs)}")
print(f"Unique messages: {len(set([m['msg'] for m in all_msgs]))}")

# Count messages by pattern
pattern_counts = defaultdict(int)
for msg_obj in all_msgs:
    msg = msg_obj['msg'].lower()
    
    if 'cpu limit' in msg:
        pattern_counts['CPU limit'] += 1
    if 'cpu request' in msg:
        pattern_counts['CPU request'] += 1
    if 'memory limit' in msg:
        pattern_counts['Memory limit'] += 1
    if 'memory request' in msg:
        pattern_counts['Memory request'] += 1
    if 'livenessprobe' in msg:
        pattern_counts['livenessProbe'] += 1
    if 'readinessprobe' in msg:
        pattern_counts['readinessProbe'] += 1
    if 'privileged' in msg:
        pattern_counts['Privileged'] += 1
    if 'allowprivilegeescalation' in msg:
        pattern_counts['allowPrivilegeEscalation'] += 1
    if 'runasnonroot' in msg:
        pattern_counts['runAsNonRoot'] += 1
    if 'readonlyrootfilesystem' in msg:
        pattern_counts['readOnlyRootFilesystem'] += 1
    if 'capabilities' in msg:
        pattern_counts['Capabilities'] += 1
    if 'securitycontext' in msg:
        pattern_counts['securityContext'] += 1
    if 'seccomp' in msg:
        pattern_counts['Seccomp'] += 1
    if 'apparmor' in msg:
        pattern_counts['AppArmor'] += 1
    if 'namespace' in msg:
        pattern_counts['Namespace'] += 1
    if 'docker.sock' in msg or 'hostpath' in msg:
        pattern_counts['Docker socket / hostPath'] += 1
    if 'latest' in msg or 'tag' in msg:
        pattern_counts['Image tag'] += 1
    if 'imagepullpolicy' in msg:
        pattern_counts['imagePullPolicy'] += 1
    if 'secret' in msg:
        pattern_counts['Secret'] += 1
    if 'cni' in msg:
        pattern_counts['CNI'] += 1
    if 'networkpolicy' in msg:
        pattern_counts['NetworkPolicy'] += 1
    if 'automount' in msg:
        pattern_counts['automountServiceAccountToken'] += 1

print("\n=== Pattern Distribution ===")
for pattern, count in sorted(pattern_counts.items(), key=lambda x: -x[1]):
    print(f"{count:3d} messages - {pattern}")

print("\n=== Sample Messages (first 10 unique) ===")
unique_msgs = sorted(set([m['msg'] for m in all_msgs]))
for i, msg in enumerate(unique_msgs[:10], 1):
    print(f"{i}. {msg}")
