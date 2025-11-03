import json
from pathlib import Path

# Load Conftest results
with open('Detection/output/raw/conftest_raw.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

# Find privileged container messages
print("Files where Conftest detects 'privileged':")
print("=" * 70)

for result in data:
    filename = Path(result.get('filename', '')).name
    if not filename:
        continue
    
    all_issues = result.get('warnings', []) + result.get('failures', [])
    
    privileged_messages = []
    for issue in all_issues:
        msg = issue.get('msg', '') if isinstance(issue, dict) else str(issue)
        if 'privileged' in msg.lower():
            privileged_messages.append(msg)
    
    if privileged_messages:
        print(f"\n{filename}:")
        for msg in privileged_messages:
            print(f"  - {msg}")

# Now show which files other tools say have privileged containers
import csv
with open('output/Coverage_Matrix_Updated.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

privileged_files = set()
for row in rows:
    if row['Vulns'] == 'Privileged container':
        # Check if any tool detected it
        has_detection = False
        for tool in ['Trivy', 'Checkov', 'Kubeaudit', 'KubeLinter', 'Polaris', 'KubeScore', 'Kubescape']:
            if row.get(tool, '').strip():
                has_detection = True
                break
        if has_detection:
            privileged_files.add(row['File'])

print("\n" + "=" * 70)
print("\nFiles OTHER TOOLS say have privileged containers:")
for f in sorted(privileged_files):
    print(f"  - {f}")

print(f"\nTotal: {len(privileged_files)} files")
