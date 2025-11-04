import csv
from collections import defaultdict

# Load the CSV
with open('output/Coverage_Matrix_Updated.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

# Find what Conftest is missing
missing_by_vuln = defaultdict(list)
missing_by_file = defaultdict(list)

for row in rows:
    conftest = row.get('Conftest (OPA)', '').strip()
    if not conftest:  # Conftest didn't detect this
        vuln = row['Vulns']
        filename = row['File']
        
        # Check which other tools detected it
        other_tools = []
        for tool in ['Trivy', 'Checkov', 'Kubeaudit', 'KubeLinter', 'Polaris', 'KubeScore', 'Kubescape']:
            if row.get(tool, '').strip():
                other_tools.append(tool)
        
        if other_tools:  # At least one other tool detected it
            missing_by_vuln[vuln].append(filename)
            missing_by_file[filename].append(vuln)

print("=" * 80)
print("VULNERABILITIES CONFTEST IS MISSING (detected by other tools)")
print("=" * 80)
print(f"\n{len(missing_by_vuln)} vulnerability types still not detected by Conftest:\n")

for vuln, files in sorted(missing_by_vuln.items(), key=lambda x: -len(x[1])):
    print(f"  [{len(files):2d} files] {vuln}")

print(f"\n\nTotal missing: {sum(len(f) for f in missing_by_vuln.values())} vulnerability instances")

print("\n" + "=" * 80)
print("FILES WITH MOST MISSING DETECTIONS")
print("=" * 80)
for filename, vulns in sorted(missing_by_file.items(), key=lambda x: -len(x[1]))[:10]:
    print(f"\n{filename} ({len(vulns)} missing):")
    for vuln in vulns[:5]:
        print(f"  - {vuln}")
    if len(vulns) > 5:
        print(f"  ... and {len(vulns) - 5} more")
