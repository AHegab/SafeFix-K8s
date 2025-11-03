import csv

rows = list(csv.DictReader(open('output/Coverage_Matrix_Updated.csv', encoding='utf-8-sig')))

print("=" * 70)
print("PRIVILEGED CONTAINER DETECTION BY FILE")
print("=" * 70)

priv_files = {}
for r in rows:
    if r['Vulns'] == 'Privileged container':
        file = r['File']
        conftest = r.get('Conftest (OPA)', '').strip()
        other_tools = []
        for tool in ['Trivy', 'Checkov', 'Kubeaudit', 'KubeLinter', 'Polaris', 'KubeScore', 'Kubescape']:
            if r.get(tool, '').strip():
                other_tools.append(tool)
        
        if file not in priv_files:
            priv_files[file] = {'conftest': bool(conftest), 'other_tools': other_tools}

for file, info in sorted(priv_files.items()):
    status = "✔" if info['conftest'] else "❌"
    print(f"{status} {file}")
    if not info['conftest']:
        print(f"   Detected by: {', '.join(info['other_tools'])}")

print(f"\nConftest detects: {sum(1 for i in priv_files.values() if i['conftest'])}/{len(priv_files)} files")
