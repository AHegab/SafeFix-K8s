import json
from pathlib import Path

decisions_file = Path(r"C:\Users\Ahmed\OneDrive - GIU AS - German International University of Applied Sciences\Desktop\Bsc Thesis\Implementaions\SafeFixK8s\output\2025-11-06__17-14-43__Checkov\llm\llm_decisions.json")

data = json.loads(decisions_file.read_text(encoding='utf-8'))

fixes = [i for i in data if i.get('consensus', {}).get('final_classification') == 'fix']
passed = [i for i in data if i.get('validation', {}).get('status') == 'pass']
both = [i for i in data if i.get('consensus', {}).get('final_classification') == 'fix' and i.get('validation', {}).get('status') == 'pass']

print(f'Total items: {len(data)}')
print(f'Classified as "fix": {len(fixes)}')
print(f'Passed validation: {len(passed)}')
print(f'Both (fix AND pass): {len(both)}')

print(f'\nPassed validation details:')
for i in passed:
    classification = i.get('consensus', {}).get('final_classification', 'unknown')
    print(f"  {i['id']} - file={Path(i['file']).name} - {i['category']} - classification={classification}")
