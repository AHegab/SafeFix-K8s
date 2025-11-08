#!/usr/bin/env python3
"""
Check validation progress - monitors latest run for validation evidence
"""
import json
from pathlib import Path

# Find latest Checkov run
output_dir = Path("output")
checkov_runs = sorted(output_dir.glob("*__Checkov"), reverse=True)

if not checkov_runs:
    print("❌ No Checkov runs found")
    exit(1)

latest_run = checkov_runs[0]
print(f"📁 Latest run: {latest_run.name}\n")

# Check validation directory
validation_dir = latest_run / "validation"
if not validation_dir.exists():
    print("⏳ Validation directory not created yet")
    exit(0)

# Check manifests directory
manifests_dir = validation_dir / "manifests"
if manifests_dir.exists():
    yaml_files = list(manifests_dir.glob("*.yaml"))
    print(f"📋 Flattened manifests: {len(yaml_files)} files")
    for f in yaml_files[:10]:  # Show first 10
        print(f"   - {f.name}")
    if len(yaml_files) > 10:
        print(f"   ... and {len(yaml_files) - 10} more")
else:
    print("⏳ Manifests directory not created yet")

print()

# Check evidence directory
evidence_dir = validation_dir / "evidence"
if evidence_dir.exists():
    evidence_files = list(evidence_dir.rglob("*.*"))
    print(f"✅ Evidence files: {len(evidence_files)} files")
    
    if evidence_files:
        # Group by gate
        by_gate = {}
        for f in evidence_files:
            gate = f.parent.name if f.parent != evidence_dir else "root"
            by_gate.setdefault(gate, []).append(f.name)
        
        for gate, files in sorted(by_gate.items()):
            print(f"\n   {gate}: {len(files)} files")
            for file in files[:5]:
                print(f"      - {file}")
            if len(files) > 5:
                print(f"      ... and {len(files) - 5} more")
    else:
        print("⏳ No evidence files generated yet")
else:
    print("⏳ Evidence directory not created yet")

print()

# Check metadata
metadata_file = latest_run / "metadata.json"
if metadata_file.exists():
    with open(metadata_file) as f:
        metadata = json.load(f)
    
    print("📊 Metadata:")
    print(f"   Steps completed: {', '.join(metadata.get('steps_completed', []))}")
    print(f"   Gates passed: {metadata.get('gates_passed', 0)}")
    print(f"   Gates failed: {metadata.get('gates_failed', 0)}")
    print(f"   Fixes generated: {metadata.get('fixes_generated', 0)}")
    
    if 'timings' in metadata:
        print(f"\n⏱️  Timings:")
        for step, duration in metadata['timings'].items():
            print(f"   {step}: {duration:.1f}s")
else:
    print("⏳ Metadata not written yet")
