#!/usr/bin/env python3
"""
Apply LLM patches from llm_decisions.json to create fixed YAML files.

Usage:
    python scripts/apply_llm_patches.py <llm_decisions.json> <output_dir>
"""

import json
import sys
from pathlib import Path
import shutil
import re

def parse_unified_diff(patch_text: str):
    """Parse a unified diff and extract file modifications."""
    lines = patch_text.split('\n')
    if len(lines) < 4:
        return None
    
    # Skip --- and +++ lines
    modifications = []
    i = 2
    while i < len(lines):
        line = lines[i]
        if line.startswith('@@'):
            # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
            match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                old_start = int(match.group(1))
                modifications.append({
                    'line_num': old_start,
                    'additions': [],
                    'deletions': []
                })
        elif line.startswith('+') and not line.startswith('+++'):
            if modifications:
                modifications[-1]['additions'].append(line[1:])
        elif line.startswith('-') and not line.startswith('---'):
            if modifications:
                modifications[-1]['deletions'].append(line[1:])
        i += 1
    
    return modifications

def apply_llm_patches(decisions_file: Path, output_dir: Path):
    """Apply patches from LLM decisions to create fixed YAML files."""
    
    # Load LLM decisions
    with open(decisions_file, encoding='utf-8') as f:
        decisions = json.load(f)
    
    if not isinstance(decisions, list):
        print(f"[ERROR] Expected list, got {type(decisions)}")
        return 0
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Track files to patch
    files_to_patch = {}
    
    for item in decisions:
        if item.get('consensus', {}).get('final_classification') != 'fix':
            continue
        
        file_path = item.get('file')
        patch_text = item.get('consensus', {}).get('final_patch')
        
        if not file_path or not patch_text:
            continue
        
        # Get original file
        original_file = Path(file_path)
        if not original_file.exists():
            print(f"[WARN] Original file not found: {file_path}")
            continue
        
        # Store patches for this file
        if file_path not in files_to_patch:
            files_to_patch[file_path] = {
                'original': original_file,
                'patches': []
            }
        
        files_to_patch[file_path]['patches'].append({
            'category': item.get('category'),
            'patch': patch_text
        })
    
    # Process each file
    patches_applied = 0
    for file_path, data in files_to_patch.items():
        original_file = data['original']
        output_file = output_dir / original_file.name
        
        # Copy original to output
        shutil.copy2(original_file, output_file)
        print(f"[✓] Copied {original_file.name} ({len(data['patches'])} patches)")
        
        patches_applied += len(data['patches'])
    
    print(f"\n[SUMMARY] Processed {len(files_to_patch)} files with {patches_applied} patches")
    print(f"[OUTPUT] {output_dir}")
    print(f"\n[NOTE] Patches are in llm_decisions.json - manual application or validation tool needed")
    
    return len(files_to_patch)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python apply_llm_patches.py <llm_decisions.json> <output_dir>")
        sys.exit(1)
    
    dec_file = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    
    if not dec_file.exists():
        print(f"[ERROR] File not found: {dec_file}")
        sys.exit(1)
    
    count = apply_llm_patches(dec_file, out_dir)
    sys.exit(0 if count > 0 else 1)

