#!/usr/bin/env python3
"""Summarize all pipeline run results."""

from pathlib import Path
import json

def main():
    output_dir = Path('output')
    run_dirs = sorted(output_dir.glob('2025-11-06*'))
    
    print('\n=== COMPLETE PIPELINE SUMMARY ===\n')
    print(f'{"Tool":<15} | {"Raw":>4} | {"Norm":>4} | {"Fixes":>5} | {"Time":>6}')
    print('-' * 60)
    
    total_raw = 0
    total_norm = 0
    total_patches = 0
    
    for run_dir in run_dirs:
        tool = run_dir.name.split('__')[-1]
        
        # Load metadata
        meta_file = run_dir / 'metadata.json'
        if meta_file.exists():
            with open(meta_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
        else:
            metadata = {}
        
        # Count patch files
        patch_dir = run_dir / 'llm' / 'patch_sandbox'
        patch_files = list(patch_dir.glob('*.yaml')) if patch_dir.exists() else []
        
        raw = metadata.get('results', {}).get('raw_findings', 0)
        norm = metadata.get('results', {}).get('normalized_findings', 0)
        fixes = len(patch_files)
        duration = metadata.get('total_duration', 0)
        
        total_raw += raw
        total_norm += norm
        total_patches += fixes
        
        print(f'{tool:<15} | {raw:4} | {norm:4} | {fixes:5} | {duration:5.0f}s')
    
    print('-' * 60)
    print(f'{"TOTAL":<15} | {total_raw:4} | {total_norm:4} | {total_patches:5} |')
    print()

if __name__ == '__main__':
    main()
