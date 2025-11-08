#!/usr/bin/env python3
"""Check LLM results across all tool runs."""

from pathlib import Path
import json

def main():
    output_dir = Path('output')
    run_dirs = sorted(output_dir.glob('2025-11-06*'))
    
    print('\n=== LLM PROCESSING RESULTS ===\n')
    print(f'{"Tool":<15} | {"Items":>5} | {"Fix":>4} | {"Ignore":>6} | {"Review":>6}')
    print('-' * 60)
    
    total_items = 0
    total_fixes = 0
    total_ignore = 0
    total_review = 0
    
    for run_dir in run_dirs:
        tool = run_dir.name.split('__')[-1]
        
        decisions_file = run_dir / 'llm' / 'llm_decisions.json'
        if not decisions_file.exists():
            continue
        
        try:
            with open(decisions_file, 'r', encoding='utf-8') as f:
                decisions = json.load(f)
            
            # Handle both dict and list formats
            if isinstance(decisions, dict):
                decisions = list(decisions.values())
            
            items = len(decisions)
            fixes = len([x for x in decisions if x.get('consensus', {}).get('final_classification') == 'fix'])
            ignore = len([x for x in decisions if x.get('consensus', {}).get('final_classification') == 'ignore'])
            review = len([x for x in decisions if x.get('consensus', {}).get('final_classification') == 'needs_review'])
            
            total_items += items
            total_fixes += fixes
            total_ignore += ignore
            total_review += review
            
            print(f'{tool:<15} | {items:5} | {fixes:4} | {ignore:6} | {review:6}')
            
        except Exception as e:
            print(f'{tool:<15} | Error: {e}')
    
    print('-' * 60)
    print(f'{"TOTAL":<15} | {total_items:5} | {total_fixes:4} | {total_ignore:6} | {total_review:6}')
    print()

if __name__ == '__main__':
    main()
