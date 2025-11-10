#!/usr/bin/env python3
"""
Show merged fixes summary - Display comprehensive overview of all merged final manifests.

Usage:
    python show_merged_fixes.py
"""

import json
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parent
FINAL_DIR = REPO_ROOT / "output" / "FINAL_SECURED_MANIFESTS"


def main():
    report_file = FINAL_DIR / "MERGE_REPORT.json"
    
    if not report_file.exists():
        print("❌ No merge report found. Run this first:")
        print("   python orchestrator\\merge_all_fixes.py")
        return
    
    report = json.loads(report_file.read_text(encoding='utf-8'))
    
    print("="*80)
    print("FINAL SECURED MANIFESTS - MERGE REPORT")
    print("="*80)
    print(f"Created: {report['created_at']}")
    print(f"Total files: {report['total_files']}")
    print(f"Total fixes: {report['total_fixes']}")
    print()
    
    # Group by merge strategy
    by_strategy = {}
    for file_info in report["files"]:
        strategy = file_info["merge_info"]["strategy"]
        by_strategy.setdefault(strategy, []).append(file_info)
    
    print("📊 MERGE STRATEGIES:")
    print(f"  Single tool fix:     {len(by_strategy.get('single', []))} files")
    print(f"  Identical fixes:     {len(by_strategy.get('identical', []))} files")
    print(f"  Best validation:     {len(by_strategy.get('best_validation', []))} files")
    print()
    
    # Detailed per-file breakdown
    print("="*80)
    print("DETAILED FILE BREAKDOWN")
    print("="*80)
    
    for idx, file_info in enumerate(report["files"], 1):
        print(f"\n[{idx}] {file_info['original_path']}")
        print(f"    Output: {file_info['output_file']}")
        print(f"    Fixes: {file_info['fixes_count']} from tools: {', '.join(set(file_info['tools']))}")
        
        merge_info = file_info["merge_info"]
        strategy = merge_info["strategy"]
        
        if strategy == "single":
            print(f"    Strategy: Single tool ({merge_info['tool']})")
            print(f"    Gates passed: {merge_info['gates_passed']}")
        
        elif strategy == "identical":
            print(f"    Strategy: All tools produced identical fixes")
            print(f"    Tools: {', '.join(merge_info['tools'])}")
            print(f"    Gates passed: {merge_info['gates_passed']}")
        
        elif strategy == "best_validation":
            print(f"    Strategy: Selected best validated fix")
            print(f"    Selected tool: {merge_info['selected_tool']}")
            print(f"    Gates passed: {merge_info['gates_passed']}")
            print(f"    Alternatives: {merge_info['alternatives']}")
            print(f"    All tools: {', '.join(merge_info['all_tools'])}")
    
    print("\n" + "="*80)
    print("NEXT STEPS")
    print("="*80)
    print(f"📁 Final manifests: {FINAL_DIR}")
    print(f"📄 Merge report:    {report_file}")
    print(f"🔍 Comparisons:     {FINAL_DIR / 'comparisons'}")
    print()
    print("To validate final manifests:")
    print("  powershell .\\Validations\\validate-gates.ps1 -InputDir .\\output\\FINAL_SECURED_MANIFESTS -Gates schema,policy")
    print()
    print("To deploy to cluster:")
    print("  kubectl apply -f output/FINAL_SECURED_MANIFESTS/tests_<filename>.yaml")
    print()

if __name__ == "__main__":
    main()
