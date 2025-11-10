#!/usr/bin/env python3
"""
Display validation results for each tool run.
Shows consensus voting, validation status, and final fixes.
"""

import json
import sys
from pathlib import Path
from collections import Counter

def analyze_validation(run_dir: Path):
    """Analyze validation results from a tool run."""
    
    # Read metadata
    metadata_path = run_dir / "metadata.json"
    if not metadata_path.exists():
        return None
    
    with open(metadata_path, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    
    # Read LLM decisions
    decisions_path = run_dir / "llm" / "llm_decisions.json"
    if not decisions_path.exists():
        return {
            "tool": metadata.get("tool", "Unknown"),
            "models": metadata.get("models", []),
            "gates": metadata.get("gates", ""),
            "total_items": 0,
            "validation_summary": {}
        }
    
    with open(decisions_path, 'r', encoding='utf-8') as f:
        decisions = json.load(f)
    
    # Analyze consensus and validation
    consensus_counts = Counter()
    validation_counts = Counter()
    model_vote_counts = {model: Counter() for model in metadata.get("models", [])}
    validated_fixes = []
    
    for decision in decisions:
        # Consensus classification
        consensus_cls = decision.get("consensus", {}).get("final_classification", "unknown")
        consensus_counts[consensus_cls] += 1
        
        # Validation status
        validation = decision.get("validation", {})
        val_status = validation.get("status", "unknown")
        validation_counts[val_status] += 1
        
        # Individual model votes
        votes = decision.get("consensus", {}).get("votes", {})
        for model, vote_info in votes.items():
            vote_cls = vote_info.get("classification", "unknown")
            model_vote_counts[model][vote_cls] += 1
        
        # Collect validated fixes
        if consensus_cls == "fix" and val_status == "pass":
            validated_fixes.append({
                "file": decision.get("file", ""),
                "category": decision.get("category", ""),
                "sandbox_path": validation.get("sandbox_path", ""),
                "reason": validation.get("reason", ""),
                "hygiene": validation.get("hygiene", {}).get("applied", [])
            })
    
    return {
        "tool": metadata.get("tool", "Unknown"),
        "models": metadata.get("models", []),
        "gates": metadata.get("gates", ""),
        "total_items": len(decisions),
        "consensus_summary": dict(consensus_counts),
        "validation_summary": dict(validation_counts),
        "model_votes": {model: dict(votes) for model, votes in model_vote_counts.items()},
        "validated_fixes": validated_fixes,
        "timings": metadata.get("timings", {}),
        "total_duration": metadata.get("total_duration", 0)
    }

def print_tool_report(analysis):
    """Print a detailed report for one tool."""
    if not analysis:
        return
    
    print(f"\n{'='*100}")
    print(f"TOOL: {analysis['tool']}")
    print(f"{'='*100}")
    print(f"LLMs Used: {', '.join(analysis['models'])}")
    print(f"Gates: {analysis['gates']}")
    print(f"Total Items Processed: {analysis['total_items']}")
    print(f"Total Duration: {analysis.get('total_duration', 0):.1f}s")
    
    # Consensus summary
    print(f"\n--- CONSENSUS VOTING RESULTS ---")
    consensus = analysis.get('consensus_summary', {})
    for cls, count in sorted(consensus.items(), key=lambda x: x[1], reverse=True):
        pct = (count / analysis['total_items'] * 100) if analysis['total_items'] > 0 else 0
        print(f"  {cls:20s}: {count:3d} ({pct:5.1f}%)")
    
    # Model-by-model breakdown
    print(f"\n--- INDIVIDUAL MODEL VOTES ---")
    for model, votes in analysis.get('model_votes', {}).items():
        print(f"  {model.upper()}:")
        for cls, count in sorted(votes.items(), key=lambda x: x[1], reverse=True):
            pct = (count / analysis['total_items'] * 100) if analysis['total_items'] > 0 else 0
            print(f"    {cls:20s}: {count:3d} ({pct:5.1f}%)")
    
    # Validation results
    print(f"\n--- VALIDATION RESULTS ---")
    validation = analysis.get('validation_summary', {})
    for status, count in sorted(validation.items(), key=lambda x: x[1], reverse=True):
        pct = (count / analysis['total_items'] * 100) if analysis['total_items'] > 0 else 0
        print(f"  {status:20s}: {count:3d} ({pct:5.1f}%)")
    
    # Validated fixes
    validated_fixes = analysis.get('validated_fixes', [])
    print(f"\n--- VALIDATED FIXES (consensus=fix AND validation=pass) ---")
    print(f"Total Validated Fixes: {len(validated_fixes)}")
    
    if validated_fixes:
        # Group by file
        files = {}
        for fix in validated_fixes:
            file = fix['file']
            if file not in files:
                files[file] = []
            files[file].append(fix)
        
        for file, fixes in sorted(files.items()):
            print(f"\n  File: {file}")
            print(f"  Fixes: {len(fixes)}")
            for fix in fixes:
                print(f"    - Category: {fix['category']}")
                print(f"      Validation Reason: {fix['reason']}")
                if fix.get('hygiene'):
                    print(f"      Hygiene Applied: {len(fix['hygiene'])} changes")
                print(f"      Fixed File: {fix.get('sandbox_path', 'N/A')}")

def main():
    """Main entry point."""
    output_dir = Path("output")
    
    if not output_dir.exists():
        print("No output directory found. Run the pipeline first.")
        return 1
    
    # Find all tool run directories
    run_dirs = sorted(output_dir.glob("*__*"), key=lambda x: x.stat().st_mtime)
    
    if not run_dirs:
        print("No tool runs found in output directory.")
        return 1
    
    print(f"\n{'#'*100}")
    print(f"# SAFEFIX-K8S: VALIDATION RESULTS FOR ALL TOOLS")
    print(f"{'#'*100}")
    
    all_analyses = []
    
    for run_dir in run_dirs:
        analysis = analyze_validation(run_dir)
        if analysis:
            all_analyses.append(analysis)
            print_tool_report(analysis)
    
    # Overall summary
    print(f"\n\n{'='*100}")
    print(f"OVERALL SUMMARY")
    print(f"{'='*100}")
    
    total_items = sum(a['total_items'] for a in all_analyses)
    total_validated = sum(len(a['validated_fixes']) for a in all_analyses)
    
    print(f"Tools Run: {len(all_analyses)}")
    print(f"Total Items Processed: {total_items}")
    print(f"Total Validated Fixes: {total_validated}")
    
    if total_items > 0:
        print(f"Validation Success Rate: {(total_validated / total_items * 100):.1f}%")
    
    # Tools with fixes
    tools_with_fixes = [a for a in all_analyses if len(a['validated_fixes']) > 0]
    if tools_with_fixes:
        print(f"\nTools with Validated Fixes:")
        for analysis in sorted(tools_with_fixes, key=lambda x: len(x['validated_fixes']), reverse=True):
            print(f"  - {analysis['tool']:15s}: {len(analysis['validated_fixes']):3d} fixes")
    
    # Files fixed
    all_files = set()
    for analysis in all_analyses:
        for fix in analysis['validated_fixes']:
            all_files.add(fix['file'])
    
    if all_files:
        print(f"\nTotal Unique Files Fixed: {len(all_files)}")
        for file in sorted(all_files):
            print(f"  - {file}")
    
    print(f"\n{'='*100}\n")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
