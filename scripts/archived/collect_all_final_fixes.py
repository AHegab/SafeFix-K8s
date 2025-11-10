#!/usr/bin/env python3
"""
Collect and summarize all final fixes from all tools.
This script will:
1. Find the most recent run for each tool
2. Collect accepted fixes (consensus=fix AND validation=pass)
3. Copy them to a clean final_fixes directory
4. Generate a comprehensive summary report
"""

import json
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

REPO_ROOT = Path(__file__).parent.absolute()
OUTPUT_DIR = REPO_ROOT / "output"
FINAL_FIXES_DIR = OUTPUT_DIR / "final_fixes_all_tools"

# All tools that were run
ALL_TOOLS = [
    "Checkov", "Trivy", "KubeAudit", "Conftest",
    "KubeLinter", "Kubescape", "Polaris", "KubeScore",
    "Pluto", "Gitleaks", "KubeConform", "Yamllint", "RBACPolice"
]

def find_latest_run(tool_name):
    """Find the most recent run directory for a tool."""
    pattern = f"*__{tool_name}"
    matching_dirs = sorted(OUTPUT_DIR.glob(pattern), reverse=True)
    return matching_dirs[0] if matching_dirs else None

def collect_fixes_from_run(run_dir, tool_name):
    """Collect all accepted fixes from a single run."""
    if not run_dir or not run_dir.exists():
        return {
            "tool": tool_name,
            "status": "no_run_found",
            "fixes": [],
            "raw_findings": 0,
            "normalized": 0,
            "total_decisions": 0,
            "accepted_count": 0
        }
    
    # Read metadata
    metadata_file = run_dir / "metadata.json"
    metadata = {}
    if metadata_file.exists():
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    
    # Read LLM decisions
    decisions_file = run_dir / "llm" / "llm_decisions.json"
    if not decisions_file.exists():
        return {
            "tool": tool_name,
            "status": "no_llm_decisions",
            "fixes": [],
            "raw_findings": metadata.get("results", {}).get("raw_findings", 0),
            "normalized": metadata.get("results", {}).get("normalized_findings", 0),
            "total_decisions": 0,
            "accepted_count": 0,
            "run_dir": str(run_dir)
        }
    
    with open(decisions_file, 'r', encoding='utf-8') as f:
        decisions = json.load(f)
    
    # Filter for accepted fixes
    accepted = [
        d for d in decisions 
        if d.get("consensus", {}).get("final_classification") == "fix"
        and d.get("validation", {}).get("status") == "pass"
    ]
    
    # Collect fix details
    fixes = []
    for decision in accepted:
        sandbox_path = decision.get("validation", {}).get("sandbox_path")
        fix_info = {
            "file": decision["file"],
            "category": decision.get("category"),
            "severity": decision.get("severity"),
            "sandbox_path": sandbox_path,
            "exists": Path(sandbox_path).exists() if sandbox_path else False
        }
        fixes.append(fix_info)
    
    return {
        "tool": tool_name,
        "status": "success" if accepted else "no_accepted_fixes",
        "fixes": fixes,
        "raw_findings": metadata.get("results", {}).get("raw_findings", 0),
        "normalized": metadata.get("results", {}).get("normalized_findings", 0),
        "total_decisions": len(decisions),
        "accepted_count": len(accepted),
        "run_dir": str(run_dir),
        "timestamp": metadata.get("timestamp"),
        "duration": metadata.get("total_duration")
    }

def copy_fixes_to_final(tool_results):
    """Copy all accepted fixes to final directory."""
    # Create final fixes directory
    FINAL_FIXES_DIR.mkdir(parents=True, exist_ok=True)
    
    for result in tool_results:
        if not result["fixes"]:
            continue
        
        tool_name = result["tool"]
        tool_dir = FINAL_FIXES_DIR / tool_name
        tool_dir.mkdir(parents=True, exist_ok=True)
        
        for fix in result["fixes"]:
            sandbox_path = fix["sandbox_path"]
            if not sandbox_path or not Path(sandbox_path).exists():
                continue
            
            # Preserve relative path
            relative_path = Path(fix["file"])
            dest_path = tool_dir / relative_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(sandbox_path, dest_path)
        
        # Save tool summary
        tool_summary = {
            "tool": tool_name,
            "timestamp": datetime.now().isoformat(),
            "run_directory": result["run_dir"],
            "raw_findings": result["raw_findings"],
            "normalized_findings": result["normalized"],
            "total_decisions": result["total_decisions"],
            "accepted_fixes": result["accepted_count"],
            "fixes": [
                {
                    "file": f["file"],
                    "category": f["category"],
                    "severity": f["severity"]
                }
                for f in result["fixes"]
            ]
        }
        
        with open(tool_dir / f"{tool_name}_summary.json", 'w', encoding='utf-8') as f:
            json.dump(tool_summary, f, indent=2)

def generate_report(tool_results):
    """Generate comprehensive summary report."""
    print("\n" + "="*90)
    print("  🎯 SAFEFIX-K8S: FINAL FIXES SUMMARY - ALL TOOLS")
    print("="*90 + "\n")
    
    # Tool-by-tool summary
    print("📊 TOOL-BY-TOOL RESULTS:\n")
    print(f"{'Tool':<15} | {'Raw':<5} | {'Norm':<5} | {'LLM':<5} | {'Fixes':<5} | Status")
    print("-" * 90)
    
    total_raw = 0
    total_norm = 0
    total_decisions = 0
    total_fixes = 0
    tools_with_fixes = 0
    
    for result in sorted(tool_results, key=lambda x: x["accepted_count"], reverse=True):
        tool = result["tool"]
        raw = result["raw_findings"]
        norm = result["normalized"]
        decisions = result["total_decisions"]
        fixes = result["accepted_count"]
        status = "✅" if fixes > 0 else "⚠️" if norm > 0 else "○"
        
        total_raw += raw
        total_norm += norm
        total_decisions += decisions
        total_fixes += fixes
        if fixes > 0:
            tools_with_fixes += 1
        
        print(f"{tool:<15} | {raw:>5} | {norm:>5} | {decisions:>5} | {fixes:>5} | {status}")
    
    print("-" * 90)
    print(f"{'TOTAL':<15} | {total_raw:>5} | {total_norm:>5} | {total_decisions:>5} | {total_fixes:>5} |")
    
    # Summary statistics
    print("\n" + "="*90)
    print("📈 SUMMARY STATISTICS:")
    print(f"  • Tools Run:              {len(ALL_TOOLS)}")
    print(f"  • Tools with Fixes:       {tools_with_fixes}")
    print(f"  • Total Raw Findings:     {total_raw}")
    print(f"  • Total Normalized:       {total_norm}")
    print(f"  • Total LLM Decisions:    {total_decisions}")
    print(f"  • Total Accepted Fixes:   {total_fixes}")
    print(f"  • Normalization Rate:     {(total_norm/total_raw*100):.1f}%" if total_raw > 0 else "  • Normalization Rate:     N/A")
    print(f"  • Fix Acceptance Rate:    {(total_fixes/total_decisions*100):.1f}%" if total_decisions > 0 else "  • Fix Acceptance Rate:    N/A")
    
    # Files fixed
    print("\n" + "="*90)
    print("📁 FILES WITH FIXES:\n")
    
    files_by_tool = defaultdict(set)
    for result in tool_results:
        for fix in result["fixes"]:
            files_by_tool[fix["file"]].add(result["tool"])
    
    for file in sorted(files_by_tool.keys()):
        tools = ", ".join(sorted(files_by_tool[file]))
        count = len(files_by_tool[file])
        print(f"  {file:<50} | {count} tool(s): {tools}")
    
    # Categories fixed
    print("\n" + "="*90)
    print("🔒 SECURITY CATEGORIES FIXED:\n")
    
    categories = defaultdict(int)
    for result in tool_results:
        for fix in result["fixes"]:
            if fix["category"]:
                categories[fix["category"]] += 1
    
    for category, count in sorted(categories.items(), key=lambda x: -x[1])[:20]:
        print(f"  {category:<50} | {count:>3} fixes")
    
    print("\n" + "="*90)
    print(f"✅ All fixes saved to: {FINAL_FIXES_DIR}")
    print("="*90 + "\n")
    
    # Save master index
    master_index = {
        "generated_at": datetime.now().isoformat(),
        "total_tools": len(ALL_TOOLS),
        "tools_with_fixes": tools_with_fixes,
        "total_raw_findings": total_raw,
        "total_normalized": total_norm,
        "total_llm_decisions": total_decisions,
        "total_accepted_fixes": total_fixes,
        "normalization_rate": f"{(total_norm/total_raw*100):.1f}%" if total_raw > 0 else "N/A",
        "fix_acceptance_rate": f"{(total_fixes/total_decisions*100):.1f}%" if total_decisions > 0 else "N/A",
        "tool_results": [
            {
                "tool": r["tool"],
                "status": r["status"],
                "raw_findings": r["raw_findings"],
                "normalized": r["normalized"],
                "total_decisions": r["total_decisions"],
                "accepted_count": r["accepted_count"],
                "run_dir": r["run_dir"]
            }
            for r in tool_results
        ],
        "files_fixed": {file: list(tools) for file, tools in files_by_tool.items()},
        "categories_fixed": dict(categories),
        "output_directory": str(FINAL_FIXES_DIR)
    }
    
    with open(FINAL_FIXES_DIR / "master_summary.json", 'w', encoding='utf-8') as f:
        json.dump(master_index, f, indent=2)
    
    print(f"📄 Master summary saved to: {FINAL_FIXES_DIR / 'master_summary.json'}\n")

def main():
    """Main execution."""
    print("\n🔍 Scanning for completed tool runs...")
    
    tool_results = []
    for tool in ALL_TOOLS:
        run_dir = find_latest_run(tool)
        result = collect_fixes_from_run(run_dir, tool)
        tool_results.append(result)
        
        if result["accepted_count"] > 0:
            print(f"  ✅ {tool}: {result['accepted_count']} fixes")
        elif result["normalized"] > 0:
            print(f"  ⚠️  {tool}: {result['normalized']} normalized but 0 fixes")
        elif result["raw_findings"] > 0:
            print(f"  ○  {tool}: {result['raw_findings']} raw findings (not normalized)")
        else:
            print(f"  ○  {tool}: No findings")
    
    print("\n📦 Copying fixes to final directory...")
    copy_fixes_to_final(tool_results)
    
    print("\n📊 Generating comprehensive report...")
    generate_report(tool_results)

if __name__ == "__main__":
    main()
