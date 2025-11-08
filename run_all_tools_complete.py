#!/usr/bin/env python3
"""
Run complete pipeline for all 13 tools and collect final fixed files.
This will create a consolidated output with all accepted fixes from each tool.
"""

import subprocess
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime

# All available detection tools
TOOLS = [
    "Checkov",
    "Trivy", 
    "KubeAudit",
    "Conftest",
    "KubeLinter",
    "Kubescape",
    "Polaris",
    "KubeScore",
    "Pluto",
    "Gitleaks",
    "KubeConform",
    "Yamllint",
    "RbacPolice"
]

REPO_ROOT = Path(__file__).parent.absolute()
OUTPUT_DIR = REPO_ROOT / "output"
FINAL_FIXES_DIR = OUTPUT_DIR / "all_tools_final_fixes"

def run_tool(tool_name):
    """Run complete pipeline for a single tool."""
    print(f"\n{'='*80}")
    print(f"🔧 Starting pipeline for: {tool_name}")
    print(f"{'='*80}\n")
    
    cmd = [
        sys.executable,
        str(REPO_ROOT / "orchestrator" / "safefix_single_tool.py"),
        "--tool", tool_name.lower(),
        "--path", "tests",
        "--output-dir", "output",
        "--models", "groq,openai,anthropic",
        "--gates", "1,2,3,4,5,6,7"
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False, text=True)
        print(f"\n✅ {tool_name} completed successfully\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {tool_name} failed with error code {e.returncode}\n")
        return False
    except KeyboardInterrupt:
        print(f"\n⚠️ {tool_name} interrupted by user\n")
        raise

def collect_final_fixes(tool_name, run_dir):
    """Collect final fixed files from a tool's run."""
    print(f"\n📁 Collecting final fixes for {tool_name}...")
    
    # Find the most recent run directory for this tool
    if not run_dir or not run_dir.exists():
        pattern = f"*__{tool_name}"
        matching_dirs = sorted(OUTPUT_DIR.glob(pattern), reverse=True)
        if not matching_dirs:
            print(f"   ⚠️ No run directory found for {tool_name}")
            return 0
        run_dir = matching_dirs[0]
    
    # Read LLM decisions to find accepted fixes
    decisions_file = run_dir / "llm" / "llm_decisions.json"
    if not decisions_file.exists():
        print(f"   ⚠️ No LLM decisions found for {tool_name}")
        return 0
    
    with open(decisions_file, 'r', encoding='utf-8') as f:
        decisions = json.load(f)
    
    # Filter for accepted fixes (consensus = fix AND validation = pass)
    accepted = [
        d for d in decisions 
        if d.get("consensus", {}).get("final_classification") == "fix"
        and d.get("validation", {}).get("status") == "pass"
    ]
    
    if not accepted:
        print(f"   ⚠️ No accepted fixes found for {tool_name}")
        return 0
    
    # Create tool-specific output directory
    tool_output = FINAL_FIXES_DIR / tool_name
    tool_output.mkdir(parents=True, exist_ok=True)
    
    # Copy each accepted fix
    fixes_copied = 0
    for decision in accepted:
        sandbox_path = decision.get("validation", {}).get("sandbox_path")
        if sandbox_path and Path(sandbox_path).exists():
            # Preserve relative path structure
            relative_path = Path(decision["file"])
            dest_path = tool_output / relative_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(sandbox_path, dest_path)
            fixes_copied += 1
    
    print(f"   ✅ Collected {fixes_copied} final fixes from {tool_name}")
    
    # Save summary
    summary = {
        "tool": tool_name,
        "run_directory": str(run_dir),
        "timestamp": datetime.now().isoformat(),
        "total_decisions": len(decisions),
        "accepted_fixes": len(accepted),
        "fixes_copied": fixes_copied,
        "accepted_details": [
            {
                "file": d["file"],
                "category": d.get("category"),
                "severity": d.get("severity"),
                "sandbox_path": d.get("validation", {}).get("sandbox_path")
            }
            for d in accepted
        ]
    }
    
    with open(tool_output / f"{tool_name}_summary.json", 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    return fixes_copied

def main():
    """Run all tools and collect final fixes."""
    print("\n" + "="*80)
    print("🚀 SafeFix-K8s: Complete Pipeline for All 13 Tools")
    print("="*80)
    print(f"Tools to run: {', '.join(TOOLS)}")
    print(f"Target: tests/")
    print(f"Output: output/")
    print(f"Final fixes: {FINAL_FIXES_DIR}")
    print(f"Models: Groq, OpenAI, Anthropic")
    print(f"Gates: 1,2,3,4,5,6,7 (All)")
    print("="*80 + "\n")
    
    # Create final fixes directory
    FINAL_FIXES_DIR.mkdir(parents=True, exist_ok=True)
    
    results = {}
    run_dirs = {}
    
    # Step 1: Run pipeline for each tool
    for i, tool in enumerate(TOOLS, 1):
        print(f"\n[{i}/{len(TOOLS)}] Processing {tool}...")
        
        try:
            success = run_tool(tool)
            results[tool] = "✅ Success" if success else "❌ Failed"
            
            # Find the run directory (most recent)
            pattern = f"*__{tool}"
            matching_dirs = sorted(OUTPUT_DIR.glob(pattern), reverse=True)
            if matching_dirs:
                run_dirs[tool] = matching_dirs[0]
            
        except KeyboardInterrupt:
            print(f"\n⚠️ Pipeline interrupted by user at {tool}\n")
            break
        except Exception as e:
            print(f"\n❌ Error running {tool}: {e}\n")
            results[tool] = f"❌ Error: {e}"
    
    # Step 2: Collect final fixes from all successful runs
    print("\n" + "="*80)
    print("📦 COLLECTING FINAL FIXES FROM ALL TOOLS")
    print("="*80 + "\n")
    
    fix_counts = {}
    for tool in TOOLS:
        if tool in run_dirs:
            fix_counts[tool] = collect_final_fixes(tool, run_dirs[tool])
        else:
            fix_counts[tool] = 0
    
    # Step 3: Print comprehensive summary
    print("\n" + "="*80)
    print("📊 FINAL SUMMARY - ALL TOOLS")
    print("="*80)
    
    print("\n🔧 Pipeline Execution Results:")
    for tool, status in results.items():
        print(f"  {tool:15} | {status}")
    
    print("\n📁 Final Fixes Collected:")
    total_fixes = 0
    for tool, count in fix_counts.items():
        if count > 0:
            print(f"  {tool:15} | {count:3d} fixes → {FINAL_FIXES_DIR / tool}")
            total_fixes += count
        else:
            print(f"  {tool:15} | {count:3d} fixes")
    
    print("\n" + "="*80)
    print(f"✅ TOTAL FIXES COLLECTED: {total_fixes}")
    print(f"📂 All fixes saved to: {FINAL_FIXES_DIR}")
    print("="*80 + "\n")
    
    # Create master index
    master_index = {
        "timestamp": datetime.now().isoformat(),
        "tools_run": len(results),
        "tools_successful": sum(1 for s in results.values() if "Success" in s),
        "total_fixes": total_fixes,
        "results": results,
        "fix_counts": fix_counts,
        "output_directory": str(FINAL_FIXES_DIR)
    }
    
    with open(FINAL_FIXES_DIR / "master_index.json", 'w', encoding='utf-8') as f:
        json.dump(master_index, f, indent=2)
    
    print(f"📄 Master index saved to: {FINAL_FIXES_DIR / 'master_index.json'}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Pipeline interrupted by user\n")
        sys.exit(1)
