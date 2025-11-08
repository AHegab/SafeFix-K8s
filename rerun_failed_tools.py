#!/usr/bin/env python3
"""
Rerun only the tools that had issues:
1. Conftest - YAML syntax errors (now fixed)
2. KubeLinter - Has findings but missing normalizer mappings
3. Kubescape - Has findings but missing normalizer mappings  
4. Polaris - Needs checking
5. KubeScore - Needs checking
6. Pluto - Needs checking
"""

import subprocess
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime

# Tools to rerun
TOOLS_TO_RERUN = [
    "Conftest",      # Was failing due to YAML syntax - now fixed
]

TOOLS_NEED_NORMALIZERS = [
    "KubeLinter",    # 49 findings, 0 normalized
    "Kubescape",     # 10 findings, 0 normalized
    "Polaris",       # Check if has findings
    "KubeScore",     # Check if has findings
]

REPO_ROOT = Path(__file__).parent.absolute()
OUTPUT_DIR = REPO_ROOT / "output"
FINAL_FIXES_DIR = OUTPUT_DIR / "all_tools_final_fixes"

def run_tool(tool_name):
    """Run complete pipeline for a single tool."""
    print(f"\n{'='*80}")
    print(f"🔧 Rerunning pipeline for: {tool_name}")
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
    """Rerun failed tools and collect final fixes."""
    print("\n" + "="*80)
    print("🔄 SafeFix-K8s: Rerunning Tools with Issues")
    print("="*80)
    print(f"Tools to rerun: {', '.join(TOOLS_TO_RERUN)}")
    print(f"Note: {len(TOOLS_NEED_NORMALIZERS)} tools need normalizer mappings")
    print("="*80 + "\n")
    
    results = {}
    run_dirs = {}
    
    # Rerun tools
    for i, tool in enumerate(TOOLS_TO_RERUN, 1):
        print(f"\n[{i}/{len(TOOLS_TO_RERUN)}] Processing {tool}...")
        
        try:
            success = run_tool(tool)
            results[tool] = "✅ Success" if success else "❌ Failed"
            
            # Find the run directory (most recent)
            pattern = f"*__{tool}"
            matching_dirs = sorted(OUTPUT_DIR.glob(pattern), reverse=True)
            if matching_dirs:
                run_dirs[tool] = matching_dirs[0]
            
        except KeyboardInterrupt:
            print(f"\n⚠️ Rerun interrupted by user at {tool}\n")
            break
        except Exception as e:
            print(f"\n❌ Error running {tool}: {e}\n")
            results[tool] = f"❌ Error: {e}"
    
    # Collect final fixes
    print("\n" + "="*80)
    print("📦 COLLECTING FINAL FIXES")
    print("="*80 + "\n")
    
    fix_counts = {}
    for tool in TOOLS_TO_RERUN:
        if tool in run_dirs:
            fix_counts[tool] = collect_final_fixes(tool, run_dirs[tool])
        else:
            fix_counts[tool] = 0
    
    # Summary
    print("\n" + "="*80)
    print("📊 RERUN SUMMARY")
    print("="*80)
    
    print("\n🔧 Execution Results:")
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
    print(f"✅ TOTAL NEW FIXES COLLECTED: {total_fixes}")
    print(f"📂 All fixes saved to: {FINAL_FIXES_DIR}")
    print("="*80 + "\n")
    
    # Tools needing normalizers
    print("\n⚠️  TOOLS NEEDING NORMALIZER MAPPINGS:")
    for tool in TOOLS_NEED_NORMALIZERS:
        pattern = f"*__{tool}"
        matching_dirs = sorted(OUTPUT_DIR.glob(pattern), reverse=True)
        if matching_dirs:
            metadata_file = matching_dirs[0] / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file) as f:
                    meta = json.load(f)
                    raw = meta.get("results", {}).get("raw_findings", 0)
                    norm = meta.get("results", {}).get("normalized_findings", 0)
                    print(f"  {tool:15} | {raw:3d} raw findings → {norm:3d} normalized (needs mapping)")
    
    print("\n💡 To enable these tools, add normalizer mappings in:")
    print("   Normalizer/normalize.py")
    print("\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Rerun interrupted by user\n")
        sys.exit(1)
