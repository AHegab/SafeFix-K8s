#!/usr/bin/env python3
"""
Sequential execution of SafeFix-K8s pipeline for all detection tools.
Runs one tool at a time with full LLM and validation gates.
Generates final fixed YAML files that pass validation.
"""

import subprocess
import sys
import time
import json
import shutil
from pathlib import Path
from datetime import datetime

# All detection tools to run
TOOLS = [
    "checkov",
    "trivy",
    "kubeaudit",
    "conftest",
    "kubelinter",
    "kubescape",
    "polaris",
    "kube-score",
    "rbac-police",
    "pluto",
    "gitleaks",
    "kubeconform",
    "yamllint"
]

# Pipeline configuration - ALL 3 LLMs + ALL 7 gates
MODELS = "groq,openrouter,gemini"
GATES = "1,2,3,4,5,6,7"
TEST_PATH = "tests"

def collect_final_fixes(run_dir: Path, tool_name: str) -> dict:
    """Collect validated fix files from a tool run."""
    final_fixes_dir = Path("output") / "final_fixes" / tool_name
    final_fixes_dir.mkdir(parents=True, exist_ok=True)
    
    collected_files = []
    
    # Check for metadata
    metadata_path = run_dir / "metadata.json"
    if not metadata_path.exists():
        return {"tool": tool_name, "fixed_files": 0, "files": []}
    
    # Read validation results from llm_decisions.json
    llm_decisions_path = run_dir / "llm" / "llm_decisions.json"
    if not llm_decisions_path.exists():
        return {"tool": tool_name, "fixed_files": 0, "files": []}
    
    try:
        with open(llm_decisions_path, 'r', encoding='utf-8') as f:
            decisions = json.load(f)
        
        # Find all items with consensus=fix AND validation=pass
        for decision in decisions:
            consensus = decision.get("consensus", {}).get("final_classification")
            validation = decision.get("validation", {})
            
            if consensus == "fix" and validation.get("status") == "pass":
                # Get the sandbox path (the validated fixed file)
                sandbox_path = validation.get("sandbox_path")
                if sandbox_path and Path(sandbox_path).exists():
                    # Copy to final fixes directory
                    src_file = Path(sandbox_path)
                    # Preserve the relative path structure
                    rel_path = src_file.relative_to(run_dir / "llm" / "patch_sandbox" / str(decision.get("id", "unknown")[:2]))
                    dest_file = final_fixes_dir / rel_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dest_file)
                    collected_files.append(str(rel_path))
        
        return {
            "tool": tool_name,
            "fixed_files": len(collected_files),
            "files": collected_files
        }
    except Exception as e:
        print(f"  [!] Error collecting fixes: {e}")
        return {"tool": tool_name, "fixed_files": 0, "files": [], "error": str(e)}


def run_tool(tool_name: str) -> dict:
    """Run pipeline for a single tool and return results."""
    print(f"\n{'='*80}")
    print(f"Running: {tool_name.upper()}")
    print(f"{'='*80}")
    
    start_time = time.time()
    
    # Build command
    cmd = [
        sys.executable,
        "orchestrator/safefix_single_tool.py",
        "--tool", tool_name,
        "--path", TEST_PATH,
        "--models", MODELS,
        "--gates", GATES
    ]
    
    print(f"Command: {' '.join(cmd)}\n")
    
    try:
        # Run the pipeline
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout per tool
            encoding='utf-8',
            errors='replace'  # Handle unicode errors
        )
        
        elapsed = time.time() - start_time
        
        # Parse result
        success = result.returncode == 0
        
        # Find the run directory
        output_dir = Path("output")
        if output_dir.exists():
            # Find the most recent directory for this tool
            tool_dirs = sorted(output_dir.glob(f"*__{tool_name.title().replace('-', '')}"),
                             key=lambda x: x.stat().st_mtime, reverse=True)
            run_dir = tool_dirs[0] if tool_dirs else None
        else:
            run_dir = None
        
        # Collect final fixes
        fix_info = {"fixed_files": 0, "files": []}
        if run_dir and run_dir.exists():
            fix_info = collect_final_fixes(run_dir, tool_name)
        
        return {
            "tool": tool_name,
            "success": success,
            "returncode": result.returncode,
            "elapsed_time": round(elapsed, 2),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "run_dir": str(run_dir) if run_dir else None,
            "fixed_files": fix_info.get("fixed_files", 0),
            "files": fix_info.get("files", [])
        }
        
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        print(f"TIMEOUT after {elapsed:.1f}s")
        return {
            "tool": tool_name,
            "success": False,
            "returncode": -1,
            "elapsed_time": round(elapsed, 2),
            "stdout": "",
            "stderr": "Process timed out after 600 seconds",
            "fixed_files": 0,
            "files": []
        }
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"ERROR: {e}")
        return {
            "tool": tool_name,
            "success": False,
            "returncode": -2,
            "elapsed_time": round(elapsed, 2),
            "stdout": "",
            "stderr": str(e),
            "fixed_files": 0,
            "files": []
        }

def main():
    """Run pipeline for all tools sequentially."""
    print("SafeFix-K8s: Sequential Tool Execution")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Tools: {len(TOOLS)}")
    print(f"LLMs: {MODELS}")
    print(f"Gates: {GATES}")
    print(f"Path: {TEST_PATH}")
    
    results = []
    overall_start = time.time()
    
    # Run each tool
    for i, tool in enumerate(TOOLS, 1):
        print(f"\n{'#'*80}")
        print(f"# Tool {i}/{len(TOOLS)}: {tool.upper()}")
        print(f"{'#'*80}")
        
        result = run_tool(tool)
        results.append(result)
        
        # Print immediate result
        if result["success"]:
            print(f"\n[OK] {tool.upper()} completed in {result['elapsed_time']}s")
            if result.get("fixed_files", 0) > 0:
                print(f"      Generated {result['fixed_files']} validated fix file(s)")
                for f in result.get("files", []):
                    print(f"      - {f}")
        else:
            print(f"\n[FAIL] {tool.upper()} failed (code {result['returncode']}) after {result['elapsed_time']}s")
        
        # Show last 300 chars of output if available
        if result["stdout"]:
            last_lines = result["stdout"][-300:].strip()
            if last_lines:
                print(f"\n--- Last Output ---")
                print(last_lines)
        
        # Show errors if any
        if result["stderr"] and len(result["stderr"]) > 10:
            print(f"\n--- Errors ---")
            print(result["stderr"][-300:])
        
        # Brief pause between tools
        if i < len(TOOLS):
            print(f"\nWaiting 2 seconds before next tool...")
            time.sleep(2)
    
    # Summary
    overall_elapsed = time.time() - overall_start
    successful = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    total_fixes = sum(r.get("fixed_files", 0) for r in results)
    
    print(f"\n\n{'='*80}")
    print(f"EXECUTION SUMMARY")
    print(f"{'='*80}")
    print(f"Total Time: {overall_elapsed/60:.1f} minutes ({overall_elapsed:.1f}s)")
    print(f"Successful: {len(successful)}/{len(TOOLS)}")
    print(f"Failed: {len(failed)}/{len(TOOLS)}")
    print(f"Total Fixed Files: {total_fixes}")
    
    if successful:
        print(f"\n[OK] Successful Tools:")
        for r in successful:
            fixes = r.get("fixed_files", 0)
            print(f"   - {r['tool']:15s} ({r['elapsed_time']:6.1f}s) - {fixes} fix(es)")
    
    if failed:
        print(f"\n[FAIL] Failed Tools:")
        for r in failed:
            print(f"   - {r['tool']:15s} (code {r['returncode']}, {r['elapsed_time']:6.1f}s)")
    
    print(f"\nFinal fixed files located in: output/final_fixes/")
    print(f"{'='*80}\n")
    
    # Save summary
    summary_path = Path("output") / "pipeline_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump({
            "execution_date": datetime.now().isoformat(),
            "total_time": round(overall_elapsed, 2),
            "models": MODELS,
            "gates": GATES,
            "test_path": TEST_PATH,
            "tools_run": len(TOOLS),
            "successful": len(successful),
            "failed": len(failed),
            "total_fixes": total_fixes,
            "results": results
        }, f, indent=2)
    print(f"Summary saved to: {summary_path}")
    
    # Exit code based on results
    return 0 if len(successful) == len(TOOLS) else 1

if __name__ == "__main__":
    sys.exit(main())
