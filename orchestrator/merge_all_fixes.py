#!/usr/bin/env python3
"""
Merge All Fixes - Combine validated patches from all detection tools into unified final files.

This script:
1. Scans all tool outputs (Checkov, Trivy, KubeAudit, etc.)
2. Finds validated fixes (passed validation gates)
3. Merges multiple fixes for the same file into one unified patch
4. Produces final secured manifests ready for deployment

Usage:
    python orchestrator/merge_all_fixes.py
    python orchestrator/merge_all_fixes.py --output-dir final_patches
    python orchestrator/merge_all_fixes.py --min-gates 2  # Only merge if passed at least 2 gates
"""

import argparse
import json
import shutil
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
import yaml
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
FINAL_DIR = REPO_ROOT / "output" / "FINAL_SECURED_MANIFESTS"


def load_tool_results(output_dir: Path) -> List[Dict]:
    """
    Load all tool run results from output directory.
    
    Returns list of tool runs with metadata, validated fixes, and paths.
    """
    tool_runs = []
    
    # Find all tool output directories (format: 2025-11-06__16-47-54__Checkov)
    for run_dir in sorted(output_dir.iterdir(), reverse=True):
        if not run_dir.is_dir():
            continue
        
        # Extract tool name from directory (last component after __)
        parts = run_dir.name.split("__")
        if len(parts) < 3:
            continue
        
        tool_name = parts[-1]
        
        # Load metadata
        metadata_file = run_dir / "metadata.json"
        if not metadata_file.exists():
            continue
        
        try:
            metadata = json.loads(metadata_file.read_text(encoding='utf-8'))
        except:
            continue
        
        # Skip if no validation step
        if "validation" not in metadata.get("steps_completed", []):
            continue
        
        # Load safe_fix_proof.json
        proof_file = run_dir / "validation" / "safe_fix_proof.json"
        if not proof_file.exists():
            continue
        
        try:
            proof = json.loads(proof_file.read_text(encoding='utf-8'))
        except:
            continue
        
        tool_runs.append({
            "tool": tool_name,
            "run_dir": run_dir,
            "timestamp": metadata.get("timestamp"),
            "metadata": metadata,
            "proof": proof,
            "files": proof.get("files", [])
        })
    
    return tool_runs


def extract_validated_fixes(tool_runs: List[Dict], min_gates: int = 0) -> Dict[str, List[Dict]]:
    """
    Extract validated fixes grouped by original file path.
    
    Args:
        tool_runs: List of tool run results
        min_gates: Minimum number of gates that must pass (0 = include all)
    
    Returns:
        Dict mapping original file path -> list of validated fix info
    """
    fixes_by_file = defaultdict(list)
    
    for run in tool_runs:
        tool = run["tool"]
        
        for file_result in run["files"]:
            # Count passed gates
            gates = file_result.get("gates", [])
            passed = sum(1 for g in gates if g.get("status") == "PASS")
            
            # Filter by min_gates
            if passed < min_gates:
                continue
            
            # Get original file path from the manifest filename
            manifest_path = file_result.get("file", "")
            if not manifest_path:
                continue
            
            # Extract original filename from flattened name
            # Format: manifests/2_13.deployment.yaml -> tests/13.deployment.yaml
            manifest_name = Path(manifest_path).name
            
            # Remove item_id prefix (e.g., "2_" from "2_13.deployment.yaml")
            if "_" in manifest_name:
                original_name = manifest_name.split("_", 1)[1]
            else:
                original_name = manifest_name
            
            # Reconstruct original path (assuming tests/ directory)
            original_path = f"tests/{original_name}"
            
            # Get actual patched file content
            patched_file = run["run_dir"] / "validation" / "manifests" / manifest_name
            
            if not patched_file.exists():
                continue
            
            fixes_by_file[original_path].append({
                "tool": tool,
                "timestamp": run["timestamp"],
                "gates_passed": passed,
                "gates_total": len(gates),
                "gates": gates,
                "overall": file_result.get("overall"),
                "patched_content": patched_file.read_text(encoding='utf-8'),
                "patched_file": str(patched_file),
                "sha256": file_result.get("file_sha256")
            })
    
    return dict(fixes_by_file)


def merge_yaml_fixes(original_path: Path, fixes: List[Dict]) -> Tuple[str, Dict]:
    """
    Merge multiple YAML fixes for the same file.
    
    Strategy:
    1. If all fixes have same SHA256 -> they're identical, use any one
    2. If different -> use the one with most gates passed
    3. If tie -> use most recent timestamp
    
    Returns:
        (merged_content, merge_info)
    """
    if len(fixes) == 1:
        return fixes[0]["patched_content"], {
            "strategy": "single",
            "tool": fixes[0]["tool"],
            "gates_passed": fixes[0]["gates_passed"]
        }
    
    # Check if all fixes are identical
    shas = set(f["sha256"] for f in fixes if f.get("sha256"))
    if len(shas) == 1:
        return fixes[0]["patched_content"], {
            "strategy": "identical",
            "tools": [f["tool"] for f in fixes],
            "gates_passed": max(f["gates_passed"] for f in fixes)
        }
    
    # Sort by: gates_passed (desc), timestamp (desc)
    sorted_fixes = sorted(
        fixes,
        key=lambda f: (f["gates_passed"], f["timestamp"] or ""),
        reverse=True
    )
    
    best = sorted_fixes[0]
    
    return best["patched_content"], {
        "strategy": "best_validation",
        "selected_tool": best["tool"],
        "gates_passed": best["gates_passed"],
        "alternatives": len(fixes) - 1,
        "all_tools": [f["tool"] for f in sorted_fixes]
    }


def create_final_manifests(
    fixes_by_file: Dict[str, List[Dict]],
    output_dir: Path,
    original_dir: Path
) -> Dict:
    """
    Create final merged manifests and report.
    
    Returns:
        Summary statistics
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {
        "created_at": datetime.now().isoformat(),
        "total_files": len(fixes_by_file),
        "total_fixes": sum(len(fixes) for fixes in fixes_by_file.values()),
        "files": []
    }
    
    for original_path, fixes in fixes_by_file.items():
        print(f"\n[{original_path}]")
        print(f"  Fixes from {len(fixes)} tool(s): {', '.join(set(f['tool'] for f in fixes))}")
        
        # Merge fixes
        merged_content, merge_info = merge_yaml_fixes(Path(original_path), fixes)
        
        print(f"  Strategy: {merge_info['strategy']}")
        if merge_info['strategy'] == 'best_validation':
            print(f"  Selected: {merge_info['selected_tool']} ({merge_info['gates_passed']} gates passed)")
        
        # Create output file
        safe_name = original_path.replace("/", "_").replace("\\", "_")
        output_file = output_dir / safe_name
        output_file.write_text(merged_content, encoding='utf-8')
        
        print(f"  Output: {output_file.name}")
        
        # Also create side-by-side comparison if original exists
        original_file = original_dir / original_path.replace("tests/", "")
        if original_file.exists():
            comparison_dir = output_dir / "comparisons"
            comparison_dir.mkdir(exist_ok=True)
            
            # Copy original
            orig_copy = comparison_dir / f"{safe_name}.ORIGINAL"
            shutil.copy2(original_file, orig_copy)
            
            # Copy secured
            secured_copy = comparison_dir / f"{safe_name}.SECURED"
            secured_copy.write_text(merged_content, encoding='utf-8')
        
        results["files"].append({
            "original_path": original_path,
            "output_file": output_file.name,
            "merge_info": merge_info,
            "fixes_count": len(fixes),
            "tools": [f["tool"] for f in fixes]
        })
    
    # Write summary report
    report_file = output_dir / "MERGE_REPORT.json"
    report_file.write_text(json.dumps(results, indent=2), encoding='utf-8')
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Merge all validated fixes into final secured manifests")
    parser.add_argument("--output-dir", type=str, default=str(FINAL_DIR),
                        help="Output directory for final manifests")
    parser.add_argument("--input-dir", type=str, default=str(OUTPUT_DIR),
                        help="Input directory containing tool outputs")
    parser.add_argument("--original-dir", type=str, default=str(REPO_ROOT / "tests"),
                        help="Directory containing original manifests")
    parser.add_argument("--min-gates", type=int, default=0,
                        help="Minimum gates passed to include fix (0 = all)")
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    input_dir = Path(args.input_dir)
    original_dir = Path(args.original_dir)
    
    print("="*70)
    print("SafeFixK8s - Merge All Fixes")
    print("="*70)
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Minimum gates: {args.min_gates}")
    print()
    
    # Load tool results
    print("[1/3] Loading tool results...")
    tool_runs = load_tool_results(input_dir)
    print(f"  Found {len(tool_runs)} tool runs with validation")
    
    for run in tool_runs:
        gates_passed = run["metadata"]["results"].get("gates_passed", 0)
        gates_failed = run["metadata"]["results"].get("gates_failed", 0)
        fixes = run["metadata"]["results"].get("fixes_generated", 0)
        print(f"    {run['tool']}: {fixes} fixes, {gates_passed} gates passed, {gates_failed} failed")
    
    # Extract validated fixes
    print("\n[2/3] Extracting validated fixes...")
    fixes_by_file = extract_validated_fixes(tool_runs, min_gates=args.min_gates)
    print(f"  Found fixes for {len(fixes_by_file)} unique files")
    
    # Create final manifests
    print("\n[3/3] Creating final merged manifests...")
    results = create_final_manifests(fixes_by_file, output_dir, original_dir)
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total files merged: {results['total_files']}")
    print(f"Total fixes combined: {results['total_fixes']}")
    print(f"Output directory: {output_dir}")
    print(f"Report: {output_dir / 'MERGE_REPORT.json'}")
    
    # Print per-file summary
    print("\nPer-file breakdown:")
    for file_result in results["files"]:
        tools = ", ".join(file_result["tools"])
        print(f"  {file_result['original_path']}: {file_result['fixes_count']} fix(es) from [{tools}]")
    
    print("\n[SUCCESS] All fixes merged successfully!")

if __name__ == "__main__":
    main()
