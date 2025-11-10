#!/usr/bin/env python3
"""
SafeFix-K8s Pipeline Runner
Runs the complete pipeline: Detection → Normalization → LLM → Combine
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Paths
DETECTION_DIR = Path("Detection")
NORMALIZER_DIR = Path("Normalizer")
LLMS_DIR = Path("LLMs")

OUTPUT_DIR = Path("output")
RAW_DIR = OUTPUT_DIR / "detection" / "raw"
NORM_DIR = OUTPUT_DIR / "normalization"
LLM_DIR = OUTPUT_DIR / "llm"
COMBINE_DIR = OUTPUT_DIR / "combination"

TESTS_DIR = Path("tests")
DETECTORS_SCRIPT = DETECTION_DIR / "detectors.ps1"
NORMALIZER_SCRIPT = NORMALIZER_DIR / "normalize.py"
LLM_ORCHESTRATOR = LLMS_DIR / "multi_llm_orchestrator.py"
COMBINE_YAML = LLMS_DIR / "combine_yaml_files.py"


def run_detectors():
    """Step 1: Run all security detection tools."""
    print("\n" + "="*60)
    print("[1/4] Running Detection Tools...")
    print("="*60)
    
    # Ensure output directory exists
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    
    if not DETECTORS_SCRIPT.exists():
        print(f"ERROR: {DETECTORS_SCRIPT} not found.")
        sys.exit(1)
    
    # Set environment variable so detectors use the correct output location
    env = os.environ.copy()
    env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
    
    # Run extended detection (13 tools)
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        f'. "{DETECTORS_SCRIPT}"; Det-RunExtended -Path "{TESTS_DIR}"'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd(), env=env)
    print(result.stdout)
    
    if result.returncode != 0:
        print(f"ERROR: Detection failed with exit code {result.returncode}")
        print(result.stderr)
        sys.exit(result.returncode)
    
    print(f"\n✓ Detection complete. Raw output should be in {RAW_DIR}")


def run_normalizer():
    """Step 2: Normalize raw findings into LLM payload."""
    print("\n" + "="*60)
    print("[2/4] Running Normalizer...")
    print("="*60)
    
    NORM_DIR.mkdir(parents=True, exist_ok=True)
    
    if not NORMALIZER_SCRIPT.exists():
        print(f"ERROR: {NORMALIZER_SCRIPT} not found.")
        sys.exit(1)
    
    # Find raw directory - check multiple possible locations
    # detectors.ps1 creates: $SAFEFIX_OUTPUT_ROOT/detection/raw (if env var set)
    # OR: Detection/output/detection/raw (if env var not set)
    raw_candidates = [
        RAW_DIR,  # output/detection/raw (preferred)
        OUTPUT_DIR / "detection" / "raw",  # Same as above
        DETECTION_DIR / "output" / "detection" / "raw",  # Fallback location
        DETECTION_DIR / "output" / "raw",  # Alternative fallback
        Path("Detection/output/detection/raw"),  # Absolute fallback
    ]
    
    raw_input = None
    for candidate in raw_candidates:
        if candidate.exists():
            # Check if it has JSON files
            json_files = list(candidate.glob("*.json"))
            txt_files = list(candidate.glob("*.txt"))
            if json_files or txt_files:
                raw_input = candidate
                break
    
    if not raw_input:
        print(f"ERROR: No raw detection files found.")
        print(f"Checked locations:")
        for c in raw_candidates:
            exists = "✓" if c.exists() else "✗"
            print(f"  {exists} {c}")
        sys.exit(1)
    
    print(f"Using raw input: {raw_input}")
    json_count = len(list(raw_input.glob("*.json")))
    txt_count = len(list(raw_input.glob("*.txt")))
    print(f"  Found {json_count} JSON files and {txt_count} TXT files")
    
    cmd = [
        sys.executable, str(NORMALIZER_SCRIPT),
        "--raw", str(raw_input),
        "--out", str(NORM_DIR)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd())
    print(result.stdout)
    
    if result.returncode != 0:
        print(f"ERROR: Normalization failed with exit code {result.returncode}")
        print(result.stderr)
        sys.exit(result.returncode)
    
    # Check if llm_payload.json was created
    llm_payload = NORM_DIR / "llm_payload.json"
    if not llm_payload.exists():
        print(f"WARNING: {llm_payload} not found. Normalization may have failed.")
    
    print(f"\n✓ Normalization complete. Output in {NORM_DIR}")


def run_llm_layer(use_sharding=True):
    """Step 3: Generate fixes using LLM consensus.
    
    Args:
        use_sharding: If True, use round-robin model assignment (1 model per finding = 3x faster)
                     If False, use all models per finding for consensus (slower but more accurate)
    """
    print("\n" + "="*60)
    print("[3/4] Running LLM Fix Generation...")
    if use_sharding:
        print("⚡ FAST MODE: Using model sharding (1 model per finding)")
    else:
        print("🎯 QUALITY MODE: Using full consensus (all models per finding)")
    print("="*60)
    
    if not LLM_ORCHESTRATOR.exists():
        print(f"ERROR: {LLM_ORCHESTRATOR} not found.")
        sys.exit(1)
    
    LLM_DIR.mkdir(parents=True, exist_ok=True)
    
    # Build command with optimized settings
    cmd = [
        sys.executable, str(LLM_ORCHESTRATOR),
        "--models", "groq,openrouter,gemini",
        "--validate", "yaml",  # Keep validation for quality
        "--autofix",
        "--hygiene",
        "--concurrency", "15",  # Increased from 5 to 15 (3x more parallel)
        "--timeout", "20",  # Reduced from 40s to 20s (faster failure detection)
        "--retries", "1"  # Reduced from 3 to 1 (faster failure handling)
    ]
    
    # Add sharding flag if fast mode
    if use_sharding:
        cmd.append("--shard-models")  # Round-robin: 1 model per finding (3x faster)
        print("  → Model sharding enabled: Each finding uses 1 model (round-robin)")
        print("  → Expected speedup: ~3x faster than quality mode")
    else:
        print("  → Full consensus: Each finding uses all 3 models")
        print("  → Expected: Higher accuracy, slower processing")
    
    # Set environment variables
    env = dict(os.environ) if hasattr(os, 'environ') else {}
    env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
    env["SAFEFIX_NORMALIZATION_DIR"] = str(NORM_DIR)
    env["SAFEFIX_LLM_DIR"] = str(LLM_DIR)
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd(), env=env)
    print(result.stdout)
    
    if result.returncode != 0:
        print(f"ERROR: LLM generation failed with exit code {result.returncode}")
        print(result.stderr)
        sys.exit(result.returncode)
    
    # Check if llm_decisions.json was created
    llm_decisions = LLM_DIR / "llm_decisions.json"
    if not llm_decisions.exists():
        print(f"WARNING: {llm_decisions} not found. LLM generation may have failed.")
    
    print(f"\n✓ LLM fix generation complete. Decisions in {LLM_DIR}")


def run_combine():
    """Step 4: Combine all fixed YAML files for each target file."""
    print("\n" + "="*60)
    print("[4/4] Combining Fixed YAML Files...")
    print("="*60)
    
    if not COMBINE_YAML.exists():
        print(f"ERROR: {COMBINE_YAML} not found.")
        sys.exit(1)
    
    COMBINE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Find llm_decisions.json
    llm_decisions_candidates = [
        LLM_DIR / "llm_decisions.json",
        OUTPUT_DIR / "llm" / "llm_decisions.json",
        Path("output/llm/llm_decisions.json")
    ]
    
    llm_decisions_path = None
    for candidate in llm_decisions_candidates:
        if candidate.exists():
            llm_decisions_path = candidate
            break
    
    if not llm_decisions_path:
        print("ERROR: llm_decisions.json not found. Run LLM stage first.")
        sys.exit(1)
    
    # Load decisions to find all files that need combining
    try:
        with open(llm_decisions_path, 'r', encoding='utf-8') as f:
            decisions = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load {llm_decisions_path}: {e}")
        sys.exit(1)
    
    # Find unique files that have fixes
    files_to_combine = set()
    for item in decisions:
        if item.get("consensus", {}).get("final_classification") == "fix":
            file_path = item.get("file", "")
            if file_path and file_path != "(unknown)":
                files_to_combine.add(file_path)
    
    if not files_to_combine:
        print("WARNING: No files with fixes found in LLM decisions.")
        return
    
    print(f"Found {len(files_to_combine)} files to combine:")
    for f in sorted(files_to_combine):
        print(f"  - {f}")
    
    # Combine each file
    combined_count = 0
    failed_count = 0
    
    for file_path in sorted(files_to_combine):
        print(f"\nCombining fixes for: {file_path}")
        
        # Check if file exists
        file_candidates = [
            Path(file_path),
            TESTS_DIR / file_path.split("\\")[-1],
            TESTS_DIR / file_path.split("/")[-1],
            Path(file_path.replace("\\", "/"))
        ]
        
        actual_file = None
        for candidate in file_candidates:
            if candidate.exists():
                actual_file = candidate
                break
        
        if not actual_file:
            print(f"  WARNING: File not found: {file_path} (skipping)")
            failed_count += 1
            continue
        
        # Run combine for this file
        cmd = [
            sys.executable, str(COMBINE_YAML),
            "--file", str(actual_file),
            "--output", str(COMBINE_DIR),
            "--hygiene"
        ]
        
        env = dict(os.environ) if hasattr(os, 'environ') else {}
        env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
        env["SAFEFIX_LLM_DIR"] = str(LLM_DIR)
        env["SAFEFIX_COMBINATION_DIR"] = str(COMBINE_DIR)
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd(), env=env)
        
        if result.returncode == 0:
            print(f"  ✓ Combined successfully")
            combined_count += 1
        else:
            print(f"  ✗ Failed: {result.stderr[:200]}")
            failed_count += 1
    
    print(f"\n✓ Combination complete:")
    print(f"  - Successfully combined: {combined_count}")
    print(f"  - Failed: {failed_count}")
    print(f"  - Output directory: {COMBINE_DIR}")


def main():
    """Run the complete pipeline."""
    parser = argparse.ArgumentParser(description="SafeFix-K8s Pipeline Runner")
    parser.add_argument("--fast", action="store_true", 
                       help="Fast mode: Use model sharding (1 model per finding) for 3x speedup")
    parser.add_argument("--quality", action="store_true",
                       help="Quality mode: Use all models per finding for consensus (slower but more accurate)")
    args = parser.parse_args()
    
    # Determine mode
    use_sharding = args.fast or not args.quality  # Default to fast mode
    
    print("\n" + "="*60)
    print("SafeFix-K8s Pipeline")
    print("="*60)
    print(f"Tests directory: {TESTS_DIR}")
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"Mode: {'FAST (model sharding)' if use_sharding else 'QUALITY (full consensus)'}")
    print("="*60)
    
    try:
        # Step 1: Detection
        run_detectors()
        
        # Step 2: Normalization
        run_normalizer()
        
        # Step 3: LLM Fix Generation (with mode selection)
        run_llm_layer(use_sharding=use_sharding)
        
        # Step 4: Combine Fixed Files
        run_combine()
        
        print("\n" + "="*60)
        print("Pipeline Complete!")
        print("="*60)
        print(f"\nSecured files are in: {COMBINE_DIR}")
        print(f"Diff files showing changes: {COMBINE_DIR}/DIFF_*.diff")
        print(f"Summary files: {COMBINE_DIR}/SUMMARY_*.json")
        
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR: Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
