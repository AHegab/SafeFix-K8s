#!/usr/bin/env python3
"""
SafeFixK8s Unified Pipeline CLI

Usage:
    python safefix_pipeline.py

- Guides user to select files/folders for scanning
- Runs detection (PowerShell detectors.ps1)
- Runs normalization (normalizer.py)
- Runs LLM fixing (raw_to_llm.py)
- Runs validation (validation_gates.py)
"""
import os
import sys
import subprocess
from pathlib import Path

# --- Helper: List files/folders for user selection ---
def list_files_and_folders(root: Path):
    items = []
    for p in root.iterdir():
        if p.is_file() or p.is_dir():
            items.append(p)
    return items

def prompt_user_selection(items):
    print("\nSelect files/folders to scan:")
    for i, item in enumerate(items):
        print(f"  [{i+1}] {item}")
    sel = input("Enter number(s) separated by comma (e.g. 1,3): ").strip()
    idxs = [int(x)-1 for x in sel.split(",") if x.strip().isdigit()]
    chosen = [items[i] for i in idxs if 0 <= i < len(items)]
    return chosen

# --- Step 1: Run detectors.ps1 ---
def run_detectors(targets):
    print("\n[1/4] Running detectors.ps1...")
    ps_script = Path("detection/detectors.ps1")
    for target in targets:
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script), "-Function", "Run-AllDetectors", "-Target", str(target)]
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

# --- Step 2: Run normalizer.py ---
def run_normalizer(raw_dir, tests_dir, out_normalized, out_llm_payload):
    print("\n[2/4] Running normalizer.py...")
    cmd = [sys.executable, "Normalizer/normalizer.py",
           "--raw-dir", str(raw_dir),
           "--tests-dir", str(tests_dir),
           "--out-normalized", str(out_normalized),
           "--out-llm-payload", str(out_llm_payload)]
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

# --- Step 3: Run LLM fixing ---
def run_llm_fix(payload, tests_dir, out_dir):
    print("\n[3/4] Running LLMs/multi_llm_orchestrator.py...")
    cmd = [sys.executable, "LLMs/multi_llm_orchestrator.py",
           "--payload", str(payload),
           "--tests-dir", str(tests_dir),
           "--out-dir", str(out_dir)]
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

# --- Step 4: Run validation ---
def run_validation(tests_dir, fixed_dir, payload, out_dir):
    print("\n[4/4] Running Validations/validation_gates.py...")
    cmd = [sys.executable, "Validations/validation_gates.py",
           "--tests-dir", str(tests_dir),
           "--fixed-dir", str(fixed_dir),
           "--payload", str(payload),
           "--out-dir", str(out_dir)]
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

# --- Main CLI ---
def main():
    import argparse
    parser = argparse.ArgumentParser(description="SafeFixK8s Unified Pipeline CLI (Single YAML)")
    parser.add_argument('yaml_file', type=str, help='Single test YAML file to process')
    args = parser.parse_args()

    root = Path.cwd()
    tests_dir = root / "tests"

    file_path = Path(args.yaml_file)
    if not file_path.exists():
        file_path = tests_dir / args.yaml_file
    if not file_path.exists():
        print(f"File not found: {file_path}")
        sys.exit(1)

    # Output directory for this file only
    file_stem = file_path.stem + file_path.suffix.replace('.', '_')
    file_out_dir = root / "pipeline/output" / file_stem
    file_out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = file_out_dir / "detection_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_normalized = file_out_dir / "output_normalized.json"
    out_llm_payload = file_out_dir / "output_llm_payload.json"
    llm_fixes_dir = file_out_dir / "llm_fixes"
    llm_fixes_dir.mkdir(parents=True, exist_ok=True)
    validation_out_dir = file_out_dir / "validation"
    validation_out_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Detection (only this file)
    run_detectors([file_path])
    # Step 2: Normalization
    run_normalizer(raw_dir, tests_dir, out_normalized, out_llm_payload)
    # Step 3: LLM Fixing
    run_llm_fix(out_llm_payload, tests_dir, llm_fixes_dir)
    # Step 4: Validation
    run_validation(tests_dir, llm_fixes_dir, out_llm_payload, validation_out_dir)
    print(f"\nPipeline complete! Check {file_out_dir} for results.")

if __name__ == "__main__":
    main()
