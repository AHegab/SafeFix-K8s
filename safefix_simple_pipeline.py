#!/usr/bin/env python3
"""
SafeFixK8s Simple Pipeline (Single YAML)

Usage:
    python safefix_simple_pipeline.py <your-yaml-file>

Steps:
1. Runs all detectors on the input YAML file, saves raw outputs in a folder named after the file.
2. Runs normalization on the detector outputs.
3. Runs LLM fixing using the normalized payload.
4. Runs validation gates on the LLM output.
"""
import os
import sys
import subprocess
from pathlib import Path

def run_all_detectors(yaml_file: Path, out_dir: Path):
    """
    Run all detectors on the input YAML file and save outputs in out_dir.
    Assumes detectors.ps1 can run all tools and save outputs in out_dir.
    """
    ps_script = Path("detection/detectors.ps1")
    cmd = [
        "powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script),
        "-Function", "Run-AllDetectors", "-Target", str(yaml_file), "-OutDir", str(out_dir)
    ]
    print(f"Running detectors: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def run_normalizer(raw_dir: Path, tests_dir: Path, out_normalized: Path, out_llm_payload: Path):
    cmd = [sys.executable, "Normalizer/normalizer.py",
           "--raw-dir", str(raw_dir),
           "--tests-dir", str(tests_dir),
           "--out-normalized", str(out_normalized),
           "--out-llm-payload", str(out_llm_payload)]
    print(f"Running normalizer: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def run_llm_fix(payload: Path, tests_dir: Path, out_dir: Path):
    cmd = [sys.executable, "LLMs/multi_llm_orchestrator.py",
           "--payload", str(payload),
           "--tests-dir", str(tests_dir),
           "--out-dir", str(out_dir)]
    print(f"Running LLM fix: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def run_validation(tests_dir: Path, fixed_dir: Path, payload: Path, out_dir: Path):
    cmd = [sys.executable, "Validations/validation_gates.py",
           "--tests-dir", str(tests_dir),
           "--fixed-dir", str(fixed_dir),
           "--payload", str(payload),
           "--out-dir", str(out_dir)]
    print(f"Running validation gates: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SafeFixK8s Simple Pipeline (Single YAML)")
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

    # Step 1: Run all detectors
    run_all_detectors(file_path, raw_dir)
    # Step 2: Normalization
    run_normalizer(raw_dir, tests_dir, out_normalized, out_llm_payload)
    # Step 3: LLM Fixing
    run_llm_fix(out_llm_payload, tests_dir, llm_fixes_dir)
    # Step 4: Validation
    run_validation(tests_dir, llm_fixes_dir, out_llm_payload, validation_out_dir)
    print(f"\nPipeline complete! Check {file_out_dir} for results.")

if __name__ == "__main__":
    main()
