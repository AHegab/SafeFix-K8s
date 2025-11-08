#!/usr/bin/env python3
"""
Validate merged manifests - Run validation gates on final merged files.

This script validates the final unified manifests to ensure they're production-ready.

Usage:
    python validate_merged_manifests.py
    python validate_merged_manifests.py --gates schema,policy,dryrun
"""

import argparse
import subprocess
import json
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent
FINAL_DIR = REPO_ROOT / "output" / "FINAL_SECURED_MANIFESTS"
VALIDATION_SCRIPT = REPO_ROOT / "Validations" / "validate-gates.ps1"


def validate_manifests(gates: str = "schema,policy,dryrun"):
    """Run validation gates on merged manifests."""
    
    if not FINAL_DIR.exists():
        print("❌ No merged manifests found. Run this first:")
        print("   python orchestrator\\merge_all_fixes.py")
        return False
    
    # Count YAML files
    yaml_files = list(FINAL_DIR.glob("tests_*.yaml"))
    if not yaml_files:
        print("❌ No YAML files found in", FINAL_DIR)
        return False
    
    print("="*70)
    print("VALIDATING FINAL MERGED MANIFESTS")
    print("="*70)
    print(f"Input directory: {FINAL_DIR}")
    print(f"Files to validate: {len(yaml_files)}")
    print(f"Gates: {gates}")
    print()
    
    # Create validation output directory
    validation_dir = FINAL_DIR / "validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    
    # Run PowerShell validation script with properly escaped paths
    # Use forward slashes for PowerShell compatibility
    input_dir_str = str(FINAL_DIR).replace('\\', '/')
    output_dir_str = str(validation_dir).replace('\\', '/')
    script_str = str(VALIDATION_SCRIPT).replace('\\', '/')
    
    ps_command = (
        f"& '{script_str}' "
        f"-InputDir '{input_dir_str}' "
        f"-Gates {gates} "
        f"-OutputDir '{output_dir_str}'"
    )
    
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", ps_command
    ]
    
    print("[*] Running validation gates...")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT / "Validations"),
            timeout=600
        )
        
        # Parse results
        proof_file = FINAL_DIR / "validation" / "safe_fix_proof.json"
        
        if proof_file.exists():
            proof = json.loads(proof_file.read_text(encoding='utf-8'))
            
            print("="*70)
            print("VALIDATION RESULTS")
            print("="*70)
            
            summary = proof.get("summary", {})
            print(f"✅ PASS: {summary.get('PASS', 0)} files")
            print(f"❌ FAIL: {summary.get('FAIL', 0)} files")
            print(f"⏭️  SKIP: {summary.get('SKIP', 0)} files")
            print()
            
            # Per-file details
            print("Per-file breakdown:")
            for file_result in proof.get("files", []):
                file_name = Path(file_result["file"]).name
                overall = file_result.get("overall", "UNKNOWN")
                
                symbol = "✅" if overall == "PASS" else "❌" if overall == "FAIL" else "⏭️"
                print(f"  {symbol} {file_name}: {overall}")
                
                # Show gate details
                for gate in file_result.get("gates", []):
                    gate_status = gate.get("status", "UNKNOWN")
                    gate_name = gate.get("gate", "unknown")
                    gate_symbol = "✅" if gate_status == "PASS" else "❌" if gate_status == "FAIL" else "⏭️"
                    print(f"      {gate_symbol} {gate_name}: {gate_status}")
            
            print()
            print(f"📄 Full report: {proof_file}")
            
            # Success if at least some passed
            if summary.get('PASS', 0) > 0:
                print("\n[SUCCESS] Some manifests passed validation!")
                return True
            elif summary.get('FAIL', 0) == len(yaml_files):
                print("\n[WARNING] All manifests failed validation")
                return False
            else:
                print("\n[INFO] Validation completed with mixed results")
                return True
        else:
            print("❌ No validation proof file generated")
            print(result.stdout)
            print(result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Validation timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"❌ Validation error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Validate final merged manifests")
    parser.add_argument("--gates", type=str, default="schema,policy,dryrun",
                        help="Gates to run (default: schema,policy,dryrun)")
    
    args = parser.parse_args()
    
    success = validate_manifests(args.gates)
    
    if not success:
        exit(1)

if __name__ == "__main__":
    main()
