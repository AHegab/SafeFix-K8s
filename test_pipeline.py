#!/usr/bin/env python3
"""
Quick test script for the SafeFixK8s pipeline.
Tests each stage individually to verify everything works.
"""

import subprocess
import sys
from pathlib import Path

def run_cmd(cmd, description):
    """Run a command and report status."""
    print(f"\n{'='*70}")
    print(f"TEST: {description}")
    print(f"{'='*70}")
    print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=False, text=True)

    if result.returncode == 0:
        print(f"✓ {description} - PASSED")
        return True
    else:
        print(f"✗ {description} - FAILED (exit code: {result.returncode})")
        return False

def main():
    """Run pipeline tests."""
    tests_passed = 0
    tests_failed = 0

    print("\n" + "="*70)
    print("SAFEFIXK8S PIPELINE TEST SUITE")
    print("="*70)

    # Clean up
    print("\nCleaning up old test outputs...")
    subprocess.run(["rm", "-rf", "test-results"], capture_output=True)

    # Test 1: Detection
    if run_cmd(
        ["python", "pipeline.py", "--stage", "detection", "--input", "tests/", "--output", "test-results/"],
        "Stage 1: Detection"
    ):
        tests_passed += 1
    else:
        tests_failed += 1
        print("\nAborting tests - detection failed")
        return 1

    # Test 2: Normalization
    if run_cmd(
        ["python", "pipeline.py", "--stage", "normalize",
         "--raw", "test-results/detection/raw",
         "--tests", "tests/",
         "--output", "test-results/"],
        "Stage 2: Normalization"
    ):
        tests_passed += 1
    else:
        tests_failed += 1

    # Test 3: Help
    if run_cmd(
        ["python", "pipeline.py", "--help"],
        "CLI Help Display"
    ):
        tests_passed += 1
    else:
        tests_failed += 1

    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    print(f"Total Tests:  {tests_passed + tests_failed}")

    if tests_failed == 0:
        print("\n✓ All tests PASSED!")
        return 0
    else:
        print(f"\n✗ {tests_failed} test(s) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
