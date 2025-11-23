#!/usr/bin/env python3
"""
Test script to verify normalizer UNKNOWN_FILE fixes
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent / "Normalizer"))

from normalizer import extract_filename_from_raw, normalize_path


def test_windows_path_extraction():
    """Test that Windows absolute paths are correctly extracted"""

    print("Testing Windows path extraction...")

    # Test 1: Conftest-style path
    raw = {
        "filename": r"C:\Users\Ahmed\OneDrive - GIU AS - German International University of Applied Sciences\Desktop\Bsc Thesis\Implementaions\SafeFixK8s\tests\20.wordpress_mariadb_compose.yaml"
    }
    result = extract_filename_from_raw(raw, "")
    expected = "20.wordpress_mariadb_compose.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Conftest Windows path: {result}")

    # Test 2: Gitleaks-style path (capital F in "File")
    raw = {
        "File": r"C:/Users/Ahmed/OneDrive - GIU AS - German International University of Applied Sciences/Desktop/Bsc Thesis/Implementaions/SafeFixK8s/tests/20.wordpress_mariadb_compose.yaml"
    }
    result = extract_filename_from_raw(raw, "")
    expected = "20.wordpress_mariadb_compose.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Gitleaks Windows path: {result}")

    # Test 3: Path with line number (should strip it)
    raw = {
        "filename": "/path/to/tests/deployment.yaml:42"
    }
    result = extract_filename_from_raw(raw, "")
    expected = "deployment.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Path with line number: {result}")

    # Test 4: Unix path
    raw = {
        "file": "/scan/tests/service.yaml"
    }
    result = extract_filename_from_raw(raw, "")
    expected = "service.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Unix path: {result}")

    print("[PASS] All path extraction tests passed!\n")


def test_normalize_path():
    """Test path normalization"""

    print("Testing path normalization...")

    # Test 1: Windows absolute path with tests/
    path = r"C:\Users\Ahmed\Desktop\SafeFixK8s\tests\20.wordpress_mariadb_compose.yaml"
    result = normalize_path(path)
    expected = "20.wordpress_mariadb_compose.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Windows path: {result}")

    # Test 2: Unix absolute path with tests/
    path = "/home/user/project/tests/deployment.yaml"
    result = normalize_path(path)
    expected = "deployment.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Unix path: {result}")

    # Test 3: Relative path
    path = "tests/service.yaml"
    result = normalize_path(path)
    expected = "service.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Relative path: {result}")

    # Test 4: Just filename
    path = "configmap.yaml"
    result = normalize_path(path)
    expected = "configmap.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Filename only: {result}")

    # Test 5: Path with subdirectories after tests/
    path = "/project/tests/subfolder/nested.yaml"
    result = normalize_path(path)
    expected = "nested.yaml"
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  [OK] Nested path: {result}")

    print("[PASS] All normalization tests passed!\n")


if __name__ == "__main__":
    try:
        test_windows_path_extraction()
        test_normalize_path()
        print("=" * 60)
        print("SUCCESS: ALL TESTS PASSED!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
