#!/usr/bin/env python3
"""
Analyze all validation results from Detection/output subdirectories.
"""

import json
import csv
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any

def analyze_all_validations(base_dir: Path):
    """Analyze all validation results."""

    results = {
        "total_files": 0,
        "pass": [],
        "needs_review": [],
        "fail": [],
        "dangerous_configs": [],
        "missing_rules": Counter(),
        "high_failures_by_category": Counter(),
        "critical_failures_by_category": Counter(),
        "by_file": {}
    }

    # Find all validation directories
    for subdir in base_dir.iterdir():
        if not subdir.is_dir():
            continue

        validation_dir = subdir / "validation"
        if not validation_dir.exists():
            continue

        # Read summary CSV
        summary_csv = validation_dir / "SUMMARY_VALIDATION.csv"
        if summary_csv.exists():
            with summary_csv.open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    results["total_files"] += 1
                    file_name = row["file"]
                    status = row["status"]

                    file_info = {
                        "file": file_name,
                        "subdir": subdir.name,
                        "status": status,
                        "total_checks": int(row.get("total_checks", 0)),
                        "passed_checks": int(row.get("passed_checks", 0)),
                        "failed_checks": int(row.get("failed_checks", 0)),
                        "critical_failures": int(row.get("critical_failures", 0)),
                        "high_failures": int(row.get("high_failures", 0)),
                        "medium_failures": int(row.get("medium_failures", 0)),
                        "dangerous_configs": int(row.get("dangerous_configs", 0)),
                    }

                    results["by_file"][file_name] = file_info

                    if status == "PASS":
                        results["pass"].append(file_name)
                    elif status == "NEEDS_REVIEW":
                        results["needs_review"].append(file_name)
                    else:
                        results["fail"].append(file_name)

                    if file_info["dangerous_configs"] > 0:
                        results["dangerous_configs"].append({
                            "file": file_name,
                            "count": file_info["dangerous_configs"]
                        })

        # Read detailed JSON reports
        for json_file in validation_dir.glob("REPORT_VALIDATE_*.json"):
            try:
                with json_file.open('r', encoding='utf-8') as f:
                    data = json.load(f)

                    # Track missing rules
                    # (we can infer this from categories that have no findings)

                    # Track failures by category
                    for finding in data.get("findings", []):
                        if not finding["passed"]:
                            category = finding["category"]
                            severity = finding["severity"]

                            if severity == "CRITICAL":
                                results["critical_failures_by_category"][category] += 1
                            elif severity == "HIGH":
                                results["high_failures_by_category"][category] += 1
            except Exception as e:
                print(f"Error reading {json_file}: {e}")

    return results


def print_summary(results: Dict[str, Any]):
    """Print comprehensive summary."""

    total = results["total_files"]
    pass_count = len(results["pass"])
    needs_review_count = len(results["needs_review"])
    fail_count = len(results["fail"])

    print("=" * 80)
    print("VALIDATION RESULTS SUMMARY")
    print("=" * 80)
    print(f"\nTotal Files Validated: {total}")
    print(f"  PASS:         {pass_count:3d} ({pass_count/total*100:.1f}%)")
    print(f"  NEEDS_REVIEW: {needs_review_count:3d} ({needs_review_count/total*100:.1f}%)")
    print(f"  FAIL:         {fail_count:3d} ({fail_count/total*100:.1f}%)")

    # PASS files
    if results["pass"]:
        print(f"\n{'='*80}")
        print(f"PASSED FILES ({len(results['pass'])})")
        print("=" * 80)
        for file in sorted(results["pass"]):
            info = results["by_file"][file]
            print(f"  - {file}")
            print(f"    Checks: {info['passed_checks']}/{info['total_checks']} passed")

    # NEEDS_REVIEW files
    if results["needs_review"]:
        print(f"\n{'='*80}")
        print(f"NEEDS REVIEW ({len(results['needs_review'])})")
        print("=" * 80)
        for file in sorted(results["needs_review"]):
            info = results["by_file"][file]
            print(f"  - {file}")
            print(f"    Checks: {info['passed_checks']}/{info['total_checks']} passed, "
                  f"{info['medium_failures']} medium issues")

    # FAIL files
    if results["fail"]:
        print(f"\n{'='*80}")
        print(f"[FAIL] FAILED FILES ({len(results['fail'])})")
        print("=" * 80)
        for file in sorted(results["fail"]):
            info = results["by_file"][file]
            print(f"  - {file}")
            print(f"    Checks: {info['passed_checks']}/{info['total_checks']} passed")

            failures = []
            if info["critical_failures"] > 0:
                failures.append(f"{info['critical_failures']} CRITICAL")
            if info["high_failures"] > 0:
                failures.append(f"{info['high_failures']} HIGH")
            if info["medium_failures"] > 0:
                failures.append(f"{info['medium_failures']} MEDIUM")

            if failures:
                print(f"    Failures: {', '.join(failures)}")

            if info["dangerous_configs"] > 0:
                print(f"     {info['dangerous_configs']} DANGEROUS CONFIGURATIONS")

    # Dangerous configurations
    if results["dangerous_configs"]:
        print(f"\n{'='*80}")
        print(f"[DANGER] DANGEROUS CONFIGURATIONS DETECTED")
        print("=" * 80)
        sorted_dangerous = sorted(results["dangerous_configs"],
                                 key=lambda x: x["count"], reverse=True)
        for item in sorted_dangerous:
            print(f"  - {item['file']}: {item['count']} dangerous configs")

    # Top failing categories
    if results["high_failures_by_category"]:
        print(f"\n{'='*80}")
        print(f"TOP HIGH SEVERITY FAILURES BY CATEGORY")
        print("=" * 80)
        for category, count in results["high_failures_by_category"].most_common(10):
            print(f"  - {category}: {count} failures")

    if results["critical_failures_by_category"]:
        print(f"\n{'='*80}")
        print(f"CRITICAL SEVERITY FAILURES BY CATEGORY")
        print("=" * 80)
        for category, count in results["critical_failures_by_category"].most_common():
            print(f"  - {category}: {count} failures")


def identify_missing_rules(base_dir: Path):
    """Identify validation rules that are missing."""

    missing_rules = set()

    for subdir in base_dir.iterdir():
        if not subdir.is_dir():
            continue

        payload_file = subdir / "llm_payload.json"
        if not payload_file.exists():
            continue

        try:
            with payload_file.open('r', encoding='utf-8') as f:
                payload = json.load(f)

            for file_entry in payload.get("files", []):
                for finding in file_entry.get("findings", []):
                    category = finding.get("category", "")
                    if category:
                        missing_rules.add(category)
        except Exception as e:
            continue

    # Check which ones are implemented
    implemented = {
        "Security/PrivilegedContainer",
        "Security/AllowPrivilegeEscalation",
        "Security/CapabilitiesNotDropped",
        "Security/MissingSeccompProfile",
        "Security/ReadOnlyRootFSFalse",
        "Security/MissingAppArmorProfile",
        "Auth/RunAsRoot",
        "Auth/AutomountServiceAccountToken",
        "Auth/DefaultServiceAccount",
        "Auth/DefaultNamespace",
        "Resources/MissingRequests",
        "Resources/MissingLimits",
        "Probes/MissingReadinessLiveness",
        "Image/TagNotPinned",
        "Image/UntrustedRegistry",
        "Policy/PodSecurityViolation",
    }

    truly_missing = missing_rules - implemented

    if truly_missing:
        print(f"\n{'='*80}")
        print(f" MISSING VALIDATION RULES ({len(truly_missing)})")
        print("=" * 80)
        print("\nThese categories appear in payloads but have no validation rules:")
        for rule in sorted(truly_missing):
            print(f"  - {rule}")


def generate_recommendations(results: Dict[str, Any]):
    """Generate recommendations based on results."""

    print(f"\n{'='*80}")
    print(f"[INFO] RECOMMENDATIONS")
    print("=" * 80)

    fail_count = len(results["fail"])
    dangerous_count = len(results["dangerous_configs"])

    print(f"\n1. HIGH PRIORITY: Fix {fail_count} failing files")
    print(f"   - {dangerous_count} files have dangerous configurations (privileged, hostPath, etc.)")
    print(f"   - Focus on files with DANGEROUS CONFIGURATIONS first")

    print(f"\n2. MEDIUM PRIORITY: Review {len(results['needs_review'])} files needing review")
    print(f"   - These passed security checks but have schema warnings")
    print(f"   - Review kubeconform output for each")

    print(f"\n3. VALIDATION IMPROVEMENTS:")
    print(f"   - Add missing validation rules (see list above)")
    print(f"   - Consider adjusting severity levels in validation_config.yaml")

    print(f"\n4. LLM FIX IMPROVEMENTS:")
    print(f"   - {fail_count} files failed validation after LLM fixes")
    print(f"   - Review LLM prompts for categories with most failures")
    print(f"   - Consider adding more specific fix instructions")


if __name__ == "__main__":
    base_dir = Path("Detection/output")

    if not base_dir.exists():
        print(f"Error: {base_dir} not found")
        exit(1)

    print("Analyzing all validation results...\n")

    results = analyze_all_validations(base_dir)
    print_summary(results)
    identify_missing_rules(base_dir)
    generate_recommendations(results)

    print(f"\n{'='*80}")
    print("Analysis complete!")
    print("=" * 80)
