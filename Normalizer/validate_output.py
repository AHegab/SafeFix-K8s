#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Normalizer Output Validator

Validates the quality and completeness of llm_payload.json output.
Ensures all required fields are present, severity levels are correct,
and provides statistics on data quality.
"""

import json
import sys
from pathlib import Path
from collections import Counter

REQUIRED_TOP_LEVEL = {"generated_at", "version", "metadata", "items"}
REQUIRED_METADATA = {"raw_findings_count", "aggregated_count", "llm_items_count", 
                     "severity_distribution", "filters"}
REQUIRED_ITEM = {"file", "category", "severity", "tools", "support_count", 
                 "rule_ids", "hints", "policy", "resource", "snippet", 
                 "span", "jsonpath"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def validate_payload(payload_path: Path):
    """Validate llm_payload.json structure and content."""
    print(f"{Colors.BOLD}SafeFix-K8s Normalizer Output Validator{Colors.RESET}\n")
    
    if not payload_path.exists():
        print(f"{Colors.RED}✗ ERROR: File not found: {payload_path}{Colors.RESET}")
        return False
    
    print(f"{Colors.CYAN}📄 Loading: {payload_path}{Colors.RESET}")
    
    try:
        with open(payload_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}✗ ERROR: Invalid JSON: {e}{Colors.RESET}")
        return False
    
    errors = []
    warnings = []
    stats = {}
    
    # Validate top-level structure
    print(f"\n{Colors.BOLD}1. Structure Validation{Colors.RESET}")
    missing_top = REQUIRED_TOP_LEVEL - set(data.keys())
    if missing_top:
        errors.append(f"Missing top-level keys: {missing_top}")
        print(f"{Colors.RED}  ✗ Missing top-level keys: {missing_top}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}  ✓ All top-level keys present{Colors.RESET}")
    
    # Validate metadata
    if "metadata" in data:
        missing_meta = REQUIRED_METADATA - set(data["metadata"].keys())
        if missing_meta:
            errors.append(f"Missing metadata keys: {missing_meta}")
            print(f"{Colors.RED}  ✗ Missing metadata: {missing_meta}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}  ✓ Metadata complete{Colors.RESET}")
            stats["metadata"] = data["metadata"]
    
    # Validate items
    print(f"\n{Colors.BOLD}2. Items Validation{Colors.RESET}")
    items = data.get("items", [])
    print(f"  📊 Total items: {len(items)}")
    
    severity_count = Counter()
    tool_count = Counter()
    category_count = Counter()
    support_dist = Counter()
    file_coverage = set()
    
    for idx, item in enumerate(items):
        missing_fields = REQUIRED_ITEM - set(item.keys())
        if missing_fields:
            errors.append(f"Item {idx}: missing fields {missing_fields}")
            print(f"{Colors.RED}  ✗ Item {idx}: missing {missing_fields}{Colors.RESET}")
        
        # Validate severity
        severity = item.get("severity", "")
        if severity not in VALID_SEVERITIES:
            errors.append(f"Item {idx}: invalid severity '{severity}'")
        severity_count[severity] += 1
        
        # Track stats
        category_count[item.get("category", "unknown")] += 1
        support_dist[item.get("support_count", 0)] += 1
        file_coverage.add(item.get("file", ""))
        for tool in item.get("tools", []):
            tool_count[tool] += 1
        
        # Validate resource structure
        resource = item.get("resource", {})
        if not isinstance(resource, dict):
            warnings.append(f"Item {idx}: resource is not a dict")
        else:
            if not resource.get("kind"):
                warnings.append(f"Item {idx}: resource missing 'kind'")
        
        # Validate span
        span = item.get("span", {})
        if isinstance(span, dict):
            if span.get("start_line", 0) > span.get("end_line", 0):
                warnings.append(f"Item {idx}: invalid span (start > end)")
        
        # Check for empty snippet
        if not item.get("snippet", "").strip():
            warnings.append(f"Item {idx}: empty snippet")
    
    if not errors:
        print(f"{Colors.GREEN}  ✓ All items structurally valid{Colors.RESET}")
    
    # Print statistics
    print(f"\n{Colors.BOLD}3. Statistics{Colors.RESET}")
    
    print(f"\n  {Colors.CYAN}Severity Distribution:{Colors.RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_count[sev]
        pct = (count / len(items) * 100) if items else 0
        color = Colors.RED if sev == "CRITICAL" else Colors.YELLOW if sev == "HIGH" else Colors.BLUE
        print(f"    {color}{sev:10}{Colors.RESET}: {count:3} ({pct:5.1f}%)")
    
    print(f"\n  {Colors.CYAN}Top 5 Categories:{Colors.RESET}")
    for cat, count in category_count.most_common(5):
        pct = (count / len(items) * 100) if items else 0
        print(f"    {cat:25}: {count:3} ({pct:5.1f}%)")
    
    print(f"\n  {Colors.CYAN}Tool Coverage:{Colors.RESET}")
    for tool, count in sorted(tool_count.items()):
        print(f"    {tool:15}: {count:3} findings")
    
    print(f"\n  {Colors.CYAN}Multi-Tool Support:{Colors.RESET}")
    for support_cnt in sorted(support_dist.keys(), reverse=True):
        count = support_dist[support_cnt]
        pct = (count / len(items) * 100) if items else 0
        print(f"    {support_cnt} tools: {count:3} items ({pct:5.1f}%)")
    
    print(f"\n  {Colors.CYAN}File Coverage:{Colors.RESET}")
    print(f"    Unique files: {len([f for f in file_coverage if f])}")
    
    # Print errors and warnings
    if errors:
        print(f"\n{Colors.BOLD}❌ ERRORS ({len(errors)}){Colors.RESET}")
        for err in errors[:10]:  # Limit to first 10
            print(f"{Colors.RED}  • {err}{Colors.RESET}")
        if len(errors) > 10:
            print(f"{Colors.YELLOW}  ... and {len(errors) - 10} more{Colors.RESET}")
    
    if warnings:
        print(f"\n{Colors.BOLD}⚠️  WARNINGS ({len(warnings)}){Colors.RESET}")
        for warn in warnings[:10]:
            print(f"{Colors.YELLOW}  • {warn}{Colors.RESET}")
        if len(warnings) > 10:
            print(f"{Colors.YELLOW}  ... and {len(warnings) - 10} more{Colors.RESET}")
    
    # Final verdict
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    if not errors:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ VALIDATION PASSED{Colors.RESET}")
        if warnings:
            print(f"{Colors.YELLOW}  ({len(warnings)} warnings - review recommended){Colors.RESET}")
        return True
    else:
        print(f"{Colors.RED}{Colors.BOLD}✗ VALIDATION FAILED{Colors.RESET}")
        print(f"{Colors.RED}  {len(errors)} errors must be fixed{Colors.RESET}")
        return False

def main():
    if len(sys.argv) > 1:
        payload_path = Path(sys.argv[1])
    else:
        # Default path
        payload_path = Path(__file__).parent.parent / "output" / "llm_payload.json"
    
    success = validate_payload(payload_path)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
