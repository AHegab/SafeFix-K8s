"""
Example analysis script for SafeFixK8s detection matrix.
Demonstrates how to analyze tool effectiveness and overlap.
"""

import json
from pathlib import Path
from collections import Counter

def load_matrix():
    """Load the detection matrix JSON file."""
    matrix_path = Path(__file__).parent.parent / "output" / "tool_detection_matrix.json"
    with matrix_path.open("r", encoding="utf-8") as f:
        return json.load(f)

def print_tool_ranking(data):
    """Print tools ranked by total detections."""
    print("\n" + "="*60)
    print("TOOL EFFECTIVENESS RANKING")
    print("="*60)
    print(f"{'Rank':<6} {'Tool':<20} {'Total':<10} {'Unique':<10} {'%Unique':<10}")
    print("-"*60)
    
    stats = data["toolStats"]
    ranked = sorted(stats.items(), key=lambda x: x[1]["total"], reverse=True)
    
    for idx, (tool, metrics) in enumerate(ranked, 1):
        total = metrics["total"]
        unique = metrics["unique"]
        pct_unique = (unique / total * 100) if total > 0 else 0
        print(f"{idx:<6} {tool:<20} {total:<10} {unique:<10} {pct_unique:<10.1f}%")

def analyze_consensus(data):
    """Analyze issues by detection count (how many tools agree)."""
    print("\n" + "="*60)
    print("CONSENSUS ANALYSIS")
    print("="*60)
    
    detection_counts = Counter(row["toolCount"] for row in data["matrix"])
    total_issues = sum(detection_counts.values())
    
    print(f"{'Tools':<15} {'Count':<10} {'%':<10}")
    print("-"*35)
    for count in sorted(detection_counts.keys(), reverse=True):
        num_issues = detection_counts[count]
        pct = (num_issues / total_issues * 100) if total_issues > 0 else 0
        print(f"{count} tool(s){'':<8} {num_issues:<10} {pct:<10.1f}%")
    
    # High-confidence issues (3+ tools)
    high_conf = [r for r in data["matrix"] if r["toolCount"] >= 3]
    print(f"\n✓ High-confidence issues (3+ tools): {len(high_conf)}")
    
    # Single-tool findings (potential false positives OR unique detections)
    single_tool = [r for r in data["matrix"] if r["toolCount"] == 1]
    print(f"⚠ Single-tool findings (needs validation): {len(single_tool)}")

def severity_breakdown(data):
    """Show severity distribution."""
    print("\n" + "="*60)
    print("SEVERITY DISTRIBUTION")
    print("="*60)
    
    severities = Counter(row["severity"] for row in data["matrix"])
    total = sum(severities.values())
    
    # Order by severity
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    
    print(f"{'Severity':<15} {'Count':<10} {'%':<10}")
    print("-"*35)
    for sev in sev_order:
        count = severities.get(sev, 0)
        pct = (count / total * 100) if total > 0 else 0
        print(f"{sev:<15} {count:<10} {pct:<10.1f}%")

def top_issues(data, n=10):
    """Show top N most-detected issues."""
    print("\n" + "="*60)
    print(f"TOP {n} MOST-DETECTED ISSUES")
    print("="*60)
    
    # Sort by detection count
    top = sorted(data["matrix"], key=lambda x: x["detectionCount"], reverse=True)[:n]
    
    print(f"{'RuleID':<30} {'Severity':<10} {'Tools':<6} {'Resource':<20}")
    print("-"*70)
    for row in top:
        rule = row["ruleId"][:28]
        sev = row["severity"]
        count = row["detectionCount"]
        res = f"{row['resourceKind']}/{row['resourceName']}"[:18]
        print(f"{rule:<30} {sev:<10} {count:<6} {res:<20}")

def tool_overlap_matrix(data):
    """Calculate pairwise tool overlap (Jaccard similarity)."""
    print("\n" + "="*60)
    print("TOOL OVERLAP ANALYSIS (Top Pairs)")
    print("="*60)
    
    tools = data["allTools"]
    
    # Build sets of issue keys per tool
    tool_issues = {tool: set() for tool in tools}
    for row in data["matrix"]:
        for tool in row["toolsDetected"]:
            # Use ruleId + resource as key
            key = f"{row['ruleId']}|{row['resourceKind']}|{row['resourceName']}"
            tool_issues[tool].add(key)
    
    # Calculate pairwise overlap
    overlaps = []
    for i, t1 in enumerate(tools):
        for t2 in tools[i+1:]:
            s1 = tool_issues[t1]
            s2 = tool_issues[t2]
            if len(s1) == 0 or len(s2) == 0:
                continue
            intersection = len(s1 & s2)
            union = len(s1 | s2)
            jaccard = (intersection / union * 100) if union > 0 else 0
            overlaps.append((t1, t2, intersection, jaccard))
    
    # Show top 10 overlaps
    overlaps.sort(key=lambda x: x[2], reverse=True)
    print(f"{'Tool 1':<20} {'Tool 2':<20} {'Shared':<8} {'Jaccard%':<10}")
    print("-"*60)
    for t1, t2, shared, jacc in overlaps[:10]:
        print(f"{t1:<20} {t2:<20} {shared:<8} {jacc:<10.1f}%")

def export_for_thesis(data):
    """Export data in formats useful for thesis charts."""
    output_dir = Path(__file__).parent.parent / "output"
    
    # 1. Tool effectiveness CSV
    with (output_dir / "thesis_tool_ranking.csv").open("w", encoding="utf-8") as f:
        f.write("Tool,Total,Unique,PercentUnique\n")
        stats = data["toolStats"]
        ranked = sorted(stats.items(), key=lambda x: x[1]["total"], reverse=True)
        for tool, metrics in ranked:
            total = metrics["total"]
            unique = metrics["unique"]
            pct = (unique / total * 100) if total > 0 else 0
            f.write(f"{tool},{total},{unique},{pct:.2f}\n")
    
    # 2. Severity distribution CSV
    with (output_dir / "thesis_severity_dist.csv").open("w", encoding="utf-8") as f:
        f.write("Severity,Count\n")
        severities = Counter(row["severity"] for row in data["matrix"])
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            f.write(f"{sev},{severities.get(sev, 0)}\n")
    
    # 3. Consensus distribution CSV
    with (output_dir / "thesis_consensus_dist.csv").open("w", encoding="utf-8") as f:
        f.write("ToolCount,IssueCount\n")
        detection_counts = Counter(row["toolCount"] for row in data["matrix"])
        for count in sorted(detection_counts.keys()):
            f.write(f"{count},{detection_counts[count]}\n")
    
    print(f"\n✓ Exported thesis data to output/thesis_*.csv")

def main():
    """Run all analyses."""
    data = load_matrix()
    
    print("\n" + "="*60)
    print("SAFEFIX-K8S DETECTION MATRIX ANALYSIS")
    print("="*60)
    print(f"Total unique issues: {data['totalIssues']}")
    print(f"Total findings (with duplicates): {data['totalFindings']}")
    print(f"Tools analyzed: {len(data['allTools'])}")
    
    print_tool_ranking(data)
    analyze_consensus(data)
    severity_breakdown(data)
    top_issues(data)
    tool_overlap_matrix(data)
    export_for_thesis(data)
    
    print("\n" + "="*60)
    print("Analysis complete! Check output/thesis_*.csv for chart data.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
