#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s Run Comparison Tool (B.Sc. Thesis)

Purpose:
    Compare results from multiple single-tool pipeline runs.
    Generate CSV matrices showing tool coverage, fix success rates, and validation results.

Comparisons:
    1. Detection Coverage Matrix - What each tool detects per file/category
    2. Fix Success Matrix - Which tools' findings were successfully fixed
    3. Validation Pass Matrix - Which fixes passed which gates
    4. Timeline Comparison - Performance metrics per tool

Output:
    compare/results/
        ├── detection_coverage.csv
        ├── fix_success_rate.csv
        ├── validation_pass_rate.csv
        ├── performance_comparison.csv
        └── summary_report.md

Usage:
    python compare/compare_runs.py --runs runs/2025-11-06*
    python compare/compare_runs.py --runs runs/ --output compare/results
    python compare/compare_runs.py --list-runs
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple

REPO_ROOT = Path(__file__).parent.parent.absolute()


class RunComparator:
    """Compare multiple tool runs and generate comparison matrices."""
    
    def __init__(self, run_dirs: List[Path], output_dir: Path):
        self.run_dirs = sorted(run_dirs)
        self.output_dir = output_dir
        self.runs_data = []
        
    def load_run_data(self) -> bool:
        """Load metadata and results from all run directories."""
        print(f"[*] Loading data from {len(self.run_dirs)} runs...")
        
        for run_dir in self.run_dirs:
            metadata_file = run_dir / "metadata.json"
            
            if not metadata_file.exists():
                print(f"[!] Skipping {run_dir.name} - no metadata.json")
                continue
            
            try:
                metadata = json.loads(metadata_file.read_text(encoding='utf-8'))
                
                # Load additional data
                run_data = {
                    "metadata": metadata,
                    "run_dir": run_dir,
                    "tool": metadata.get("tool", "Unknown"),
                    "tool_normalized": metadata.get("tool_normalized", "unknown"),
                    "timestamp": metadata.get("timestamp", ""),
                    "findings": self._load_findings(run_dir),
                    "llm_decisions": self._load_llm_decisions(run_dir),
                    "validation_proof": self._load_validation_proof(run_dir)
                }
                
                self.runs_data.append(run_data)
                print(f"[✓] Loaded {run_data['tool']} - {metadata.get('results', {}).get('raw_findings', 0)} findings")
                
            except Exception as e:
                print(f"[✗] Error loading {run_dir.name}: {e}")
        
        if not self.runs_data:
            print(f"[✗] No valid run data found")
            return False
        
        print(f"[✓] Loaded {len(self.runs_data)} runs successfully\n")
        return True
    
    def _load_findings(self, run_dir: Path) -> Dict:
        """Load normalized findings from a run."""
        payload_file = run_dir / "normalization" / "llm_payload.json"
        
        if not payload_file.exists():
            return {"items": []}
        
        try:
            return json.loads(payload_file.read_text(encoding='utf-8'))
        except:
            return {"items": []}
    
    def _load_llm_decisions(self, run_dir: Path) -> List[Dict]:
        """Load LLM decisions from a run."""
        decisions_file = run_dir / "llm" / "llm_decisions.json"
        
        if not decisions_file.exists():
            return []
        
        try:
            return json.loads(decisions_file.read_text(encoding='utf-8'))
        except:
            return []
    
    def _load_validation_proof(self, run_dir: Path) -> Dict:
        """Load validation proof from a run."""
        proof_file = run_dir / "validation" / "safe_fix_proof.json"
        
        if not proof_file.exists():
            return {}
        
        try:
            return json.loads(proof_file.read_text(encoding='utf-8'))
        except:
            return {}
    
    def generate_detection_coverage(self) -> str:
        """Generate CSV matrix of what each tool detected."""
        print(f"[*] Generating detection coverage matrix...")
        
        # Collect all unique (file, category) pairs across all tools
        file_category_pairs = set()
        detection_matrix = defaultdict(lambda: defaultdict(int))
        
        for run in self.runs_data:
            tool = run["tool"]
            items = run["findings"].get("items", [])
            
            for item in items:
                file = item.get("file", "")
                category = item.get("category", "")
                
                if file and category:
                    pair = (file, category)
                    file_category_pairs.add(pair)
                    detection_matrix[pair][tool] = item.get("support_count", 1)
        
        # Sort pairs
        sorted_pairs = sorted(file_category_pairs)
        
        # Get sorted tools
        tools = sorted([run["tool"] for run in self.runs_data])
        
        # Write CSV
        output_file = self.output_dir / "detection_coverage.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(["File", "Category"] + tools + ["Total Tools"])
            
            # Data rows
            for file, category in sorted_pairs:
                row = [file, category]
                detected_count = 0
                
                for tool in tools:
                    detected = detection_matrix[(file, category)].get(tool, 0)
                    row.append("✓" if detected > 0 else "")
                    if detected > 0:
                        detected_count += 1
                
                row.append(detected_count)
                writer.writerow(row)
        
        print(f"[✓] Detection coverage saved to {output_file}")
        return str(output_file)
    
    def generate_fix_success_matrix(self) -> str:
        """Generate CSV matrix of fix success rates per tool."""
        print(f"[*] Generating fix success matrix...")
        
        # Collect fix statistics per tool
        fix_stats = []
        
        for run in self.runs_data:
            tool = run["tool"]
            items = run["findings"].get("items", [])
            decisions = run["llm_decisions"]
            
            total_findings = len(items)
            total_decisions = len(decisions)
            
            fixes = sum(
                1 for d in decisions
                if d.get("consensus", {}).get("final_classification") == "fix"
            )
            
            needs_review = sum(
                1 for d in decisions
                if d.get("consensus", {}).get("final_classification") == "needs_review"
            )
            
            safe = sum(
                1 for d in decisions
                if d.get("consensus", {}).get("final_classification") == "safe"
            )
            
            fix_rate = (fixes / total_decisions * 100) if total_decisions > 0 else 0
            
            fix_stats.append({
                "Tool": tool,
                "Total Findings": total_findings,
                "LLM Processed": total_decisions,
                "Fixes Generated": fixes,
                "Needs Review": needs_review,
                "Safe (No Fix)": safe,
                "Fix Success Rate %": f"{fix_rate:.1f}"
            })
        
        # Write CSV
        output_file = self.output_dir / "fix_success_rate.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if fix_stats:
                writer = csv.DictWriter(f, fieldnames=fix_stats[0].keys())
                writer.writeheader()
                writer.writerows(fix_stats)
        
        print(f"[✓] Fix success matrix saved to {output_file}")
        return str(output_file)
    
    def generate_validation_pass_matrix(self) -> str:
        """Generate CSV matrix of validation gate pass rates."""
        print(f"[*] Generating validation pass matrix...")
        
        # Collect validation statistics per tool
        validation_stats = []
        
        for run in self.runs_data:
            tool = run["tool"]
            proof = run["validation_proof"]
            
            summary = proof.get("summary", {})
            
            validation_stats.append({
                "Tool": tool,
                "Gates Run": summary.get("gates_run", 0),
                "Gates Passed": summary.get("gates_passed", 0),
                "Gates Failed": summary.get("gates_failed", 0),
                "Pass Rate %": f"{summary.get('pass_rate', 0):.1f}",
                "Files Validated": summary.get("files_validated", 0),
                "Timestamp": proof.get("timestamp", "")
            })
        
        # Write CSV
        output_file = self.output_dir / "validation_pass_rate.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if validation_stats:
                writer = csv.DictWriter(f, fieldnames=validation_stats[0].keys())
                writer.writeheader()
                writer.writerows(validation_stats)
        
        print(f"[✓] Validation pass matrix saved to {output_file}")
        return str(output_file)
    
    def generate_performance_comparison(self) -> str:
        """Generate CSV of performance metrics per tool."""
        print(f"[*] Generating performance comparison...")
        
        # Collect performance statistics
        perf_stats = []
        
        for run in self.runs_data:
            tool = run["tool"]
            metadata = run["metadata"]
            timings = metadata.get("timings", {})
            
            perf_stats.append({
                "Tool": tool,
                "Detection Time (s)": f"{timings.get('detection', 0):.1f}",
                "Normalization Time (s)": f"{timings.get('normalization', 0):.1f}",
                "LLM Repair Time (s)": f"{timings.get('llm_repair', 0):.1f}",
                "Validation Time (s)": f"{timings.get('validation', 0):.1f}",
                "Total Time (s)": f"{metadata.get('total_duration', 0):.1f}",
                "Steps Completed": ", ".join(metadata.get("steps_completed", []))
            })
        
        # Write CSV
        output_file = self.output_dir / "performance_comparison.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if perf_stats:
                writer = csv.DictWriter(f, fieldnames=perf_stats[0].keys())
                writer.writeheader()
                writer.writerows(perf_stats)
        
        print(f"[✓] Performance comparison saved to {output_file}")
        return str(output_file)
    
    def generate_summary_report(self) -> str:
        """Generate markdown summary report."""
        print(f"[*] Generating summary report...")
        
        output_file = self.output_dir / "summary_report.md"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# SafeFix-K8s Tool Comparison Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Runs Analyzed:** {len(self.runs_data)}\n\n")
            
            f.write("## Tools Compared\n\n")
            for run in self.runs_data:
                f.write(f"- **{run['tool']}** ({run['timestamp']})\n")
            f.write("\n")
            
            f.write("## Detection Coverage Summary\n\n")
            f.write("| Tool | Raw Findings | Normalized Items | Categories Detected |\n")
            f.write("|------|--------------|------------------|---------------------|\n")
            
            for run in self.runs_data:
                tool = run['tool']
                raw = run['metadata'].get('results', {}).get('raw_findings', 0)
                norm = run['metadata'].get('results', {}).get('normalized_findings', 0)
                items = run['findings'].get('items', [])
                categories = len(set(item.get('category') for item in items))
                
                f.write(f"| {tool} | {raw} | {norm} | {categories} |\n")
            f.write("\n")
            
            f.write("## Fix Generation Summary\n\n")
            f.write("| Tool | Findings | Fixes Generated | Fix Rate |\n")
            f.write("|------|----------|-----------------|----------|\n")
            
            for run in self.runs_data:
                tool = run['tool']
                findings = len(run['findings'].get('items', []))
                decisions = run['llm_decisions']
                fixes = sum(
                    1 for d in decisions
                    if d.get("consensus", {}).get("final_classification") == "fix"
                )
                rate = (fixes / findings * 100) if findings > 0 else 0
                
                f.write(f"| {tool} | {findings} | {fixes} | {rate:.1f}% |\n")
            f.write("\n")
            
            f.write("## Validation Summary\n\n")
            f.write("| Tool | Gates Run | Passed | Failed | Pass Rate |\n")
            f.write("|------|-----------|--------|--------|-----------||\n")
            
            for run in self.runs_data:
                tool = run['tool']
                proof = run['validation_proof']
                summary = proof.get('summary', {})
                gates_run = summary.get('gates_run', 0)
                passed = summary.get('gates_passed', 0)
                failed = summary.get('gates_failed', 0)
                rate = summary.get('pass_rate', 0)
                
                f.write(f"| {tool} | {gates_run} | {passed} | {failed} | {rate:.1f}% |\n")
            f.write("\n")
            
            f.write("## Performance Summary\n\n")
            f.write("| Tool | Total Time | Detection | Normalization | LLM Repair | Validation |\n")
            f.write("|------|------------|-----------|---------------|------------|------------|\n")
            
            for run in self.runs_data:
                tool = run['tool']
                metadata = run['metadata']
                timings = metadata.get('timings', {})
                total = metadata.get('total_duration', 0)
                
                f.write(f"| {tool} | {total:.1f}s | "
                       f"{timings.get('detection', 0):.1f}s | "
                       f"{timings.get('normalization', 0):.1f}s | "
                       f"{timings.get('llm_repair', 0):.1f}s | "
                       f"{timings.get('validation', 0):.1f}s |\n")
            f.write("\n")
            
            f.write("## Files Generated\n\n")
            f.write("- `detection_coverage.csv` - What each tool detected per file/category\n")
            f.write("- `fix_success_rate.csv` - Fix generation success rates\n")
            f.write("- `validation_pass_rate.csv` - Validation gate pass rates\n")
            f.write("- `performance_comparison.csv` - Performance metrics\n")
            f.write("- `summary_report.md` - This report\n\n")
            
            f.write("---\n\n")
            f.write("*Generated by SafeFix-K8s Run Comparison Tool (B.Sc. Thesis)*\n")
        
        print(f"[✓] Summary report saved to {output_file}")
        return str(output_file)
    
    def run(self) -> bool:
        """Execute the comparison analysis."""
        print(f"\n{'='*60}")
        print(f"SafeFix-K8s Run Comparison Tool")
        print(f"{'='*60}\n")
        
        # Load data
        if not self.load_run_data():
            return False
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate comparisons
        try:
            self.generate_detection_coverage()
            self.generate_fix_success_matrix()
            self.generate_validation_pass_matrix()
            self.generate_performance_comparison()
            self.generate_summary_report()
            
            print(f"\n{'='*60}")
            print(f"✓ COMPARISON COMPLETED")
            print(f"{'='*60}")
            print(f"Output directory: {self.output_dir}")
            print(f"{'='*60}\n")
            
            return True
            
        except Exception as e:
            print(f"\n[✗] Comparison error: {e}")
            import traceback
            traceback.print_exc()
            return False


def list_available_runs(runs_dir: Path):
    """List all available run directories."""
    print(f"\n{'='*60}")
    print(f"Available Runs in {runs_dir}")
    print(f"{'='*60}\n")
    
    if not runs_dir.exists():
        print(f"[!] Runs directory does not exist: {runs_dir}")
        return
    
    run_dirs = sorted([d for d in runs_dir.iterdir() if d.is_dir()])
    
    if not run_dirs:
        print(f"[!] No run directories found")
        return
    
    for run_dir in run_dirs:
        metadata_file = run_dir / "metadata.json"
        
        if metadata_file.exists():
            try:
                metadata = json.loads(metadata_file.read_text(encoding='utf-8'))
                tool = metadata.get("tool", "Unknown")
                timestamp = metadata.get("timestamp", "")
                findings = metadata.get("results", {}).get("raw_findings", 0)
                success = "✓" if metadata.get("success", False) else "✗"
                
                print(f"{success} {run_dir.name}")
                print(f"   Tool: {tool}")
                print(f"   Findings: {findings}")
                print(f"   Timestamp: {timestamp}")
                print()
            except:
                print(f"[!] {run_dir.name} (invalid metadata)")
        else:
            print(f"[!] {run_dir.name} (no metadata)")


def main():
    parser = argparse.ArgumentParser(
        description="SafeFix-K8s Run Comparison Tool (B.Sc. Thesis)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare all runs
  python compare/compare_runs.py --runs runs/
  
  # Compare specific runs
  python compare/compare_runs.py --runs runs/2025-11-06*
  
  # Custom output directory
  python compare/compare_runs.py --runs runs/ --output compare/results_2025-11-06
  
  # List available runs
  python compare/compare_runs.py --list-runs
        """
    )
    
    parser.add_argument(
        "--runs",
        help="Run directories to compare (glob pattern or directory)"
    )
    
    parser.add_argument(
        "--output",
        default="compare/results",
        help="Output directory for comparison results (default: compare/results)"
    )
    
    parser.add_argument(
        "--list-runs",
        action="store_true",
        help="List all available runs"
    )
    
    args = parser.parse_args()
    
    # List runs if requested
    if args.list_runs:
        runs_dir = REPO_ROOT / "runs"
        list_available_runs(runs_dir)
        return 0
    
    # Validate runs argument
    if not args.runs:
        print(f"[✗] --runs argument required (or use --list-runs)")
        parser.print_help()
        return 1
    
    # Find run directories
    runs_path = Path(args.runs)
    
    if runs_path.is_dir():
        # Directory provided - get all subdirectories
        run_dirs = sorted([d for d in runs_path.iterdir() if d.is_dir() and (d / "metadata.json").exists()])
    else:
        # Glob pattern provided
        run_dirs = sorted(REPO_ROOT.glob(args.runs))
        run_dirs = [d for d in run_dirs if d.is_dir() and (d / "metadata.json").exists()]
    
    if not run_dirs:
        print(f"[✗] No valid run directories found matching: {args.runs}")
        return 1
    
    # Setup output directory
    output_dir = (REPO_ROOT / args.output).absolute()
    
    # Create and run comparator
    comparator = RunComparator(run_dirs=run_dirs, output_dir=output_dir)
    success = comparator.run()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
