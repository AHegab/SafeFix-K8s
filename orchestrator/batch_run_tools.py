#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeFix-K8s Batch Tool Runner (B.Sc. Thesis)

Purpose:
    Run the single-tool pipeline for multiple tools in sequence.
    Useful for generating comparison data across all detection tools.

Usage:
    python orchestrator/batch_run_tools.py --tools kubelinter,checkov,trivy
    python orchestrator/batch_run_tools.py --all --path tests
    python orchestrator/batch_run_tools.py --all --skip-validate
"""

import argparse
import subprocess
import sys
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent.absolute()

# All available tools
ALL_TOOLS = [
    "kubelinter",
    "checkov",
    "trivy",
    "kubeaudit",
    "kubescape",
    "polaris",
    "kubescore",
    "conftest",
    "kubeconform"
]

# Quick test subset
QUICK_TOOLS = [
    "kubelinter",
    "checkov",
    "trivy"
]


def run_tool(tool: str, **kwargs) -> bool:
    """Run single-tool orchestrator for one tool."""
    print(f"\n{'='*60}")
    print(f"Running pipeline for: {tool}")
    print(f"{'='*60}\n")
    
    cmd = [
        sys.executable,
        str(REPO_ROOT / "orchestrator" / "safefix_single_tool.py"),
        "--tool", tool
    ]
    
    # Add optional arguments
    if kwargs.get("path"):
        cmd.extend(["--path", kwargs["path"]])
    if kwargs.get("gates"):
        cmd.extend(["--gates", kwargs["gates"]])
    if kwargs.get("models"):
        cmd.extend(["--models", kwargs["models"]])
    if kwargs.get("skip_validate"):
        cmd.append("--skip-validate")
    if kwargs.get("skip_llm"):
        cmd.append("--skip-llm")
    
    try:
        result = subprocess.run(cmd, cwd=str(REPO_ROOT))
        return result.returncode == 0
    except Exception as e:
        print(f"[✗] Error running {tool}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="SafeFix-K8s Batch Tool Runner (B.Sc. Thesis)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run specific tools
  python orchestrator/batch_run_tools.py --tools kubelinter,checkov,trivy
  
  # Run all tools
  python orchestrator/batch_run_tools.py --all
  
  # Run quick test subset
  python orchestrator/batch_run_tools.py --quick
  
  # Run with custom settings
  python orchestrator/batch_run_tools.py --all --path tests --gates 1,2 --skip-validate
        """
    )
    
    parser.add_argument(
        "--tools",
        help="Comma-separated list of tools to run"
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available tools"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick test subset (kubelinter, checkov, trivy)"
    )
    
    parser.add_argument(
        "--path",
        default="tests",
        help="Path to scan (default: tests)"
    )
    
    parser.add_argument(
        "--gates",
        default="1,2,3",
        help="Validation gates (default: 1,2,3)"
    )
    
    parser.add_argument(
        "--models",
        default="groq,openrouter,gemini",
        help="LLM models (default: groq,openrouter,gemini)"
    )
    
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip validation gates"
    )
    
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip LLM repair"
    )
    
    args = parser.parse_args()
    
    # Determine which tools to run
    if args.all:
        tools = ALL_TOOLS
    elif args.quick:
        tools = QUICK_TOOLS
    elif args.tools:
        tools = [t.strip() for t in args.tools.split(",")]
    else:
        print("[✗] Must specify --tools, --all, or --quick")
        parser.print_help()
        return 1
    
    print(f"\n{'='*60}")
    print(f"Batch Tool Runner")
    print(f"{'='*60}")
    print(f"Tools to run: {', '.join(tools)}")
    print(f"Total: {len(tools)} tools")
    print(f"{'='*60}\n")
    
    # Run each tool
    start_time = datetime.now()
    results = {}
    
    for tool in tools:
        success = run_tool(
            tool,
            path=args.path,
            gates=args.gates,
            models=args.models,
            skip_validate=args.skip_validate,
            skip_llm=args.skip_llm
        )
        results[tool] = success
    
    # Summary
    elapsed = (datetime.now() - start_time).total_seconds()
    successful = sum(1 for s in results.values() if s)
    failed = len(tools) - successful
    
    print(f"\n{'='*60}")
    print(f"BATCH RUN COMPLETED")
    print(f"{'='*60}")
    print(f"Total tools: {len(tools)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Total time: {elapsed:.1f}s")
    print(f"\nResults:")
    
    for tool, success in results.items():
        status = "✓" if success else "✗"
        print(f"  {status} {tool}")
    
    print(f"\n{'='*60}")
    print(f"To compare results, run:")
    print(f"  python compare/compare_runs.py --runs runs/")
    print(f"{'='*60}\n")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
