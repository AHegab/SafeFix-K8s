#!/usr/bin/env python3
"""Run complete pipeline for all 13 tools sequentially."""

import subprocess
import sys
from pathlib import Path

# All available detection tools (based on Detection/detectors.ps1)
TOOLS = [
    "KubeLinter",
    "Checkov", 
    "Trivy",
    "Kubescape",
    "Polaris",
    "KubeAudit",
    "KubeScore",
    "Conftest",
    "Pluto",
    "Gitleaks",
    "KubeConform",
    "YamlLint",
    "RbacPolice"
]

def run_tool(tool_name):
    """Run complete pipeline for a single tool."""
    print(f"\n{'='*70}")
    print(f"Starting pipeline for: {tool_name}")
    print(f"{'='*70}\n")
    
    cmd = [
        sys.executable,
        "orchestrator/safefix_single_tool.py",
        "--tool", tool_name,
        "--path", "tests",
        "--output-dir", "output",
        "--models", "groq"  # Use only Groq for speed
    ]
    
    try:
        result = subprocess.run(cmd, check=True)
        print(f"\n✅ {tool_name} completed successfully\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {tool_name} failed with error code {e.returncode}\n")
        return False
    except KeyboardInterrupt:
        print(f"\n⚠️ {tool_name} interrupted by user\n")
        return False

def main():
    """Run all tools sequentially."""
    print("\n" + "="*70)
    print("SafeFix-K8s: Running ALL 13 Tools Sequentially")
    print("="*70)
    print(f"Tools to run: {', '.join(TOOLS)}")
    print(f"Target: tests/")
    print(f"Output: output/")
    print("="*70 + "\n")
    
    results = {}
    
    for i, tool in enumerate(TOOLS, 1):
        print(f"\n[{i}/{len(TOOLS)}] Running {tool}...")
        success = run_tool(tool)
        results[tool] = "✅ Success" if success else "❌ Failed"
        
        if not success:
            print(f"\n⚠️ Warning: {tool} failed but continuing with remaining tools...\n")
    
    # Print final summary
    print("\n" + "="*70)
    print("FINAL SUMMARY")
    print("="*70)
    for tool, status in results.items():
        print(f"{tool:15} | {status}")
    print("="*70 + "\n")
    
    # Count successes
    successes = sum(1 for status in results.values() if "Success" in status)
    print(f"Completed: {successes}/{len(TOOLS)} tools\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Pipeline interrupted by user\n")
        sys.exit(1)
