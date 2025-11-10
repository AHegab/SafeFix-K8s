#!/usr/bin/env python3
"""
SafeFix-K8s CLI - Unified command-line interface for the security remediation pipeline.

Usage:
    cli.py scan --path tests --mode extended
    cli.py normalize --raw output/detection/raw --out output/normalization
    cli.py llm run --models groq,openrouter --autofix --hygiene
    cli.py combine --file tests/13.nginx_privileged_deployment.yaml
    cli.py validate --file output/combination/SECURED_*.yaml --gates 1,2
    cli.py review --file output/combination/SECURED_*.yaml
"""

import sys
import os
import json
import subprocess
import time
from pathlib import Path
import shutil
import uuid
from typing import Optional, List
from datetime import datetime

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich import box
    # from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.prompt import Confirm, Prompt
except ImportError:
    print("Error: Required packages not installed. Run:")
    print("  pip install typer rich")
    sys.exit(1)

app = typer.Typer(
    name="safefix-k8s",
    help="SafeFix-K8s: Automated Kubernetes Security Remediation Pipeline",
    add_completion=True
)
console = Console()


def _env_guard(stage: str):
    """Prevent cross-stage contamination by clearing unrelated SAFEFIX_* vars.
    Allowlist minimal vars per stage; remove others to avoid stale paths from previous runs.
    """
    allow = {
        "scan": {"SAFEFIX_OUTPUT_ROOT", "SAFEFIX_DETECTION_RAW_DIR", "SAFEFIX_DETECTION_LOG_DIR"},
        "normalize": {"SAFEFIX_OUTPUT_ROOT", "SAFEFIX_DETECTION_RAW_DIR", "SAFEFIX_NORMALIZATION_DIR"},
        "llm": {"SAFEFIX_OUTPUT_ROOT", "SAFEFIX_NORMALIZATION_DIR", "SAFEFIX_LLM_DIR", "SAFEFIX_LLM_SANDBOX_DIR"},
        "combine": {"SAFEFIX_OUTPUT_ROOT", "SAFEFIX_LLM_DIR", "SAFEFIX_COMBINATION_DIR"},
        "validate": {"SAFEFIX_OUTPUT_ROOT", "SAFEFIX_VALIDATION_DIR"},
        "pipeline": {"SAFEFIX_OUTPUT_ROOT"},
    }.get(stage, set())
    to_del = [k for k in os.environ.keys() if k.startswith("SAFEFIX_") and k not in allow]
    for k in to_del:
        os.environ.pop(k, None)

def _table_box():
    enc = str(getattr(sys.stdout, "encoding", "") or "").lower()
    if enc.startswith("cp") or "1252" in enc or "ansi" in enc:
        return box.SIMPLE
    return box.HEAVY_HEAD

# Get repo root
REPO_ROOT = Path(__file__).parent.absolute()
DETECTION_DIR = REPO_ROOT / "Detection"
NORMALIZER_DIR = REPO_ROOT / "Normalizer"
LLMS_DIR = REPO_ROOT / "LLMs"
VALIDATIONS_DIR = REPO_ROOT / "Validations"
OUTPUT_DIR = REPO_ROOT / "output"
EVAL_DIR = REPO_ROOT / "Evaluation"


def _ensure_layer(name: str) -> Path:
    path = OUTPUT_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    return path


DETECTION_LAYER = _ensure_layer("detection")
NORMALIZATION_LAYER = _ensure_layer("normalization")
LLM_LAYER = _ensure_layer("llm")
COMBINATION_LAYER = _ensure_layer("combination")
VALIDATION_LAYER = _ensure_layer("validation")


def print_banner():
    """Print CLI banner with ASCII fallback for Windows codepages."""
    enc = str(getattr(sys.stdout, "encoding", "") or "").lower()
    if enc.startswith("cp") or "1252" in enc or "ansi" in enc:
        banner = (
            "+-----------------------------------------------------------+\n"
            "|    SafeFix-K8s Security Remediation Pipeline              |\n"
            "|                   Automated Security Fixes                |\n"
            "+-----------------------------------------------------------+\n"
        )
    else:
        banner = """
╔═══════════════════════════════════════════════════════════╗
║          SafeFix-K8s Security Remediation Pipeline        ║
║                    Automated Security Fixes                ║
╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def print_summary(title: str, data: dict, suggestions: List[str] = None):
    """Print a formatted summary table with encoding-aware box style."""
    table = Table(title=title, show_header=True, header_style="bold magenta", box=_table_box())
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")
    
    for key, value in data.items():
        table.add_row(key, str(value))
    
    console.print(table)
    
    if suggestions:
        console.print("\n[bold yellow]Next Steps:[/bold yellow]")
        for i, suggestion in enumerate(suggestions, 1):
            console.print(f"  {i}. {suggestion}")


def find_existing(paths: List[Path], expected: Path) -> Path:
    for candidate in paths:
        if candidate.exists():
            return candidate
    return expected


@app.command()
def scan(
    path: str = typer.Option("tests", "--path", "-p", help="Path to scan"),
    mode: str = typer.Option("extended", "--mode", "-m", help="Scan mode: lean, extended, or single"),
    extended: bool = typer.Option(True, "--extended/--lean", "-e/-l", help="Use extended mode (13 tools) - default is extended"),
    tool: Optional[str] = typer.Option(None, "--tool", "-t", help="Single tool to run (e.g., kubescape, trivy, checkov)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be scanned without executing"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Custom output directory")
):
    """
    Scan Kubernetes manifests for security issues.
    
    By default, runs EXTENDED mode with all 13 tools (10 LEAN + rbac-police, pluto, gitleaks).
    Use --lean to run only the 10 core tools.
    Use --tool <name> to run a single specific tool.
    
    Available tools:
        KubeConform, KubeLinter, Polaris, Checkov, TrivyConfig, Kubescape,
        KubeScore, Yamllint, KubeAudit, Conftest, RBACPolice, Pluto, Gitleaks
    
    Examples:
        cli.py scan --path tests                    # Extended mode (13 tools)
        cli.py scan --path . --lean                 # Lean mode (10 tools)
        cli.py scan --path tests --tool Kubescape   # Single tool only
        cli.py scan --tool Trivy --dry-run
    """
    _env_guard("scan")
    print_banner()
    start_time = time.time()
    
    scan_path = Path(path).absolute()
    if not scan_path.exists():
        console.print(f"[bold red]Error:[/bold red] Path not found: {path}")
        raise typer.Exit(1)
    
    # Determine mode
    if tool:
        mode_str = f"SINGLE ({tool})"
        tool_count = 1
        function_name = "Det-RunSingle"
        function_args = f"-Path '{scan_path}' -Tool {tool}"
    elif extended or mode.lower() == "extended":
        mode_str = "EXTENDED"
        tool_count = 13
        function_name = "Det-RunExtended"
        function_args = f"-Path '{scan_path}'"
    else:
        mode_str = "LEAN"
        tool_count = 10
        function_name = "Det-RunLean"
        function_args = f"-Path '{scan_path}'"
    
    console.print(f"[bold cyan]Scanning:[/bold cyan] {scan_path}")
    console.print(f"[bold cyan]Mode:[/bold cyan] {mode_str} ({tool_count} tool{'s' if tool_count > 1 else ''})")
    console.print(f"[bold cyan]Started:[/bold cyan] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        console.print(f"Command: powershell -NoProfile -ExecutionPolicy Bypass -Command \". {DETECTION_DIR / 'detectors.ps1'}; {function_name} {function_args}\"")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    raw_layer_dir = DETECTION_LAYER / "raw"
    logs_layer_dir = DETECTION_LAYER / "logs"
    raw_layer_dir.mkdir(parents=True, exist_ok=True)
    logs_layer_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
    env["SAFEFIX_DETECTION_RAW_DIR"] = str(raw_layer_dir)
    env["SAFEFIX_DETECTION_LOG_DIR"] = str(logs_layer_dir)

    # Execute detection
    try:
        with console.status(f"[bold green]Running {tool_count} security scanner{'s' if tool_count > 1 else ''}..."):
            if sys.platform == "win32":
                # Dot-source the script to load functions, then call the function
                script_path = str(DETECTION_DIR / 'detectors.ps1').replace("'", "''")  # Escape single quotes
                scan_path_str = str(scan_path).replace("'", "''")  # Convert Path to str first
                
                # Build PowerShell command
                if tool:
                    ps_command = f". '{script_path}'; Det-RunSingle -Path '{scan_path_str}' -Tool {tool}"
                else:
                    ps_command = f". '{script_path}'; {function_name} -Path '{scan_path_str}'"
                
                cmd = [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-Command", ps_command
                ]
            else:
                cmd = [
                    "bash", "-c",
                    f"cd '{DETECTION_DIR}' && ./detectors.sh {'--extended' if extended else ''} '{scan_path}'"
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env, check=False)
            
            if result.returncode != 0:
                console.print(f"[bold red]Scan failed with exit code {result.returncode}[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
    
    except (OSError, ValueError) as e:
        console.print(f"[bold red]Error during scan:[/bold red] {e}")
        raise typer.Exit(1)
    
    # Parse results
    raw_candidates = [
        raw_layer_dir,
        DETECTION_DIR / "output" / "raw",
        REPO_ROOT / "detection" / "output" / "raw"
    ]
    raw_output_dir = next((p for p in raw_candidates if p.exists()), raw_layer_dir)
    finding_count = 0
    tool_results = {}
    
    if raw_output_dir.exists():
        for file in raw_output_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text(encoding='utf-8'))
                if isinstance(data, list):
                    count = len(data)
                else:
                    count = 1
                tool_results[file.stem.replace('_raw', '')] = count
                finding_count += count
            except (json.JSONDecodeError, OSError, ValueError):
                tool_results[file.stem.replace('_raw', '')] = 0
    
    elapsed = time.time() - start_time
    
    # Summary
    summary_data = {
        "Total Findings": finding_count,
        "Tools Run": tool_count,
        "Files Scanned": len(list(scan_path.glob("*.yaml"))) + len(list(scan_path.glob("*.yml"))),
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    suggestions = [
        f"python cli.py normalize --raw {raw_output_dir} --out {NORMALIZATION_LAYER}",
        f"Review raw findings in {raw_output_dir}",
        "Run with --extended for comprehensive scanning (13 tools)"
    ]
    
    print_summary(f"Scan Complete - {mode_str} Mode", summary_data, suggestions)
    
    # Tool breakdown
    if tool_results:
        console.print("\n[bold]Tool Breakdown:[/bold]")
        tool_table = Table(show_header=True, header_style="bold magenta", box=_table_box())
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Findings", justify="right", style="yellow")
        for tool, count in sorted(tool_results.items(), key=lambda x: -x[1]):
            tool_table.add_row(tool, str(count))
        console.print(tool_table)


@app.command()
def normalize(
    raw: str = typer.Option(str(DETECTION_LAYER / "raw"), "--raw", "-r", help="Raw detection output directory"),
    out: str = typer.Option(str(NORMALIZATION_LAYER), "--out", "-o", help="Output directory"),
    min_support: int = typer.Option(1, "--min-support", help="Minimum tool agreement"),
    only_security: bool = typer.Option(True, "--only-security", help="Filter only security findings"),
    ml_fp: bool = typer.Option(True, "--ml-fp/--no-ml-fp", help="Apply ML-based false-positive filtering when model available"),
    ml_threshold: float = typer.Option(0.6, "--ml-threshold", help="Probability threshold for ML false-positive filtering"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be normalized")
):
    """
    Normalize raw detection findings into a unified schema.
    
    Examples:
    cli.py normalize
    cli.py normalize --raw output/detection/raw --out output/normalization
        cli.py normalize --min-support 2 --only-security
    """
    _env_guard("normalize")
    print_banner()
    start_time = time.time()
    
    raw_dir = Path(raw)
    if not raw_dir.exists():
        legacy_candidates = [
            DETECTION_LAYER / "raw",
            DETECTION_DIR / "output" / "raw",
            REPO_ROOT / "detection" / "output" / "raw"
        ]
        replacement = find_existing(legacy_candidates, raw_dir)
        if replacement.exists():
            console.print(f"[yellow]Raw directory {raw} not found. Using {replacement} instead.[/yellow]")
            raw_dir = replacement
        else:
            console.print(f"[bold red]Error:[/bold red] Raw directory not found: {raw}")
            raise typer.Exit(1)

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]Normalizing:[/bold cyan] {raw_dir}")
    console.print(f"[bold cyan]Output:[/bold cyan] {out_dir}")
    console.print(f"[bold cyan]Min Support:[/bold cyan] {min_support}")
    console.print(f"[bold cyan]Security Only:[/bold cyan] {only_security}")
    console.print(f"[bold cyan]ML FP Filter:[/bold cyan] {'enabled' if ml_fp else 'disabled'} (threshold={ml_threshold})\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        cmd_parts = [
            f"python {NORMALIZER_DIR / 'normalize.py'}",
            f"--raw {raw_dir}",
            f"--out {out_dir}",
            f"--min-support {min_support}",
            f"--only-security {1 if only_security else 0}",
            f"--ml-fp {1 if ml_fp else 0}",
            f"--ml-threshold {ml_threshold}"
        ]
        console.print(f"Command: {' '.join(cmd_parts)}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute normalization
    try:
        with console.status("[bold green]Normalizing findings..."):
            cmd = [
                sys.executable,
                str(NORMALIZER_DIR / "normalize.py"),
                "--raw", str(raw_dir),
                "--out", str(out_dir),
                "--min-support", str(min_support),
                "--only-security", ("1" if only_security else "0"),
                "--ml-fp", ("1" if ml_fp else "0"),
                "--ml-threshold", str(ml_threshold)
            ]

            env = os.environ.copy()
            env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
            env["SAFEFIX_DETECTION_RAW_DIR"] = str(raw_dir)
            env["SAFEFIX_NORMALIZATION_DIR"] = str(out_dir)
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env, check=False)
            
            if result.returncode != 0:
                console.print("[bold red]Normalization failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except Exception as e:
        console.print(f"[bold red]Error during normalization:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    # Parse results
    llm_payload_path = find_existing([
        out_dir / "llm_payload.json",
        NORMALIZATION_LAYER / "llm_payload.json",
        OUTPUT_DIR / "llm_payload.json"
    ], out_dir / "llm_payload.json")
    normalized_path = find_existing([
        out_dir / "normalized_findings.json",
        NORMALIZATION_LAYER / "normalized_findings.json",
        OUTPUT_DIR / "normalized_findings.json"
    ], out_dir / "normalized_findings.json")
    
    llm_items = 0
    normalized_count = 0
    
    if llm_payload_path.exists():
        data = json.loads(llm_payload_path.read_text(encoding='utf-8'))
        llm_items = len(data.get("items", []))
    
    if normalized_path.exists():
        data = json.loads(normalized_path.read_text(encoding='utf-8'))
        normalized_count = len(data)
    
    summary_data = {
        "Normalized Findings": normalized_count,
        "LLM Items": llm_items,
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    suggestions = [
        f"python cli.py llm run --models groq,openrouter --autofix --hygiene",
        f"Review LLM payload: {llm_payload_path}",
        f"Review normalized findings: {normalized_path}"
    ]
    
    print_summary("Normalization Complete", summary_data, suggestions)


@app.command(name="run")
def llm_run(
    models: str = typer.Option("groq,openrouter,gemini", "--models", "-m", help="Comma-separated model list"),
    autofix: bool = typer.Option(True, "--autofix/--no-autofix", help="Enable automatic fixes"),
    hygiene: bool = typer.Option(True, "--hygiene/--no-hygiene", help="Enable security hygiene"),
    limit: int = typer.Option(0, "--limit", "-l", help="Limit number of items (0=all)"),
    timeout: int = typer.Option(25, "--timeout", "-t", help="Timeout per model in seconds"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Process N items in parallel"),
    validate: str = typer.Option("yaml", "--validate", "-v", help="Post-patch validation mode: none or yaml"),
    apply_dir: Optional[str] = typer.Option(None, "--apply-dir", help="Directory to stage per-finding fixed manifests"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be executed")
):
    """
    Run LLM orchestration to generate security patches.
    
    Examples:
        cli.py llm run --models groq,openrouter
        cli.py llm run --autofix --hygiene --limit 10
        cli.py llm run --no-autofix --timeout 60
        cli.py llm run --concurrency 10  # Process 10 items at once (faster!)
    """
    _env_guard("llm")
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Models:[/bold cyan] {models}")
    console.print(f"[bold cyan]Autofix:[/bold cyan] {autofix}")
    console.print(f"[bold cyan]Hygiene:[/bold cyan] {hygiene}")
    console.print(f"[bold cyan]Limit:[/bold cyan] {limit if limit > 0 else 'All'}")
    console.print(f"[bold cyan]Timeout:[/bold cyan] {timeout}s")
    console.print(f"[bold cyan]Concurrency:[/bold cyan] {concurrency}")
    console.print(f"[bold cyan]Validation:[/bold cyan] {validate}")
    if apply_dir:
        console.print(f"[bold cyan]Apply Dir:[/bold cyan] {apply_dir}")
    console.print("")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        cmd_str = f"python {LLMS_DIR / 'multi_llm_orchestrator.py'} --models {models} --concurrency {concurrency}"
        if autofix:
            cmd_str += " --autofix"
        if hygiene:
            cmd_str += " --hygiene"
        if limit > 0:
            cmd_str += f" --limit {limit}"
        cmd_str += f" --validate {validate}"
        if apply_dir:
            cmd_str += f" --apply-dir {apply_dir}"
        console.print(f"Command: {cmd_str}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute LLM orchestration
    try:
        cmd = [
            sys.executable,
            str(LLMS_DIR / "multi_llm_orchestrator.py"),
            "--models", models,
            "--timeout", str(timeout),
            "--concurrency", str(concurrency),
            "--validate", validate
        ]
        
        if autofix:
            cmd.append("--autofix")
        if hygiene:
            cmd.append("--hygiene")
        if limit > 0:
            cmd.extend(["--limit", str(limit)])
        if apply_dir:
            cmd.extend(["--apply-dir", apply_dir])
        
        env = os.environ.copy()
        # Use environment variables if already set (for tool-specific paths), otherwise use defaults
        env["SAFEFIX_OUTPUT_ROOT"] = os.getenv("SAFEFIX_OUTPUT_ROOT", str(OUTPUT_DIR))
        env["SAFEFIX_NORMALIZATION_DIR"] = os.getenv("SAFEFIX_NORMALIZATION_DIR", str(NORMALIZATION_LAYER))
        env["SAFEFIX_LLM_DIR"] = os.getenv("SAFEFIX_LLM_DIR", str(LLM_LAYER))
        
        if apply_dir:
            llm_sandbox = Path(apply_dir)
        else:
            llm_sandbox = Path(env["SAFEFIX_LLM_DIR"]) / "patch_sandbox"
        env["SAFEFIX_LLM_SANDBOX_DIR"] = str(llm_sandbox)

        with console.status("[bold green]Running LLM orchestration..."):
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env, check=False)
            
            if result.returncode != 0:
                console.print("[bold red]LLM orchestration failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except (OSError, ValueError) as e:
        console.print(f"[bold red]Error during LLM orchestration:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    # Parse results
    # Prefer tool-scoped SAFE FIX_LLM_DIR (e.g., output/<tool>/llm) if present, then fall back to global
    llm_dir_env = Path(os.getenv("SAFEFIX_LLM_DIR", str(LLM_LAYER)).strip())
    # If tool-scoped path doesn't exist, attempt discovery across output/*/llm
    candidates = [
        llm_dir_env / "llm_decisions.json",
        LLM_LAYER / "llm_decisions.json",
        OUTPUT_DIR / "llm_decisions.json",
    ]
    if not any(p.exists() for p in candidates):
        try:
            for p in OUTPUT_DIR.glob("*/llm/llm_decisions.json"):
                candidates.append(p)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    decisions_path = find_existing(candidates, llm_dir_env / "llm_decisions.json")
    processed = 0
    fixed = 0
    
    if decisions_path.exists():
        data = json.loads(decisions_path.read_text(encoding='utf-8'))
        processed = len(data)
        fixed = sum(1 for item in data if item.get("consensus", {}).get("final_classification") == "fix")
    
    summary_data = {
        "Items Processed": processed,
        "Fixes Generated": fixed,
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    suggestions = [
        "python cli.py combine --file <target_file>",
        f"Review decisions: {decisions_path}",
        "Run validation gates after combining patches"
    ]
    
    print_summary("LLM Orchestration Complete", summary_data, suggestions)


@app.command()
def combine(
    file: str = typer.Argument(..., help="Target file to combine patches for"),
    models: str = typer.Option("groq,openrouter,gemini", "--models", "-m", help="Comma-separated model list"),
    autofix: bool = typer.Option(True, "--autofix/--no-autofix", help="Enable automatic fixes"),
    hygiene: bool = typer.Option(True, "--hygiene/--no-hygiene", help="Enable security hygiene"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Custom output directory"),
    categories: Optional[str] = typer.Option(None, "--categories", "-c", help="Comma-separated finding categories to include"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be executed")
):
    """
    Combine multiple patches for a file into a single secured manifest.
    
    Examples:
        cli.py combine tests/13.nginx_privileged_deployment.yaml
        cli.py combine tests/13.nginx_privileged_deployment.yaml --no-autofix
    """
    _env_guard("combine")
    print_banner()
    start_time = time.time()
    
    file_path = Path(file)
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file}")
        raise typer.Exit(1)
    
    if output:
        combination_dir = Path(output).expanduser()
        if not combination_dir.is_absolute():
            combination_dir = (REPO_ROOT / combination_dir).resolve()
    else:
        combination_dir = COMBINATION_LAYER

    console.print(f"[bold cyan]Target File:[/bold cyan] {file_path}")
    console.print(f"[bold cyan]Output:[/bold cyan] {combination_dir}")
    console.print(f"[bold cyan]Models:[/bold cyan] {models}")
    console.print(f"[bold cyan]Autofix:[/bold cyan] {autofix}")
    console.print(f"[bold cyan]Hygiene:[/bold cyan] {hygiene}")
    if categories:
        console.print(f"[bold cyan]Categories:[/bold cyan] {categories}\n")
    else:
        console.print("")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        cmd_str = f"python {LLMS_DIR / 'combine_yaml_files.py'} --file {file}"
        if hygiene:
            cmd_str += " --hygiene"
        console.print(f"Command: {cmd_str}")
        console.print(f"Env: SAFEFIX_COMBINATION_DIR={combination_dir}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute YAML file combination
    try:
        cmd = [
            sys.executable,
            str(LLMS_DIR / "combine_yaml_files.py"),
            "--file", file,
            "--output", str(combination_dir)
        ]
        
        if hygiene:
            cmd.append("--hygiene")

        combination_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        # Use environment variables if already set (for tool-specific paths), otherwise use defaults
        env["SAFEFIX_OUTPUT_ROOT"] = os.getenv("SAFEFIX_OUTPUT_ROOT", str(OUTPUT_DIR))
        env["SAFEFIX_NORMALIZATION_DIR"] = os.getenv("SAFEFIX_NORMALIZATION_DIR", str(NORMALIZATION_LAYER))
        env["SAFEFIX_LLM_DIR"] = os.getenv("SAFEFIX_LLM_DIR", str(LLM_LAYER))
        env["SAFEFIX_COMBINATION_DIR"] = str(combination_dir)
        
        with console.status("[bold green]Combining fixed YAML files...") as status:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
            
            if result.returncode != 0:
                console.print(f"[bold red]YAML combination failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except Exception as e:
        console.print(f"[bold red]Error during patch combination:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    # Find output file (support new prefixes)
    candidates = [
        combination_dir,
        COMBINATION_LAYER,
        OUTPUT_DIR / "combination",
        OUTPUT_DIR / "combined_patches"
    ]
    output_dir = find_existing(candidates, combination_dir)
    safe_name = file.replace("\\", "_").replace("/", "_")
    prefixes = ["SECURED_", "INEFFECTIVE_", "INVALID_", "MANUAL_REQUIRED_"]
    produced_file = None
    produced_status = None
    # Prefer validation result if available to avoid stale files
    validation_json = output_dir / f"VALIDATION_{safe_name}.json"
    if validation_json.exists():
        try:
            vdata = json.loads(validation_json.read_text(encoding='utf-8'))
            st = str(vdata.get("status", "")).upper()
            status_to_prefix = {
                "EFFECTIVE": "SECURED_",
                "INEFFECTIVE": "INEFFECTIVE_",
                "INVALID": "INVALID_",
                "MANUAL_REQUIRED": "MANUAL_REQUIRED_",
            }
            pref = status_to_prefix.get(st)
            if pref:
                p = output_dir / f"{pref}{safe_name}"
                if p.exists():
                    produced_file = p
                    produced_status = st
        except Exception:
            pass
    # Fallback: pick newest matching file by mtime
    if produced_file is None:
        newest_mtime = -1.0
        newest_path = None
        newest_status = None
        for pref in prefixes:
            p = output_dir / f"{pref}{safe_name}"
            if p.exists():
                try:
                    mtime = p.stat().st_mtime
                    if mtime > newest_mtime:
                        newest_mtime = mtime
                        newest_path = p
                        newest_status = pref.rstrip('_')
                except Exception:
                    continue
        if newest_path:
            produced_file = newest_path
            produced_status = newest_status
    decisions_file = output_dir / f"DECISIONS_{safe_name}.json"
    
    # Look for diff file
    diff_file = output_dir / f"DIFF_{safe_name}.diff"
    summary_file = output_dir / f"SUMMARY_{safe_name}.json"
    
    summary_data = {
        "Files Combined": "Multiple fixed YAML files",
        "Output File": str(produced_file) if produced_file else "Not found",
        "Diff File": str(diff_file) if diff_file.exists() else "Not found",
        "Summary File": str(summary_file) if summary_file.exists() else "Not found",
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    # Validation should be suggested only when validator status is EFFECTIVE (which maps to SECURED_ file)
    validate_hint = (
        f"python cli.py validate --file {produced_file} --gates 1,2"
        if (produced_file and produced_status == "EFFECTIVE")
        else "(skip) Only SECURED_* files should be validated"
    )
    suggestions = [
        validate_hint,
        f"Review secured file: {produced_file}" if produced_file else "Review output directory for results",
        f"View changes: {diff_file}" if diff_file.exists() else "Check diff file in output directory",
        f"Review summary: {summary_file}" if summary_file.exists() else "Check summary file in output directory"
    ]
    
    print_summary("YAML Combination Complete", summary_data, suggestions)


@app.command(name="validate")
def validate_cmd(
    file: str = typer.Argument(..., help="File to validate (we will validate all YAMLs in its directory)"),
    gates: str = typer.Option("1,2", "--gates", "-g", help="Comma-separated gate numbers (1-7)"),
    sandbox: bool = typer.Option(False, "--sandbox", "-s", help="Enable sandbox deployment (gates 4-7)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be validated")
):
    """
    Validate secured manifests through 7-gate validation.
    
    Gates:
        1. Schema validation (kubeconform)
        2. Policy validation (conftest/OPA)
        3. Dry-run apply (kubectl)
        4. Sandbox deploy (kubectl + namespace)
        5. Health checks (probes, responses)
        6. Network validation (NetworkPolicy)
        7. E2E smoke tests
    
    Examples:
        cli.py validate output/combined_patches/SECURED_*.yaml --gates 1,2
        cli.py validate output/combined_patches/SECURED_*.yaml --gates 1,2,3,4,5 --sandbox
    """
    _env_guard("validate")
    print_banner()
    start_time = time.time()
    
    file_path = Path(file)
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file}")
        raise typer.Exit(1)

    # If a JSON decision artifact was passed (e.g., DECISIONS_*.yaml.json), switch to its directory
    # and attempt to auto-locate SECURED_* YAMLs for validation instead of *.yaml.json.
    if file_path.suffix.lower() == ".json":
        console.print("[yellow]Input appears to be a JSON artifact; auto-selecting hardened YAMLs in directory.[/yellow]")
        candidate_dir = file_path.parent
        file_path = candidate_dir  # treat as directory for staging
    
    gate_list = [int(g.strip()) for g in gates.split(",")]
    
    console.print(f"[bold cyan]Validating:[/bold cyan] {file_path}")
    console.print(f"[bold cyan]Gates:[/bold cyan] {', '.join(map(str, gate_list))}")
    console.print(f"[bold cyan]Sandbox:[/bold cyan] {sandbox}\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        gate_map = {1: "schema", 2: "policy", 3: "dryrun", 4: "sandbox", 5: "health", 6: "network", 7: "e2e"}
        gate_numbers = [int(g.strip()) for g in gates.split(",") if g.strip().isdigit()]
        gate_names = [gate_map.get(n) for n in gate_numbers if gate_map.get(n)] or ["schema", "policy"]
        gates_arg = ",".join(gate_names)
        cmd_str = (
            f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"& '{VALIDATIONS_DIR / 'validate-gates.ps1'}' -InputDir '{file_path.parent}' -OutputDir '.' -Gates {gates_arg}{' -EnableSandbox' if sandbox else ''}\""
        )
        console.print(f"Command: {cmd_str}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute validation
    try:
        validate_script = str(VALIDATIONS_DIR / "validate-gates.ps1")

        # Translate numeric gates to names expected by the script
        gate_map = {
            1: "schema", 2: "policy", 3: "dryrun",
            4: "sandbox", 5: "health", 6: "network", 7: "e2e"
        }
        gate_numbers = [int(g.strip()) for g in gates.split(",") if g.strip().isdigit()]
        gate_names = [gate_map.get(n) for n in gate_numbers if gate_map.get(n)]
        if not gate_names:
            gate_names = ["schema", "policy"]
        gates_arg = ",".join(gate_names)

        # Determine source directory (if a specific secured file given, use its parent; if a directory, use it directly)
        src_dir = (file_path.parent if file_path.is_file() else file_path).resolve()
        tmp_root = (VALIDATIONS_DIR / "tmp_inputs").resolve()
        tmp_root.mkdir(parents=True, exist_ok=True)
        tmp_dir = tmp_root / (str(int(time.time())) + "_" + uuid.uuid4().hex[:8])
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Copy only YAML/YML files, skipping known auxiliary prefixes
        skipped = []
        copied = 0
        for p in src_dir.iterdir():
            if not p.is_file():
                continue
            name_lower = p.name.lower()
            # Exclude any JSON-manifest hybrids (*.yaml.json) and decision/policy artifacts
            if name_lower.endswith((".yaml", ".yml")) and not name_lower.endswith(".yaml.json"):
                # Prefer only hardened SECURED_* files if present in directory
                if any(q.startswith("secured_") for q in os.listdir(src_dir)):
                    if not name_lower.startswith("secured_"):
                        skipped.append(p.name)
                        continue
                if name_lower.startswith(("decisions_", "validation_", "scaffold_")):
                    skipped.append(p.name)
                    continue
                try:
                    shutil.copy2(str(p), str(tmp_dir / p.name))
                    copied += 1
                except (OSError, shutil.Error):
                    skipped.append(p.name)
            else:
                # Skip non-YAML
                continue

        input_dir = str(tmp_dir)
        # Prefer writing reports under Validations (script expects OutputDir relative to its CWD)
        output_dir = '.'

        # Build PowerShell command with proper path quoting
        ps_command = (
            f"& '{validate_script}' -InputDir '{input_dir}' -OutputDir '{output_dir}' -Gates {gates_arg}"
        )
        if sandbox:
            ps_command += " -EnableSandbox"

        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", ps_command
        ]
        
        with console.status(f"[bold green]Running validation gates {gates} on {copied} YAMLs (staged) ..."):
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(VALIDATIONS_DIR), check=False)
            
            if result.returncode != 0:
                console.print("[bold red]Validation failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except (OSError, ValueError) as e:
        console.print(f"[bold red]Error during validation:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    summary_data = {
        "Gates Run": len(gate_list),
        "YAMLs Validated": copied,
        "Skipped": len(skipped),
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    suggestions = [
        f"Review evidence: {VALIDATIONS_DIR / 'evidence'}",
        f"Check proof: {VALIDATIONS_DIR / 'safe_fix_proof.json'}",
        "Run remaining gates with --sandbox for full validation"
    ]
    
    print_summary("Validation Complete", summary_data, suggestions)


@app.command()
def review(
    file: str = typer.Argument(..., help="Secured file to review"),
    show_diff: bool = typer.Option(True, "--show-diff/--no-diff", help="Show diff with original")
):
    """
    Interactive review of secured manifest with side-by-side comparison.
    
    Examples:
        cli.py review output/combined_patches/SECURED_tests_13.nginx_privileged_deployment.yaml
    """
    print_banner()
    
    file_path = Path(file)
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file}")
        raise typer.Exit(1)
    
    # Find original file
    secured_name = file_path.name
    original_path = None
    for pref in ["SECURED_", "INEFFECTIVE_", "INVALID_", "MANUAL_REQUIRED_"]:
        if secured_name.startswith(pref):
            original_name = secured_name.replace(pref, "").replace("_", "/")
            original_path = REPO_ROOT / original_name
            break
    
    console.print(f"[bold cyan]Reviewing:[/bold cyan] {file_path}\n")
    
    # Show file content
    content = file_path.read_text(encoding='utf-8')
    syntax = Syntax(content, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="Secured Manifest", border_style="green"))
    
    # Show diff if original exists
    if show_diff and original_path and original_path.exists():
        console.print("\n[bold yellow]Diff with Original:[/bold yellow]")
        
        try:
            import difflib
            
            original_content = original_path.read_text(encoding='utf-8').splitlines(keepends=True)
            secured_content = content.splitlines(keepends=True)
            
            diff = difflib.unified_diff(
                original_content,
                secured_content,
                fromfile=str(original_path),
                tofile=str(file_path),
                lineterm=''
            )
            
            diff_text = ''.join(diff)
            if diff_text:
                diff_syntax = Syntax(diff_text, "diff", theme="monokai")
                console.print(Panel(diff_syntax, title="Changes Applied", border_style="yellow"))
            else:
                console.print("[yellow]No differences found[/yellow]")
        
        except Exception as e:
            console.print(f"[yellow]Could not generate diff: {e}[/yellow]")
    
    # Interactive options
    console.print("\n[bold]Options:[/bold]")
    console.print("  1. Apply to cluster (kubectl apply)")
    console.print("  2. Save to different location")
    console.print("  3. Run validation gates")
    console.print("  4. Exit")
    
    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4"], default="4")
    
    if choice == "1":
        if Confirm.ask(f"Apply {file_path.name} to cluster?"):
            try:
                result = subprocess.run(
                    ["kubectl", "apply", "-f", str(file_path)],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    console.print("[green]Successfully applied to cluster[/green]")
                    console.print(result.stdout)
                else:
                    console.print("[red]Failed to apply[/red]")
                    console.print(result.stderr)
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
    
    elif choice == "2":
        dest = Prompt.ask("Enter destination path")
        try:
            Path(dest).write_text(content, encoding='utf-8')
            console.print(f"[green]Saved to {dest}[/green]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    elif choice == "3":
        console.print(f"\n[cyan]Run: python cli.py validate {file_path} --gates 1,2[/cyan]")


@app.command()
def pipeline(
    path: str = typer.Option("tests", "--path", "-p", help="Path to scan"),
    target_file: Optional[str] = typer.Option(None, "--target", "-t", help="Specific file to patch (optional)"),
    tool: Optional[str] = typer.Option(None, "--tool", help="Single tool to run (e.g., Kubescape, Trivy)"),
    skip_scan: bool = typer.Option(False, "--skip-scan", help="Skip scan if already completed"),
    skip_normalize: bool = typer.Option(False, "--skip-normalize", help="Skip normalization if already completed"),
    skip_llm: bool = typer.Option(False, "--skip-llm", help="Skip LLM analysis if already completed"),
    validate: bool = typer.Option(True, "--validate/--no-validate", help="Run validation after patching"),
    hygiene: bool = typer.Option(False, "--hygiene/--no-hygiene", help="Enable security hygiene checks"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show pipeline steps without executing")
):
    """
    Run the complete SafeFix-K8s pipeline end-to-end.
    
    Pipeline steps:
      1. SCAN - Run security tools on manifests (13 tools or single tool with --tool)
      2. NORMALIZE - Aggregate and deduplicate findings
      3. LLM - Generate fixes using AI consensus
      4. COMBINE - Apply patches to manifests
      5. VALIDATE - Run 7-gate validation (optional)
    
    Available tools (for --tool option):
        KubeConform, KubeLinter, Polaris, Checkov, TrivyConfig, Kubescape,
        KubeScore, Yamllint, KubeAudit, Conftest, RBACPolice, Pluto, Gitleaks
    
    Examples:
        cli.py pipeline --path tests                        # Full pipeline (13 tools)
        cli.py pipeline --path tests --tool Kubescape       # Single tool pipeline
        cli.py pipeline --path tests --target tests/13.nginx_privileged_deployment.yaml
        cli.py pipeline --skip-scan --skip-normalize        # Resume from LLM step
        cli.py pipeline --dry-run                           # Preview pipeline
    """
    _env_guard("pipeline")
    print_banner()
    
    start_time = time.time()
    mode_str = f"using {tool} only" if tool else "with all 13 tools"
    console.print(f"[bold green]Starting Complete Pipeline ({mode_str})[/bold green]\n")
    
    # Create tool-specific output directory if single tool mode
    if tool:
        tool_output_root = OUTPUT_DIR / tool.lower()
        tool_detection_layer = tool_output_root / "detection"
        tool_normalization_layer = tool_output_root / "normalization"
        tool_llm_layer = tool_output_root / "llm"
        tool_combination_layer = tool_output_root / "combination"
        tool_validation_layer = tool_output_root / "validation"
        
        # Create directories
        for layer_dir in [tool_detection_layer, tool_normalization_layer, tool_llm_layer, 
                          tool_combination_layer, tool_validation_layer]:
            layer_dir.mkdir(parents=True, exist_ok=True)
        
        console.print(f"[bold cyan]Output Directory:[/bold cyan] {tool_output_root}\n")
    else:
        tool_output_root = OUTPUT_DIR
        tool_detection_layer = DETECTION_LAYER
        tool_normalization_layer = NORMALIZATION_LAYER
        tool_llm_layer = LLM_LAYER
        tool_combination_layer = COMBINATION_LAYER
        tool_validation_layer = VALIDATION_LAYER
    
    if dry_run:
        console.print("[yellow]DRY RUN - Pipeline steps that would execute:[/yellow]\n")
        if not skip_scan:
            scan_desc = f"Run {tool} tool" if tool else "Run 13 security tools"
            console.print(f"  1. [cyan]SCAN[/cyan] - {scan_desc}")
        if not skip_normalize:
            console.print("  2. [cyan]NORMALIZE[/cyan] - Aggregate findings")
        if not skip_llm:
            console.print("  3. [cyan]LLM[/cyan] - Generate AI fixes")
        console.print("  4. [cyan]COMBINE[/cyan] - Apply patches")
        if validate:
            console.print("  5. [cyan]VALIDATE[/cyan] - Run 7-gate validation")
        if tool:
            console.print(f"\n[cyan]Output will be saved to: {tool_output_root}[/cyan]")
        console.print("\n[yellow]Remove --dry-run to execute pipeline[/yellow]")
        return
    
    # Track pipeline progress
    steps_completed = []
    
    # Set environment variables for tool-specific output
    original_env = os.environ.copy()
    if tool:
        os.environ["SAFEFIX_OUTPUT_ROOT"] = str(tool_output_root)
        os.environ["SAFEFIX_DETECTION_RAW_DIR"] = str(tool_detection_layer / "raw")
        os.environ["SAFEFIX_DETECTION_LOG_DIR"] = str(tool_detection_layer / "logs")
        os.environ["SAFEFIX_NORMALIZATION_DIR"] = str(tool_normalization_layer)
        os.environ["SAFEFIX_LLM_DIR"] = str(tool_llm_layer)
        os.environ["SAFEFIX_COMBINATION_DIR"] = str(tool_combination_layer)
        os.environ["SAFEFIX_VALIDATION_DIR"] = str(tool_validation_layer)
    
    try:
        # Step 1: SCAN
        if not skip_scan:
            console.print("[bold cyan]Step 1/5: SCAN[/bold cyan]")
            if tool:
                console.print(f"Running {tool} security scanner...\n")
                # Set detection output directories
                raw_dir = tool_detection_layer / "raw"
                logs_dir = tool_detection_layer / "logs"
                raw_dir.mkdir(parents=True, exist_ok=True)
                logs_dir.mkdir(parents=True, exist_ok=True)
                
                # Run scan with tool-specific output
                scan_path = Path(path).absolute()
                env = os.environ.copy()
                env["SAFEFIX_OUTPUT_ROOT"] = str(tool_output_root)
                env["SAFEFIX_DETECTION_RAW_DIR"] = str(raw_dir)
                env["SAFEFIX_DETECTION_LOG_DIR"] = str(logs_dir)
                
                script_path = str(DETECTION_DIR / 'detectors.ps1').replace("'", "''")
                scan_path_str = str(scan_path).replace("'", "''")
                ps_command = f". '{script_path}'; Det-RunSingle -Path '{scan_path_str}' -Tool {tool}"
                
                cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
                
                if result.returncode != 0:
                    console.print(f"[bold red]Scan failed[/bold red]")
                    console.print(result.stderr)
                    raise typer.Exit(1)
            else:
                console.print("Running all 13 security detection tools...\n")
                scan(path=path, mode="extended", extended=True, tool=None, dry_run=False)
            steps_completed.append("SCAN")
            console.print("\n[green]✓ Scan completed[/green]\n")
        else:
            console.print("[yellow]⊗ Skipping SCAN (--skip-scan)[/yellow]\n")
        
        # Step 2: NORMALIZE
        if not skip_normalize:
            console.print("[bold cyan]Step 2/5: NORMALIZE[/bold cyan]")
            console.print("Aggregating and deduplicating findings...\n")
            
            # Use tool-specific paths
            raw_input = str(tool_detection_layer / "raw") if tool else str(DETECTION_LAYER / "raw")
            norm_output = str(tool_normalization_layer) if tool else str(NORMALIZATION_LAYER)
            
            normalize(
                raw=raw_input,
                out=norm_output,
                min_support=1,
                only_security=True,
                ml_fp=True,
                ml_threshold=0.6,
                dry_run=False
            )
            steps_completed.append("NORMALIZE")
            console.print("\n[green]✓ Normalization completed[/green]\n")
        else:
            console.print("[yellow]⊗ Skipping NORMALIZE (--skip-normalize)[/yellow]\n")
        
        # Step 3: LLM
        if not skip_llm:
            console.print("[bold cyan]Step 3/5: LLM ANALYSIS[/bold cyan]")
            hygiene_status = "enabled" if hygiene else "disabled"
            console.print(f"Running multi-LLM consensus voting (hygiene {hygiene_status}, 5 parallel)...\n")
            
            # Update environment for LLM stage
            if tool:
                os.environ["SAFEFIX_NORMALIZATION_DIR"] = str(tool_normalization_layer)
                os.environ["SAFEFIX_LLM_DIR"] = str(tool_llm_layer)
            else:
                # Ensure we write to the global output/llm even if a previous run left a tool-scoped env var around
                os.environ["SAFEFIX_NORMALIZATION_DIR"] = str(NORMALIZATION_LAYER)
                os.environ["SAFEFIX_LLM_DIR"] = str(LLM_LAYER)
            
            llm_run(
                models="groq,openrouter,gemini",
                autofix=True,
                hygiene=hygiene,
                limit=0,
                timeout=25,
                concurrency=5,
                validate="yaml",
                apply_dir=None,
                dry_run=False
            )
            steps_completed.append("LLM")
            console.print("\n[green]✓ LLM analysis completed[/green]\n")
        else:
            console.print("[yellow]⊗ Skipping LLM (--skip-llm)[/yellow]\n")
        
        # Step 4: COMBINE
        console.print("[bold cyan]Step 4/5: COMBINE PATCHES[/bold cyan]")
        
        # Determine which files to patch
        if target_file:
            files_to_patch = [target_file]
            console.print(f"Patching specific file: {target_file}\n")
        else:
            # Find all files with patches from LLM output
            # Search global and tool-scoped locations e.g., output/<tool>/llm/llm_decisions.json
            candidates = []
            if tool:
                candidates.append(tool_llm_layer / "llm_decisions.json")
            candidates.extend([
                LLM_LAYER / "llm_decisions.json",
                OUTPUT_DIR / "llm/llm_decisions.json",
            ])
            try:
                for p in OUTPUT_DIR.glob("*/llm/llm_decisions.json"):
                    candidates.append(p)
            except Exception:
                pass

            llm_decisions_file = next((p for p in candidates if p.exists()), None)
            if llm_decisions_file is None:
                console.print(f"[red]Error:[/red] No LLM decisions found under {OUTPUT_DIR}. Run 'python cli.py run' first or check API keys in .env.")
                raise typer.Exit(1)

            with llm_decisions_file.open(encoding="utf-8") as f:
                llm_data = json.load(f)
            files_to_patch = list({item.get("file", "") for item in llm_data if item.get("file")})
            console.print(f"Found {len(files_to_patch)} files to patch (from {llm_decisions_file})\n")
        
        # Update environment for combination stage
        if tool:
            os.environ["SAFEFIX_COMBINATION_DIR"] = str(tool_combination_layer)
        
        # Apply patches to each file
        patched_files = []
        for file_path in files_to_patch:
            if file_path:
                console.print(f"[cyan]Patching: {file_path}[/cyan]")
                combine(
                    file=file_path,
                    models="groq,openrouter,gemini",
                    autofix=True,
                    hygiene=True,
                    output=str(tool_combination_layer) if tool else None,
                    categories=None,
                    dry_run=False
                )
                patched_files.append(file_path)
        
        steps_completed.append("COMBINE")
        console.print(f"\n[green]✓ Patched {len(patched_files)} files[/green]\n")
        
        # Step 5: VALIDATE (optional)
        if validate:
            console.print("[bold cyan]Step 5/5: VALIDATE[/bold cyan]")
            console.print("Running 7-gate validation framework...\n")
            
            # Update environment for validation stage
            if tool:
                os.environ["SAFEFIX_VALIDATION_DIR"] = str(tool_validation_layer)
            
            # Validate each patched file
            # Use the combination layer where SECURED_/INEFFECTIVE_/... files are written
            output_dir = tool_combination_layer if tool else COMBINATION_LAYER
            if output_dir.exists():
                secured_files = list(output_dir.glob("SECURED_*.yaml"))
                console.print(f"Validating {len(secured_files)} secured files\n")
                
                for secured_file in secured_files:
                    console.print(f"[cyan]Validating: {secured_file.name}[/cyan]")
                    # Call validate command via subprocess to avoid naming conflict
                    validate_args = [
                        sys.executable,
                        __file__,
                        "validate",
                        str(secured_file),
                        "--gates", "1,2,3"
                    ]
                    result = subprocess.run(validate_args, capture_output=True, text=True, cwd=str(REPO_ROOT), check=False)
                    if result.returncode != 0:
                        console.print(f"[red]Validation failed for {secured_file.name}[/red]")
                        console.print(result.stderr)
                    else:
                        console.print(result.stdout)
                
                steps_completed.append("VALIDATE")
                console.print(f"\n[green]✓ Validation completed[/green]\n")
            else:
                console.print("[yellow]No secured files found to validate[/yellow]\n")
        else:
            console.print("[yellow]⊗ Skipping VALIDATE (--no-validate)[/yellow]\n")
        
    except Exception as e:
        console.print(f"\n[bold red]Pipeline failed at step: {steps_completed[-1] if steps_completed else 'START'}[/bold red]")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    finally:
        # Restore original environment
        if tool:
            os.environ.clear()
            os.environ.update(original_env)
    
    # Final summary
    elapsed = time.time() - start_time
    
    console.print("\n" + "="*60)
    console.print("[bold green]PIPELINE COMPLETED SUCCESSFULLY[/bold green]")
    console.print("="*60 + "\n")
    
    output_location = str(tool_output_root) if tool else str(OUTPUT_DIR / "combined_patches")
    
    summary_data = {
        "Total Time": f"{elapsed:.1f}s",
        "Steps Completed": " → ".join(steps_completed),
        "Files Scanned": path,
        "Files Patched": len(patched_files) if 'patched_files' in locals() else 0,
        "Output Directory": output_location
    }
    
    print_summary("Pipeline Summary", summary_data)
    
    console.print("\n[bold cyan]Next Steps:[/bold cyan]")
    if tool:
        console.print(f"  1. Review output in: {tool_output_root}/")
        console.print(f"  2. Secured files in: {tool_combination_layer}/")
    else:
        console.print("  1. Review secured files in: output/combined_patches/")
    console.print("  3. Use: python cli.py review <file> to compare changes")
    console.print("  4. Deploy validated manifests to your cluster")


@app.command()
def completion(
    shell: str = typer.Argument("bash", help="Shell type: bash, zsh, fish, powershell")
):
    """
    Generate shell completion scripts.
    
    Examples:
        cli.py completion bash > ~/.bash_completion.d/safefix-k8s
        cli.py completion zsh > ~/.zsh/completions/_safefix-k8s
    """
    console.print(f"[cyan]Generating {shell} completion...[/cyan]")
    console.print(f"[yellow]Note: Auto-completion support requires typer[all][/yellow]")
    console.print(f"\nInstall: pip install 'typer[all]'")
    console.print(f"Then run: safefix-k8s --install-completion {shell}")


@app.command()
def report(
    scope: str = typer.Option(str(OUTPUT_DIR), "--scope", "-s", help="Root directory to scan for VALIDATION_*.json (default: output)"),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Write consolidated report JSON here (defaults next to scope)")
):
    """
    Aggregate VALIDATION_*.json files into a summary per tool and overall totals.

    Examples:
        cli.py report --scope output/conftest/combination
        cli.py report --scope output
    """
    print_banner()
    scope_path = Path(scope).resolve()
    if not scope_path.exists():
        console.print(f"[bold red]Error:[/bold red] Scope path not found: {scope}")
        raise typer.Exit(1)

    # Collect all validation files
    validation_files: List[Path] = []
    if scope_path.is_file() and scope_path.name.startswith("VALIDATION_"):
        validation_files = [scope_path]
    else:
        # Typical shapes: output/<tool>/combination/VALIDATION_*.json or output/combination
        for p in scope_path.rglob("VALIDATION_*.json"):
            validation_files.append(p)

    if not validation_files:
        console.print("[yellow]No validation files found under scope[/yellow]")
        return

    total = len(validation_files)
    by_status = {"EFFECTIVE": 0, "INEFFECTIVE": 0, "INVALID": 0, "MANUAL_REQUIRED": 0}
    examples: List[dict] = []
    by_tool: dict = {}

    def infer_tool(p: Path) -> str:
        # Expect path like output/<tool>/combination/VALIDATION_...
        parts = [x.lower() for x in p.parts]
        if "output" in parts:
            try:
                idx = parts.index("output")
                if idx + 1 < len(parts):
                    return p.parts[idx + 1]
            except Exception:
                pass
        return "root"

    for vf in validation_files:
        try:
            data = json.loads(vf.read_text(encoding='utf-8'))
        except Exception:
            continue
        status = str(data.get("status", "")).upper() or "INEFFECTIVE"
        if status not in by_status:
            status = "INEFFECTIVE"
        by_status[status] += 1
        tool = infer_tool(vf)
        by_tool.setdefault(tool, {"EFFECTIVE": 0, "INEFFECTIVE": 0, "INVALID": 0, "MANUAL_REQUIRED": 0, "files": []})
        by_tool[tool][status] += 1
        # Keep up to 3 examples
        if len(examples) < 3:
            examples.append({"file": data.get("original_file"), "status": status, "path": str(vf)})

    summary = {
        "scope": str(scope_path),
        "totals": {"files": total, **by_status},
        "by_tool": by_tool,
        "examples": examples,
        "generated_at": datetime.now().isoformat(timespec='seconds')
    }

    # Output path
    if out:
        out_path = Path(out)
        if not out_path.is_absolute():
            out_path = (scope_path if scope_path.is_dir() else scope_path.parent) / out_path
    else:
        base_dir = scope_path if scope_path.is_dir() else scope_path.parent
        out_path = base_dir / "patch_validation_report.json"
    try:
        out_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
        console.print(f"[green]Wrote report:[/green] {out_path}")
    except Exception as e:
        console.print(f"[red]Failed to write report:[/red] {e}")

    # Pretty table
    table = Table(title="Validation Summary", show_header=True, header_style="bold magenta", box=_table_box())
    table.add_column("Status", style="cyan")
    table.add_column("Count", justify="right")
    for k in ("EFFECTIVE", "INEFFECTIVE", "INVALID", "MANUAL_REQUIRED"):
        table.add_row(k, str(by_status[k]))
    console.print(table)


@app.command()
def evaluate(
    normalized: Optional[str] = typer.Option(None, "--normalized", "-n", help="Path to llm_payload.json; if omitted, --scope will be used"),
    scope: Optional[str] = typer.Option(str(OUTPUT_DIR), "--scope", "-s", help="Search recursively under this folder for llm_payload.json when --normalized not provided"),
    gt: str = typer.Option(str(REPO_ROOT / "Evaluation" / "ground_truth_vulns.json"), "--gt", help="Ground truth JSON path"),
    out: str = typer.Option(str(OUTPUT_DIR / "detection_effectiveness_report.json"), "--out", "-o", help="Where to write evaluation report")
):
    """
    Evaluate detection coverage against ground truth vulnerabilities.

    Examples:
        cli.py evaluate --normalized output/normalization/llm_payload.json
        cli.py evaluate --scope output --gt Evaluation/ground_truth_vulns.json
    """
    print_banner()
    eval_script = EVAL_DIR / "evaluate_detection.py"
    if not eval_script.exists():
        console.print(f"[bold red]Error:[/bold red] Evaluation script not found at {eval_script}")
        raise typer.Exit(1)

    args = [sys.executable, str(eval_script), "--gt", gt, "--out", out]
    if normalized:
        args.extend(["--normalized", normalized])
    else:
        if scope:
            args.extend(["--scope", scope])

    with console.status("[bold green]Running evaluation..."):
        result = subprocess.run(args, capture_output=True, text=True, cwd=str(REPO_ROOT))
        if result.returncode != 0:
            console.print("[bold red]Evaluation failed[/bold red]")
            console.print(result.stderr)
            raise typer.Exit(1)
        console.print(result.stdout)

    # Print a short summary if report exists
    try:
        data = json.loads(Path(out).read_text(encoding='utf-8'))
        reports = data.get("reports", [])
        table = Table(title="Detection Effectiveness", show_header=True, header_style="bold magenta", box=_table_box())
        table.add_column("Payload", style="cyan")
        table.add_column("Recall", justify="right")
        table.add_column("Precision", justify="right")
        for r in reports:
            totals = r.get("totals", {})
            table.add_row(Path(r.get("payload","?")).name, str(totals.get("recall","?")), str(totals.get("precision","?")))
        console.print(table)
        console.print(f"[green]Report saved to:[/green] {out}")
    except Exception:
        pass


@app.command()
def raw_to_llm(
    tool: str = typer.Argument(..., help="Tool name: checkov, trivy, kubescape, kubeaudit, conftest, polaris, gitleaks, kubeconform, kubelinter, kubescore, pluto, rbacpolice, yamllint"),
    raw_file: str = typer.Option(None, "--raw", "-r", help="Path to raw tool output file"),
    models: str = typer.Option("groq,openrouter,gemini", "--models", "-m", help="Comma-separated LLM providers"),
    concurrency: int = typer.Option(15, "--concurrency", "-c", help="Number of items to process in parallel"),
    fast: bool = typer.Option(True, "--fast/--quality", help="Fast mode (model sharding) or quality mode (full consensus)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory for LLM decisions")
):
    """
    Send raw tool findings directly to LLM (bypasses normalization).
    
    This command takes raw detection output from a specific tool and sends it
    directly to the LLM orchestrator without going through the normalizer.
    
    Examples:
        cli.py raw-to-llm checkov --raw Detection/output/detection/raw/checkov_raw.json
        cli.py raw-to-llm trivy --raw Detection/output/detection/raw/trivy_config_raw.json --fast
        cli.py raw-to-llm kubescape --raw Detection/output/detection/raw/kubescape_raw.json --quality
    """
    _env_guard("llm")
    print_banner()
    start_time = time.time()
    
    # Find raw file if not provided
    if not raw_file:
        raw_candidates = [
            DETECTION_DIR / "output" / "detection" / "raw" / f"{tool.lower()}_raw.json",
            DETECTION_DIR / "output" / "raw" / f"{tool.lower()}_raw.json",
            DETECTION_LAYER / "raw" / f"{tool.lower()}_raw.json",
            OUTPUT_DIR / "detection" / "raw" / f"{tool.lower()}_raw.json",
        ]
        
        for candidate in raw_candidates:
            if candidate.exists():
                raw_file = str(candidate)
                break
        
        if not raw_file:
            console.print(f"[bold red]Error:[/bold red] Raw file not found for {tool}")
            console.print(f"Checked locations:")
            for c in raw_candidates:
                console.print(f"  - {c}")
            console.print(f"\nPlease specify with --raw option")
            raise typer.Exit(1)
    
    raw_path = Path(raw_file)
    if not raw_path.exists():
        console.print(f"[bold red]Error:[/bold red] Raw file not found: {raw_file}")
        raise typer.Exit(1)
    
    console.print(f"[bold cyan]Tool:[/bold cyan] {tool.upper()}")
    console.print(f"[bold cyan]Raw File:[/bold cyan] {raw_path}")
    console.print(f"[bold cyan]Models:[/bold cyan] {models}")
    console.print(f"[bold cyan]Mode:[/bold cyan] {'FAST (sharding)' if fast else 'QUALITY (consensus)'}")
    console.print(f"[bold cyan]Concurrency:[/bold cyan] {concurrency}\n")
    
    # Run raw-to-llm script
    raw_to_llm_script = LLMS_DIR / "raw_to_llm.py"
    if not raw_to_llm_script.exists():
        console.print(f"[bold red]Error:[/bold red] {raw_to_llm_script} not found")
        raise typer.Exit(1)
    
    cmd = [
        sys.executable, str(raw_to_llm_script),
        "--tool", tool.lower(),
        "--raw", str(raw_path),
        "--models", models,
        "--concurrency", str(concurrency)
    ]
    
    if fast:
        cmd.append("--shard-models")
    
    if output:
        cmd.extend(["--output", output])
    
    env = os.environ.copy()
    env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
    env["SAFEFIX_NORMALIZATION_DIR"] = str(NORMALIZATION_LAYER)
    env["SAFEFIX_LLM_DIR"] = str(LLM_LAYER)
    
    try:
        with console.status(f"[bold green]Processing raw {tool} findings..."):
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
            
            if result.returncode != 0:
                console.print(f"[bold red]Raw-to-LLM processing failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except Exception as e:
        console.print(f"[bold red]Error during raw-to-LLM processing:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    # Find output
    output_dir = Path(output) if output else LLM_LAYER
    decisions_file = output_dir / "llm_decisions.json"
    
    summary_data = {
        "Tool": tool.upper(),
        "Raw File": str(raw_path),
        "Decisions File": str(decisions_file) if decisions_file.exists() else "Not found",
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    suggestions = [
        f"Review decisions: {decisions_file}",
        "Run combine to apply fixes: python cli.py combine <target_file>",
        "Or use: python LLMs/combine_yaml_files.py --file <target_file>"
    ]
    
    print_summary("Raw-to-LLM Complete", summary_data, suggestions)


@app.command()
def start():
    """
    Interactive onboarding wizard for first-time users.
    """
    print_banner()
    
    console.print("[bold]Welcome to SafeFix-K8s![/bold]\n")
    console.print("This wizard will help you get started with the security remediation pipeline.\n")
    
    # Check prerequisites
    console.print("[bold cyan]Checking prerequisites...[/bold cyan]")
    
    checks = {
        "Docker": ["docker", "--version"],
        "Python": [sys.executable, "--version"],
        "PowerShell": ["powershell", "-Command", "$PSVersionTable.PSVersion"]
    }
    
    for name, cmd in checks.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                console.print(f"  ✓ {name} found")
            else:
                console.print(f"  ✗ {name} not found", style="bold red")
        except Exception:
            console.print(f"  ✗ {name} not found", style="bold red")
    
    # Check .env
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        console.print("\n[yellow]No .env file found. Create one now?[/yellow]")
        if Confirm.ask("Create .env with sample API keys?"):
            sample_env = """# SafeFix-K8s API Keys
GROQ_API_KEY=your_groq_key_here
OPENROUTER_API_KEY=your_openrouter_key_here
GEMINI_API_KEY=your_gemini_key_here
OLLAMA_BASE_URL=http://localhost:11434
"""
            env_file.write_text(sample_env)
            console.print(f"[green]Created {env_file}[/green]")
            console.print("[yellow]Please edit it with your actual API keys.[/yellow]")
    else:
        console.print("\n  ✓ .env file found")
    
    # Suggest first command
    console.print("\n[bold green]Ready to start![/bold green]")
    console.print("\n[bold]Suggested first steps:[/bold]")
    console.print("  1. python cli.py scan --path tests")
    console.print("  2. python cli.py normalize")
    console.print("  3. python cli.py llm run --autofix --hygiene")
    console.print("  4. python cli.py combine tests/13.nginx_privileged_deployment.yaml")
    console.print("  5. python cli.py validate <secured_file> --gates 1,2")
    
    if Confirm.ask("\nRun first scan now?"):
        console.print("\n")
        scan(path="tests", mode="extended", extended=True, dry_run=False)


if __name__ == "__main__":
    app()
