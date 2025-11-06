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
from typing import Optional, List
from datetime import datetime

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
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

# Get repo root
REPO_ROOT = Path(__file__).parent.absolute()
DETECTION_DIR = REPO_ROOT / "Detection"
NORMALIZER_DIR = REPO_ROOT / "Normalizer"
LLMS_DIR = REPO_ROOT / "LLMs"
VALIDATIONS_DIR = REPO_ROOT / "Validations"
OUTPUT_DIR = REPO_ROOT / "output"


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
    """Print CLI banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║          SafeFix-K8s Security Remediation Pipeline        ║
║                    Automated Security Fixes                ║
╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def print_summary(title: str, data: dict, suggestions: List[str] = None):
    """Print a formatted summary table."""
    table = Table(title=title, show_header=True, header_style="bold magenta")
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
    mode: str = typer.Option("extended", "--mode", "-m", help="Scan mode: lean or extended"),
    extended: bool = typer.Option(True, "--extended/--lean", "-e/-l", help="Use extended mode (13 tools) - default is extended"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be scanned without executing"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Custom output directory")
):
    """
    Scan Kubernetes manifests for security issues.
    
    By default, runs EXTENDED mode with all 13 tools (10 LEAN + rbac-police, pluto, gitleaks).
    Use --lean to run only the 10 core tools.
    
    Examples:
        cli.py scan --path tests                    # Extended mode (13 tools)
        cli.py scan --path . --lean                 # Lean mode (10 tools)
        cli.py scan --dry-run
    """
    print_banner()
    start_time = time.time()
    
    scan_path = Path(path).absolute()
    if not scan_path.exists():
        console.print(f"[bold red]Error:[/bold red] Path not found: {path}")
        raise typer.Exit(1)
    
    mode_str = "EXTENDED" if extended or mode.lower() == "extended" else "LEAN"
    tool_count = 13 if extended or mode.lower() == "extended" else 10
    
    console.print(f"[bold cyan]Scanning:[/bold cyan] {scan_path}")
    console.print(f"[bold cyan]Mode:[/bold cyan] {mode_str} ({tool_count} tools)")
    console.print(f"[bold cyan]Started:[/bold cyan] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        console.print(f"Command: powershell -NoProfile -ExecutionPolicy Bypass -Command \". {DETECTION_DIR / 'detectors.ps1'}; {'Det-RunExtended' if extended else 'Det-RunLean'} -Path '{scan_path}'\"")
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
        with console.status(f"[bold green]Running {tool_count} security scanners...") as status:
            if sys.platform == "win32":
                # Dot-source the script to load functions, then call the function
                script_path = str(DETECTION_DIR / 'detectors.ps1').replace("'", "''")  # Escape single quotes
                scan_path_str = str(scan_path).replace("'", "''")  # Convert Path to str first
                function_name = 'Det-RunExtended' if extended else 'Det-RunLean'
                
                # Use dot-sourcing with proper escaping
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
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
            
            if result.returncode != 0:
                console.print(f"[bold red]Scan failed with exit code {result.returncode}[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
    
    except Exception as e:
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
            except:
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
        tool_table = Table(show_header=True, header_style="bold magenta")
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
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be normalized")
):
    """
    Normalize raw detection findings into a unified schema.
    
    Examples:
    cli.py normalize
    cli.py normalize --raw output/detection/raw --out output/normalization
        cli.py normalize --min-support 2 --only-security
    """
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
    console.print(f"[bold cyan]Security Only:[/bold cyan] {only_security}\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        console.print(f"Command: python {NORMALIZER_DIR / 'normalize.py'} --raw {raw_dir} --out {out_dir}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute normalization
    try:
        with console.status("[bold green]Normalizing findings...") as status:
            cmd = [
                sys.executable,
                str(NORMALIZER_DIR / "normalize.py"),
                "--raw", str(raw_dir),
                "--out", str(out_dir)
            ]

            env = os.environ.copy()
            env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
            env["SAFEFIX_DETECTION_RAW_DIR"] = str(raw_dir)
            env["SAFEFIX_NORMALIZATION_DIR"] = str(out_dir)
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
            
            if result.returncode != 0:
                console.print(f"[bold red]Normalization failed[/bold red]")
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
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be executed")
):
    """
    Run LLM orchestration to generate security patches.
    
    Examples:
        cli.py llm run --models groq,openrouter
        cli.py llm run --autofix --hygiene --limit 10
        cli.py llm run --no-autofix --timeout 60
    """
    print_banner()
    start_time = time.time()
    
    console.print(f"[bold cyan]Models:[/bold cyan] {models}")
    console.print(f"[bold cyan]Autofix:[/bold cyan] {autofix}")
    console.print(f"[bold cyan]Hygiene:[/bold cyan] {hygiene}")
    console.print(f"[bold cyan]Limit:[/bold cyan] {limit if limit > 0 else 'All'}")
    console.print(f"[bold cyan]Timeout:[/bold cyan] {timeout}s\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        cmd_str = f"python {LLMS_DIR / 'multi_llm_orchestrator.py'} --models {models}"
        if autofix:
            cmd_str += " --autofix"
        if hygiene:
            cmd_str += " --hygiene"
        if limit > 0:
            cmd_str += f" --limit {limit}"
        console.print(f"Command: {cmd_str}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute LLM orchestration
    try:
        cmd = [
            sys.executable,
            str(LLMS_DIR / "multi_llm_orchestrator.py"),
            "--models", models,
            "--timeout", str(timeout)
        ]
        
        if autofix:
            cmd.append("--autofix")
        if hygiene:
            cmd.append("--hygiene")
        if limit > 0:
            cmd.extend(["--limit", str(limit)])
        
        env = os.environ.copy()
        env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
        env["SAFEFIX_NORMALIZATION_DIR"] = str(NORMALIZATION_LAYER)
        env["SAFEFIX_LLM_DIR"] = str(LLM_LAYER)
        env["SAFEFIX_LLM_SANDBOX_DIR"] = str(LLM_LAYER / "patch_sandbox")

        with console.status("[bold green]Running LLM orchestration...") as status:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
            
            if result.returncode != 0:
                console.print(f"[bold red]LLM orchestration failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except Exception as e:
        console.print(f"[bold red]Error during LLM orchestration:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    # Parse results
    decisions_path = find_existing([
        LLM_LAYER / "llm_decisions.json",
        OUTPUT_DIR / "llm_decisions.json"
    ], LLM_LAYER / "llm_decisions.json")
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
        cmd_str = f"python {LLMS_DIR / 'combine_patches.py'} --file {file} --models {models}"
        if autofix:
            cmd_str += " --autofix"
        if hygiene:
            cmd_str += " --hygiene"
        if categories:
            cmd_str += f" --categories {categories}"
        console.print(f"Command: {cmd_str}")
        console.print(f"Env: SAFEFIX_COMBINATION_DIR={combination_dir}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute patch combination
    try:
        cmd = [
            sys.executable,
            str(LLMS_DIR / "combine_patches.py"),
            "--file", file,
            "--models", models
        ]
        
        if autofix:
            cmd.append("--autofix")
        if hygiene:
            cmd.append("--hygiene")
        if categories:
            cmd.extend(["--categories", categories])

        combination_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["SAFEFIX_OUTPUT_ROOT"] = str(OUTPUT_DIR)
        env["SAFEFIX_NORMALIZATION_DIR"] = str(NORMALIZATION_LAYER)
        env["SAFEFIX_LLM_DIR"] = str(LLM_LAYER)
        env["SAFEFIX_COMBINATION_DIR"] = str(combination_dir)
        
        with console.status("[bold green]Combining patches...") as status:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
            
            if result.returncode != 0:
                console.print(f"[bold red]Patch combination failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except Exception as e:
        console.print(f"[bold red]Error during patch combination:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    # Find output file
    candidates = [
        combination_dir,
        COMBINATION_LAYER,
        OUTPUT_DIR / "combination",
        OUTPUT_DIR / "combined_patches"
    ]
    output_dir = find_existing(candidates, combination_dir)
    safe_name = file.replace("\\", "_").replace("/", "_")
    secured_file = output_dir / f"SECURED_{safe_name}"
    decisions_file = output_dir / f"DECISIONS_{safe_name}.json"
    
    summary_data = {
        "Patches Combined": "Multiple",
        "Output File": str(secured_file) if secured_file.exists() else "Not found",
        "Decisions Log": str(decisions_file) if decisions_file.exists() else "Not found",
        "Elapsed Time": f"{elapsed:.1f}s"
    }
    
    suggestions = [
        f"python cli.py validate --file {secured_file} --gates 1,2",
        f"Review secured file: {secured_file}",
        f"Review decision log: {decisions_file}",
        "Compare with original using diff tools"
    ]
    
    print_summary("Patch Combination Complete", summary_data, suggestions)


@app.command()
def validate(
    file: str = typer.Argument(..., help="File to validate"),
    gates: str = typer.Option("1,2", "--gates", "-g", help="Comma-separated gate numbers (1-7)"),
    sandbox: bool = typer.Option(False, "--sandbox", "-s", help="Enable sandbox deployment (gates 3-7)"),
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
    print_banner()
    start_time = time.time()
    
    file_path = Path(file)
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file}")
        raise typer.Exit(1)
    
    gate_list = [int(g.strip()) for g in gates.split(",")]
    
    console.print(f"[bold cyan]Validating:[/bold cyan] {file_path}")
    console.print(f"[bold cyan]Gates:[/bold cyan] {', '.join(map(str, gate_list))}")
    console.print(f"[bold cyan]Sandbox:[/bold cyan] {sandbox}\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - showing what would be executed:[/yellow]\n")
        cmd_str = f"powershell -NoProfile -ExecutionPolicy Bypass -File {VALIDATIONS_DIR / 'validate-gates.ps1'} -FilePath {file}"
        if sandbox:
            cmd_str += " -EnableSandbox"
        console.print(f"Command: {cmd_str}")
        console.print("\n[yellow]No changes made. Remove --dry-run to execute.[/yellow]")
        return
    
    # Execute validation
    try:
        validate_script = str(VALIDATIONS_DIR / "validate-gates.ps1")
        
        # Build PowerShell command with proper path quoting
        ps_command = f"& '{validate_script}' -FilePath '{file_path}'"
        if sandbox:
            ps_command += " -EnableSandbox"
        
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", ps_command
        ]
        
        with console.status(f"[bold green]Running validation gates {gates}...") as status:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(VALIDATIONS_DIR))
            
            if result.returncode != 0:
                console.print(f"[bold red]Validation failed[/bold red]")
                console.print(result.stderr)
                raise typer.Exit(1)
            
            console.print(result.stdout)
    
    except Exception as e:
        console.print(f"[bold red]Error during validation:[/bold red] {e}")
        raise typer.Exit(1)
    
    elapsed = time.time() - start_time
    
    summary_data = {
        "Gates Run": len(gate_list),
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
    if secured_name.startswith("SECURED_"):
        original_name = secured_name.replace("SECURED_", "").replace("_", "/")
        original_path = REPO_ROOT / original_name
    else:
        original_path = None
    
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
    skip_scan: bool = typer.Option(False, "--skip-scan", help="Skip scan if already completed"),
    skip_normalize: bool = typer.Option(False, "--skip-normalize", help="Skip normalization if already completed"),
    skip_llm: bool = typer.Option(False, "--skip-llm", help="Skip LLM analysis if already completed"),
    validate: bool = typer.Option(True, "--validate/--no-validate", help="Run validation after patching"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show pipeline steps without executing")
):
    """
    Run the complete SafeFix-K8s pipeline end-to-end.
    
    Pipeline steps:
      1. SCAN - Run all 13 security tools on manifests
      2. NORMALIZE - Aggregate and deduplicate findings
      3. LLM - Generate fixes using AI consensus
      4. COMBINE - Apply patches to manifests
      5. VALIDATE - Run 7-gate validation (optional)
    
    Examples:
        cli.py pipeline --path tests
        cli.py pipeline --path tests --target tests/13.nginx_privileged_deployment.yaml
        cli.py pipeline --skip-scan --skip-normalize  # Resume from LLM step
        cli.py pipeline --dry-run  # Preview pipeline
    """
    print_banner()
    
    start_time = time.time()
    console.print("[bold green]Starting Complete Pipeline[/bold green]\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN - Pipeline steps that would execute:[/yellow]\n")
        if not skip_scan:
            console.print("  1. [cyan]SCAN[/cyan] - Run 13 security tools")
        if not skip_normalize:
            console.print("  2. [cyan]NORMALIZE[/cyan] - Aggregate findings")
        if not skip_llm:
            console.print("  3. [cyan]LLM[/cyan] - Generate AI fixes")
        console.print("  4. [cyan]COMBINE[/cyan] - Apply patches")
        if validate:
            console.print("  5. [cyan]VALIDATE[/cyan] - Run 7-gate validation")
        console.print("\n[yellow]Remove --dry-run to execute pipeline[/yellow]")
        return
    
    # Track pipeline progress
    steps_completed = []
    
    try:
        # Step 1: SCAN
        if not skip_scan:
            console.print("[bold cyan]Step 1/5: SCAN[/bold cyan]")
            console.print("Running all 13 security detection tools...\n")
            scan(path=path, mode="extended", extended=True, dry_run=False)
            steps_completed.append("SCAN")
            console.print("\n[green]✓ Scan completed[/green]\n")
        else:
            console.print("[yellow]⊗ Skipping SCAN (--skip-scan)[/yellow]\n")
        
        # Step 2: NORMALIZE
        if not skip_normalize:
            console.print("[bold cyan]Step 2/5: NORMALIZE[/bold cyan]")
            console.print("Aggregating and deduplicating findings...\n")
            normalize(
                raw="Detection/output/raw",
                out="output",
                min_support=1,
                only_security=True,
                dry_run=False
            )
            steps_completed.append("NORMALIZE")
            console.print("\n[green]✓ Normalization completed[/green]\n")
        else:
            console.print("[yellow]⊗ Skipping NORMALIZE (--skip-normalize)[/yellow]\n")
        
        # Step 3: LLM
        if not skip_llm:
            console.print("[bold cyan]Step 3/5: LLM ANALYSIS[/bold cyan]")
            console.print("Running multi-LLM consensus voting...\n")
            llm_run(
                models="groq,openrouter,gemini",
                autofix=True,
                hygiene=True,
                limit=0,
                timeout=25,
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
            llm_decisions_file = OUTPUT_DIR / "llm_decisions.json"
            if llm_decisions_file.exists():
                with open(llm_decisions_file) as f:
                    llm_data = json.load(f)
                    files_to_patch = list(set([item.get("file", "") for item in llm_data if item.get("file")]))
                    console.print(f"Found {len(files_to_patch)} files to patch\n")
            else:
                console.print("[red]Error: No LLM decisions found. Run LLM step first.[/red]")
                raise typer.Exit(1)
        
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
                    output=None,
                    dry_run=False
                )
                patched_files.append(file_path)
        
        steps_completed.append("COMBINE")
        console.print(f"\n[green]✓ Patched {len(patched_files)} files[/green]\n")
        
        # Step 5: VALIDATE (optional)
        if validate:
            console.print("[bold cyan]Step 5/5: VALIDATE[/bold cyan]")
            console.print("Running 7-gate validation framework...\n")
            
            # Validate each patched file
            output_dir = OUTPUT_DIR / "combined_patches"
            if output_dir.exists():
                secured_files = list(output_dir.glob("SECURED_*.yaml"))
                console.print(f"Validating {len(secured_files)} secured files\n")
                
                for secured_file in secured_files:
                    console.print(f"[cyan]Validating: {secured_file.name}[/cyan]")
                    validate(file=str(secured_file), gates="1,2,3", sandbox=False, dry_run=False)
                
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
    
    # Final summary
    elapsed = time.time() - start_time
    
    console.print("\n" + "="*60)
    console.print("[bold green]PIPELINE COMPLETED SUCCESSFULLY[/bold green]")
    console.print("="*60 + "\n")
    
    summary_data = {
        "Total Time": f"{elapsed:.1f}s",
        "Steps Completed": " → ".join(steps_completed),
        "Files Scanned": path,
        "Files Patched": len(patched_files) if 'patched_files' in locals() else 0,
        "Output Directory": str(OUTPUT_DIR / "combined_patches")
    }
    
    print_summary("Pipeline Summary", summary_data)
    
    console.print("\n[bold cyan]Next Steps:[/bold cyan]")
    console.print("  1. Review secured files in: output/combined_patches/")
    console.print("  2. Use: python cli.py review <file> to compare changes")
    console.print("  3. Deploy validated manifests to your cluster")


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
