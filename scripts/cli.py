import click, subprocess, sys
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

REPO_ROOT = Path(__file__).parent
# Prefer capitalized canonical folders with legacy fallbacks
DETECTION_DIR = REPO_ROOT / ("Detection" if (REPO_ROOT / "Detection").exists() else "detection")
DETECTORS_SCRIPT = DETECTION_DIR / "detectors.ps1"

# Normalizer entrypoint (normalize.py)
_norm_cap = REPO_ROOT / "Normalizer" / "normalize.py"
_norm_legacy = REPO_ROOT / "normalizer" / "normalize.py"
NORMALIZER_SCRIPT = _norm_cap if _norm_cap.exists() else _norm_legacy

@click.group()
def cli():
    """SafeFixK8s CLI — Detection → Normalization (LEAN K8s YAML only)"""
    pass

@cli.command()
@click.option("--path", "-p", default="tests", help="Path to scan (relative to repo root)")
@click.option("--tool", "-t", type=click.Choice(
    ["KubeConform","KubeLinter","Polaris","TrivyConfig","Kubescape","KubeScore","Yamllint","KubeAudit"]),
    help="Run only one detector")
def detect(path, tool):
    """Run detection tools on Kubernetes YAML manifests"""
    scan_path = (REPO_ROOT / path).resolve()
    if not scan_path.exists():
        console.print(f"[red]Error: Path not found:[/red] {scan_path}")
        sys.exit(1)

    if not DETECTORS_SCRIPT.exists():
        console.print(f"[red]Error: detectors.ps1 missing at {DETECTORS_SCRIPT}")
        sys.exit(1)

    if tool:
        ps_cmd = f'. "{DETECTORS_SCRIPT}"; Det-{tool} -Path "{scan_path}"'
    else:
        ps_cmd = f'. "{DETECTORS_SCRIPT}"; Det-RunLean -Path "{scan_path}"'

    console.print(f"[cyan]Executing detection on[/cyan] {scan_path}")
    try:
        rc = subprocess.call(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            cwd=str(DETECTION_DIR)
        )
        if rc != 0:
            console.print(f"[red]✗ Detection failed (exit {rc})[/red]"); sys.exit(rc)
        console.print("\n[green]✓ Detection completed[/green]")
        rel_det = DETECTION_DIR.relative_to(REPO_ROOT)
        console.print(f"[cyan]Raw results:[/cyan] {rel_det}\\output\\raw\\")
    except Exception as e:
        console.print(f"[red]Error running detection:[/red] {e}"); sys.exit(1)

@cli.command()
def normalize():
    """Normalize detection results into a unified LLM-ready payload"""
    if not NORMALIZER_SCRIPT.exists():
        console.print(f"[red]Error: normalizer not found at:[/red] {NORMALIZER_SCRIPT}")
        sys.exit(1)
    rc = subprocess.call([sys.executable, str(NORMALIZER_SCRIPT)], cwd=str(REPO_ROOT))
    if rc != 0:
        console.print(f"[red]✗ Normalization failed (exit {rc})[/red]"); sys.exit(rc)
    console.print("[green]✓ Normalization done[/green]")

@cli.command()
def status():
    """Show presence/size of RAW detector outputs (+ normalized bundle)"""
    raw_dir = DETECTION_DIR / "output" / "raw"
    if not raw_dir.exists():
        console.print("[yellow]No detection outputs found. Run 'detect' first.[/yellow]")
        return

    table = Table(title="Detection Output Files")
    table.add_column("Tool", style="cyan")
    table.add_column("File", style="white")
    table.add_column("Size", justify="right", style="green")
    table.add_column("Status", style="yellow")


    # List of all 13 tools and their output files
    all_tools = [
        ("Kubescape", "kubescape_raw.json"),
        ("KubeAudit", "kubeaudit_raw.json"),
        ("KubeConform", "kubeconform_raw.json"),
        ("KubeLinter", "kubelinter_raw.json"),
        ("KubeScore", "kubescore_raw.json"),
        ("Polaris", "polaris_raw.json"),
        ("Trivy", "trivy_config_raw.json"),
        ("Yamllint", "yamllint_raw.txt"),
        ("Checkov", "checkov_raw.json"),
        ("Conftest", "conftest_raw.json"),
        ("Pluto", "pluto_raw.json"),
        ("RBACPolice", "rbacpolice_raw.json"),
        ("Gitleaks", "gitleaks_raw.json"),
    ]

    for tool_name, filename in all_tools:
        filepath = raw_dir / filename
        if filepath.exists():
            # Count findings for JSON or TXT
            try:
                if filename.endswith(".json"):
                    import json
                    data = json.loads(filepath.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        finding_count = len(data)
                    elif isinstance(data, dict) and "results" in data:
                        finding_count = len(data["results"])
                    else:
                        finding_count = sum(
                            len(v) if isinstance(v, list) else 1 for v in data.values()
                        )
                elif filename.endswith(".txt"):
                    finding_count = sum(1 for line in filepath.read_text(encoding="utf-8").splitlines() if line.strip())
                else:
                    finding_count = "?"
            except Exception:
                finding_count = "?"
            size = filepath.stat().st_size
            size_str = f"{size:,} B" if size < 1024 else f"{size/1024:.1f} KB"
            status = f"✓ {finding_count} findings" if finding_count != "?" else "✓ OK"
            table.add_row(tool_name, filename, size_str, status)
        else:
            table.add_row(tool_name, filename, "-", "✗ Missing")
    console.print(table)

    normalized_file = REPO_ROOT / "output" / "normalized_findings.json"
    console.print(
        f"\n[green]✓[/green] Normalized: {normalized_file.stat().st_size:,} B"
        if normalized_file.exists()
        else "\n[yellow]⚠[/yellow] No normalized output yet."
    )

@cli.command()
@click.option("--path", "-p", default="tests", help="Path to scan")
def pipeline(path):
    """Lean pipeline: Detect -> Normalize"""
    click.echo("\n=== SafeFixK8s (LEAN) ===\n")
    ctx = click.Context(detect); ctx.invoke(detect, path=path, tool=None)
    ctx = click.Context(normalize); ctx.invoke(normalize)
    click.echo("\n✓ Pipeline Completed\n")

if __name__ == "__main__":
    cli()
