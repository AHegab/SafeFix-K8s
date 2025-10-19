import click
from rich.console import Console
from detector.kubeaudit_runner import run_kubeaudit


console = Console()

@click.group()
def cli():
    """SafeFixK8s CLI — Detection → Repair → Validation → Proof → PR"""
    pass

@cli.command()
@click.argument("path")
def detect(path):
    """Run detection tools on Kubernetes YAML manifests"""
    console.print(f"[yellow]Running detection on:[/yellow] {path}")
    run_kubeaudit(path, "output")


@cli.command()
def repair():
    """Generate RFC6902 patch from findings"""
    console.print("[cyan]Repair Engine not implemented yet[/cyan]")

@cli.command()
def validate_pipeline():
    """Run validation gates"""
    console.print("[cyan]Validation pipeline not implemented yet[/cyan]")

@cli.command()
def proof():
    """Bundle safe_fix_proof.json"""
    console.print("[cyan]Proof generation not implemented yet[/cyan]")

if __name__ == "__main__":
    cli()
