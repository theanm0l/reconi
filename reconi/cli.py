"""CLI interface using Typer and Rich."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .core.config import create_default_config, load_config, settings

app = typer.Typer(
    name="reconi",
    help="Automated reconnaissance & OSINT for web application security testing.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
):
    """Create a default reconi.yaml config file."""
    p = Path(path)
    if p.exists() and not force:
        console.print(f"[red]Config already exists at {path}. Use --force to overwrite.[/red]")
        raise typer.Exit(1)

    cfg = create_default_config(path)
    console.print(f"[green]Config created at {path}[/green]")
    console.print(f"[dim]Edit {path} to configure targets, modules, AI provider, and proxies.[/dim]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain to scan"),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m", help="Comma-separated module names to run (default: all enabled)"
    ),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """Run reconnaissance against a target domain."""
    cfg = load_config(config_path)
    console.print(f"[bold blue]Starting recon for: {target}[/bold blue]")

    all_modules = _get_enabled_modules(cfg)
    if modules:
        requested = set(m.strip() for m in modules.split(","))
        all_modules = [m for m in all_modules if m in requested]

    if not all_modules:
        console.print("[red]No modules enabled or matching filter.[/red]")
        raise typer.Exit(1)

    console.print(f"[dim]Modules to run ({len(all_modules)}): {', '.join(all_modules)}[/dim]")
    console.print("[yellow]Recon scan would execute here (workers to be implemented)[/yellow]")


@app.command()
def findings(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Filter by target domain"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max results"),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """List findings from previous scans."""
    table = Table(title="Reconi Findings")
    table.add_column("ID", style="dim")
    table.add_column("Source")
    table.add_column("Type")
    table.add_column("Value", max_width=60)
    table.add_column("Severity")
    table.add_column("Confidence")

    console.print("[yellow]Findings query will connect to DB (to be implemented)[/yellow]")
    console.print(table)


@app.command()
def report(
    target: Optional[str] = typer.Argument(None, help="Target domain to report on"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, csv, html"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """Generate a report from findings."""
    console.print(f"[bold blue]Generating {format} report for target: {target or 'all'}[/bold blue]")
    console.print("[yellow]Report generation to be implemented[/yellow]")


@app.command()
def validate(
    finding_id: Optional[str] = typer.Argument(None, help="Specific finding ID to validate"),
    all_findings: bool = typer.Option(False, "--all", "-a", help="Validate all unvalidated findings"),
):
    """Run live validation on findings."""
    if all_findings:
        console.print("[bold blue]Validating all unvalidated findings...[/bold blue]")
    elif finding_id:
        console.print(f"[bold blue]Validating finding: {finding_id}[/bold blue]")
    else:
        console.print("[red]Specify a finding ID or use --all.[/red]")
        raise typer.Exit(1)
    console.print("[yellow]Live validation to be implemented[/yellow]")


@app.command()
def status():
    """Show recon system status (workers, queue, DB)."""
    console.print("[bold]Reconi System Status[/bold]")

    table = Table(title="Status")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row("PostgreSQL", "[yellow]Not connected[/yellow]", settings.database_url)
    table.add_row("Redis", "[yellow]Not connected[/yellow]", settings.redis_url)
    table.add_row("Celery Workers", "[yellow]Not running[/yellow]", "0 active")
    table.add_row("AI Provider", "[green]Configured[/green]", settings.config.ai.provider)
    table.add_row("Proxy Pool", "[yellow]Not loaded[/yellow]", "0 proxies")

    console.print(table)


def _get_enabled_modules(cfg) -> list[str]:
    result = []
    for category, mods in cfg.modules.model_dump().items():
        for mod in mods:
            result.append(f"{category}/{mod}")
    return result


if __name__ == "__main__":
    app()
