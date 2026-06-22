"""CLI interface using Typer and Rich — fully wired."""

import asyncio
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core.config import create_default_config, load_config, settings
from .core.database import SessionLocal, init_db, Target, ReconJob, Finding as DBFinding
from .core.executor import run_scan

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

    create_default_config(path)
    console.print(f"[green]Config created at {path}[/green]")
    console.print(f"[dim]Edit {path} to configure targets, modules, AI provider, and proxies.[/dim]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain to scan (e.g., example.com)"),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m", help="Comma-separated module names (e.g., wayback,gau,google)"
    ),
    concurrency: int = typer.Option(5, "--concurrency", "-j", help="Max parallel modules"),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """Run reconnaissance against a target domain."""
    cfg = load_config(config_path)
    console.print(f"[bold blue]Starting recon for:[/bold blue] {target}")
    console.print(f"[dim]Modules: {'all enabled' if not modules else modules}[/dim]")
    console.print(f"[dim]Concurrency: {concurrency}[/dim]")
    console.print()

    start_time = datetime.now(timezone.utc)
    run_scan(target, module_filter=modules, config_path=config_path, max_concurrency=concurrency)
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    console.print(f"[dim]Time: {elapsed:.1f}s[/dim]")


@app.command()
def findings(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Filter by target domain"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: critical, high, medium, low, info"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max results"),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """List findings from previous scans."""
    init_db()
    db = SessionLocal()

    try:
        query = db.query(DBFinding)

        if target:
            tgt = db.query(Target).filter(Target.domain == target).first()
            if tgt:
                query = query.filter(DBFinding.target_id == tgt.id)
            else:
                console.print(f"[yellow]No scans found for target: {target}[/yellow]")
                return

        if severity:
            query = query.filter(DBFinding.severity == severity)

        query = query.order_by(DBFinding.confidence.desc()).limit(limit)
        results = query.all()

        if not results:
            console.print("[yellow]No findings found.[/yellow]")
            return

        table = Table(
            title=f"Findings ({len(results)} results)",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Source", style="cyan", no_wrap=True)
        table.add_column("Type", style="dim")
        table.add_column("Value", max_width=50)
        table.add_column("Severity")
        table.add_column("Conf", justify="right")
        table.add_column("Validated")

        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "info": "dim",
        }

        for f in results:
            sev_color = severity_colors.get(f.severity, "white")
            sev_text = f"[{sev_color}]{f.severity}[/{sev_color}]"

            val_icon = "✓" if f.is_validated else ""
            conf_text = f"{f.confidence:.0f}%" if f.confidence else "-"

            table.add_row(
                f.source,
                f.type,
                str(f.value)[:50],
                sev_text,
                conf_text,
                val_icon,
            )

        console.print(table)

        critical = sum(1 for f in results if f.severity == "critical")
        high = sum(1 for f in results if f.severity == "high")
        if critical or high:
            console.print(f"[bold red]{critical} critical[/bold red] | [bold orange1]{high} high[/bold orange1]")

    finally:
        db.close()


@app.command()
def report(
    target: Optional[str] = typer.Argument(None, help="Target domain to report on"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, csv, html"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    limit: int = typer.Option(1000, "--limit", "-l", help="Max findings in report"),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """Generate a report from findings."""
    init_db()
    db = SessionLocal()

    try:
        query = db.query(DBFinding)

        if target:
            tgt = db.query(Target).filter(Target.domain == target).first()
            if tgt:
                query = query.filter(DBFinding.target_id == tgt.id)

        query = query.order_by(DBFinding.confidence.desc()).limit(limit)
        results = query.all()

        if not results:
            console.print("[yellow]No findings to report.[/yellow]")
            return

        data = []
        for f in results:
            data.append({
                "id": f.id,
                "source": f.source,
                "type": f.type,
                "value": f.value,
                "context": f.context,
                "url_found_on": f.url_found_on,
                "confidence": f.confidence,
                "severity": f.severity,
                "is_validated": f.is_validated,
                "cwe_id": f.cwe_id,
                "ai_summary": f.ai_summary,
                "raw_json": f.raw_json,
                "created_at": f.created_at.isoformat() if f.created_at else "",
            })

        if format == "json":
            content = json.dumps(data, indent=2, default=str)
            default_name = f"reconi_{target or 'all'}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

        elif format == "csv":
            import io
            buf = io.StringIO()
            if data:
                writer = csv.DictWriter(buf, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            content = buf.getvalue()
            default_name = f"reconi_{target or 'all'}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

        elif format == "html":
            content = _generate_html_report(data, target)
            default_name = f"reconi_{target or 'all'}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"

        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            return

        out_path = Path(output or default_name)
        out_path.write_text(content, encoding="utf-8")
        console.print(f"[green]Report written: {out_path}[/green] ({len(data)} findings, {format})")

    finally:
        db.close()


def _generate_html_report(data: list[dict], target: Optional[str]) -> str:
    rows = ""
    sev_style = {"critical": "background:#dc3545;color:white", "high": "background:#fd7e14;color:white",
                  "medium": "background:#ffc107;color:black", "low": "background:#28a745;color:white",
                  "info": "background:#6c757d;color:white"}

    for f in data:
        sev = sev_style.get(f["severity"], "")
        val = "✓" if f["is_validated"] else ""
        rows += f"""
        <tr>
            <td>{f['source']}</td>
            <td>{f['type']}</td>
            <td style="max-width:300px;word-break:break-all">{f['value'][:100]}</td>
            <td><span style="padding:2px 8px;border-radius:4px;{sev}">{f['severity']}</span></td>
            <td>{f['confidence']:.0f}%</td>
            <td>{val}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Reconi Report — {target or 'All'}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:20px;background:#0d1117;color:#c9d1d9}}
h1{{color:#58a6ff}} table{{border-collapse:collapse;width:100%;margin-top:16px}}
th{{background:#161b22;padding:10px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:8px;border-bottom:1px solid #21262d}}
tr:hover{{background:#161b22}}
.summary{{margin:16px 0;padding:12px;background:#161b22;border-radius:8px;border:1px solid #30363d}}
</style></head><body>
<h1>Reconi Report</h1>
<div class="summary"><strong>Target:</strong> {target or 'All'} | <strong>Findings:</strong> {len(data)} | <strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</div>
<table><thead><tr><th>Source</th><th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Validated</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""


@app.command()
def status():
    """Show recon system status."""
    console.print("[bold]Reconi System Status[/bold]")
    console.print()

    table = Table(title="Components")
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    db_ok = False
    try:
        init_db()
        db = SessionLocal()
        db.execute(db.query(Target).exists().select())
        db.close()
        db_ok = True
    except Exception:
        pass

    table.add_row(
        "Database",
        "[green]Connected[/green]" if db_ok else "[red]Not connected[/red]",
        settings.database_url,
    )

    redis_ok = False
    try:
        from .core.cache import redis_client
        redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    table.add_row(
        "Redis",
        "[green]Connected[/green]" if redis_ok else "[yellow]Not available[/yellow]",
        settings.redis_url,
    )

    ai_label = settings.config.ai.provider
    table.add_row(
        "AI Provider",
        "[green]Configured[/green]" if ai_label else "[dim]Not configured[/dim]",
        f"{ai_label} / triage: {settings.config.ai.triage_model} / analysis: {settings.config.ai.analysis_model}",
    )

    try:
        from .core.executor import _get_module_registry
        registry = _get_module_registry()
        mod_count = len(registry)
        table.add_row("Total Modules", f"[green]{mod_count}[/green]", "")
    except Exception:
        mod_count = 0
        table.add_row("Total Modules", "[yellow]Not loaded[/yellow]", "")

    try:
        db = SessionLocal()
        scan_count = db.query(Target).count()
        finding_count = db.query(DBFinding).count()
        db.close()
        table.add_row("Targets Scanned", str(scan_count), "")
        table.add_row("Total Findings", str(finding_count), "")
    except Exception:
        table.add_row("Targets Scanned", "-", "")
        table.add_row("Total Findings", "-", "")

    console.print(table)


@app.command()
def validate(
    finding_id: Optional[str] = typer.Argument(None, help="Specific finding ID to validate"),
    all_findings: bool = typer.Option(False, "--all", "-a", help="Validate all unvalidated findings"),
    config_path: str = typer.Option("reconi.yaml", "--config", "-c", help="Config file path"),
):
    """Run live validation on findings (test if API keys / endpoints are active)."""
    if not finding_id and not all_findings:
        console.print("[red]Specify a finding ID or use --all.[/red]")
        raise typer.Exit(1)

    init_db()
    db = SessionLocal()

    try:
        if finding_id:
            finding = db.query(DBFinding).filter(DBFinding.id == finding_id).first()
            if not finding:
                console.print(f"[red]Finding not found: {finding_id}[/red]")
                return
            findings = [finding]
        else:
            findings = db.query(DBFinding).filter(
                DBFinding.is_validated == False,
                DBFinding.type.in_(["api_key", "secret", "endpoint", "url"]),
            ).limit(50).all()

        if not findings:
            console.print("[yellow]No unvalidated findings to test.[/yellow]")
            return

        console.print(f"[bold blue]Validating {len(findings)} findings...[/bold blue]")
        console.print()

        validated = 0
        for f in findings:
            try:
                result = _validate_finding_sync(f)
                if result:
                    f.is_validated = True
                    detail = result.get("detail", "")
                    conf_boost = result.get("confidence_boost", 0)
                    f.confidence = min(100, f.confidence + conf_boost * 100)

                    from .core.database import ValidationResult as VR
                    db.add(VR(
                        finding_id=f.id,
                        validator="live",
                        result="valid" if result.get("is_valid") else "invalid",
                        detail=detail,
                    ))

                    icon = "✓" if result.get("is_valid") else "✗"
                    color = "green" if result.get("is_valid") else "red"
                    console.print(f"  [{color}]{icon}[/{color}] {f.source}/{f.type}: {str(f.value)[:60]}")
                    validated += 1
            except Exception as e:
                console.print(f"  [red]Error[/red] {f.id[:8]}: {str(e)[:50]}")

        db.commit()
        console.print()
        console.print(f"[green]Validated {validated}/{len(findings)} findings[/green]")

    finally:
        db.close()


def _validate_finding_sync(finding) -> dict | None:
    import httpx

    value = str(finding.value).strip()
    ftype = finding.type

    try:
        if ftype in ("api_key", "secret"):
            if value.startswith("ghp_") or value.startswith("github_pat_"):
                resp = httpx.get("https://api.github.com/user", headers={
                    "Authorization": f"Bearer {value}",
                    "Accept": "application/vnd.github+json",
                }, timeout=10)
                return {"is_valid": resp.status_code == 200, "detail": f"GitHub: {resp.status_code}", "confidence_boost": 0.3}

            if value.startswith("sk_live_"):
                resp = httpx.get("https://api.stripe.com/v1/charges", auth=(value, ""), timeout=10)
                return {"is_valid": resp.status_code in (200, 401), "detail": f"Stripe: {resp.status_code}", "confidence_boost": 0.3}

            if value.startswith("sk-") and len(value) > 50:
                resp = httpx.get("https://api.openai.com/v1/models", headers={
                    "Authorization": f"Bearer {value}",
                }, timeout=10)
                return {"is_valid": resp.status_code == 200, "detail": f"OpenAI: {resp.status_code}", "confidence_boost": 0.3}

        if ftype in ("endpoint", "url"):
            if value.startswith("http"):
                resp = httpx.head(value, timeout=10)
                is_live = resp.status_code < 500
                return {"is_valid": is_live, "detail": f"HTTP {resp.status_code}", "confidence_boost": 0.15}

    except Exception:
        pass

    return None


if __name__ == "__main__":
    app()
