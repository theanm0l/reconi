"""Direct module executor — runs recon modules without Celery."""

import asyncio
import importlib
import json
import os
import pkgutil
import time
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

from .config import AppConfig, load_config
from .database import SessionLocal, init_db, Target, ReconJob, Finding as DBFinding
from .plugin import Finding, ReconModule

console = Console()

MODULE_CATEGORIES = [
    "url_discovery", "dorking", "code_mining", "api_discovery",
    "js_analysis", "dns_infra", "leaks", "osint",
]


def _discover_modules() -> dict[str, type[ReconModule]]:
    registry: dict[str, type[ReconModule]] = {}
    base_path = os.path.dirname(os.path.dirname(__file__))

    if not os.path.isdir(os.path.join(base_path, "workers")):
        base_path = os.path.dirname(base_path)

    for category in MODULE_CATEGORIES:
        category_path = os.path.join(base_path, "workers", category)
        if not os.path.isdir(category_path):
            continue

        for _, module_name, _ in pkgutil.iter_modules([category_path]):
            if module_name.startswith("_"):
                continue
            try:
                mod = importlib.import_module(f"reconi.workers.{category}.{module_name}")
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ReconModule)
                        and attr is not ReconModule
                        and hasattr(attr, "name")
                        and attr.name
                    ):
                        key = f"{category}/{attr.name}"
                        registry[key] = attr
            except ImportError as e:
                pass
            except Exception:
                continue

    return registry


def _get_module_registry() -> dict[str, type[ReconModule]]:
    return _discover_modules()


def _resolve_modules(config: AppConfig, module_filter: Optional[str] = None) -> list[tuple[str, str, type[ReconModule]]]:
    registry = _get_module_registry()
    result: list[tuple[str, str, type[ReconModule]]] = []

    if module_filter:
        requested = set(m.strip() for m in module_filter.split(","))
        for key, cls in registry.items():
            cat, name = key.split("/", 1)
            if key in requested or name in requested:
                result.append((cat, name, cls))
        return result

    enabled = config.modules.model_dump()
    for category, mod_names in enabled.items():
        if category not in MODULE_CATEGORIES:
            continue
        for mod_name in mod_names:
            key = f"{category}/{mod_name}"
            if key in registry:
                result.append((category, mod_name, registry[key]))

    return result


async def _run_one_module(
    module_cls: type[ReconModule],
    target: str,
    job_id: str,
    target_id: str,
    progress: Progress,
    task_id: int,
) -> list[Finding]:
    module = module_cls()
    label = f"{module.category}/{module.name}"
    progress.update(task_id, description=f"[cyan]{label}[/cyan]")

    try:
        findings = await module.run(target)
        progress.update(task_id, description=f"[green]{label}[/green]", completed=True)
    except Exception as e:
        progress.update(
            task_id,
            description=f"[red]{label} (failed: {str(e)[:50]})[/red]",
            completed=True,
        )
        return [Finding(
            source=module.name,
            type="error",
            value=str(e),
            severity="info",
            confidence=0.0,
        )]

    if not findings:
        progress.update(task_id, description=f"[dim]{label} (0 findings)[/dim]", completed=True)
        return []

    db = SessionLocal()
    try:
        for f in findings:
            db_finding = DBFinding(
                target_id=target_id,
                job_id=job_id,
                source=f.source,
                type=f.type,
                value=f.value,
                context=f.context,
                url_found_on=f.url_found_on,
                confidence=f.confidence,
                severity=f.severity,
                raw_json=json.dumps(f.raw) if f.raw else None,
            )
            db.add(db_finding)

        job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if job:
            job.items_found = len(findings)
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        db.rollback()
        findings.append(Finding(
            source=module.name,
            type="db_error",
            value=str(e),
            severity="info",
            confidence=0.0,
        ))
    finally:
        db.close()

    count_text = f"({len(findings)})" if findings else "(0)"
    progress.update(
        task_id,
        description=f"[green]{label}[/green] [bold]{count_text}[/bold]",
        completed=True,
    )
    return findings


def run_scan(
    target: str,
    module_filter: Optional[str] = None,
    config_path: str = "reconi.yaml",
    parallel: bool = True,
    max_concurrency: int = 5,
):
    config = load_config(config_path)
    init_db()

    modules = _resolve_modules(config, module_filter)

    if not modules:
        console.print("[red]No modules found matching filter.[/red]")
        return

    db = SessionLocal()
    try:
        target_record = db.query(Target).filter(Target.domain == target).first()
        if not target_record:
            target_record = Target(id=str(uuid4()), domain=target, status="scanning")
            db.add(target_record)
            db.commit()
            db.refresh(target_record)
        else:
            target_record.status = "scanning"
            db.commit()

        job_ids: list[str] = []
        display_names: list[str] = []
        for cat, name, _ in modules:
            job = ReconJob(
                id=str(uuid4()),
                target_id=target_record.id,
                module_name=name,
                category=cat,
                status="queued",
            )
            db.add(job)
            job_ids.append(job.id)
            display_names.append(f"{cat}/{name}")
        db.commit()
    finally:
        db.close()

    console.print()
    console.print(f"[bold blue]  Recon: [white]{target}[/white][/bold blue]")
    console.print(f"[dim]  Modules: {len(modules)} | Mode: {'parallel' if parallel else 'sequential'}[/dim]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        all_tasks = [
            progress.add_task("", total=1, start=False)
            for _ in modules
        ]

        async def _run_all():
            results: list[list[Finding]] = []
            sem = asyncio.Semaphore(max_concurrency)

            async def _run_one(i: int):
                cat, name, cls = modules[i]
                job_id = job_ids[i]
                task_id = all_tasks[i]
                progress.start_task(task_id)

                async with sem:
                    findings = await _run_one_module(
                        cls, target, job_id, target_record.id, progress, task_id
                    )
                return findings

            if parallel:
                coros = [_run_one(i) for i in range(len(modules))]
                results = await asyncio.gather(*coros, return_exceptions=True)
            else:
                for i in range(len(modules)):
                    r = await _run_one(i)
                    results.append(r)

            return results

        all_findings = asyncio.run(_run_all())

    total_findings = sum(
        len(f) if isinstance(f, list) else 0
        for f in (all_findings if isinstance(all_findings, list) else [all_findings])
    )

    console.print()
    console.print(f"[bold green]  Scan complete: {total_findings} findings across {len(modules)} modules[/bold green]")
    console.print(f"[dim]  Run 'reconi findings -t {target}' to view results[/dim]")

    return all_findings
