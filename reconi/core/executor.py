"""Direct module executor — runs recon modules without Celery, with clear line-by-line output."""

import asyncio
import importlib
import json
import os
import pkgutil
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from rich.console import Console
from rich.panel import Panel

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

    for category in MODULE_CATEGORIES:
        try:
            pkg = importlib.import_module(f"reconi.workers.{category}")
            pkg_path = os.path.dirname(pkg.__file__) if pkg.__file__ else ""
        except ImportError:
            continue

        if not pkg_path or not os.path.isdir(pkg_path):
            continue

        for _, module_name, _ in pkgutil.iter_modules([pkg_path]):
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
            except Exception:
                pass

    return registry


def _resolve_modules(config: AppConfig, module_filter: Optional[str] = None) -> list[tuple[str, str, type[ReconModule]]]:
    registry = _discover_modules()
    result: list[tuple[str, str, type[ReconModule]]] = []

    if module_filter:
        requested = set(m.strip() for m in module_filter.split(","))
        for key, cls in registry.items():
            cat, name = key.split("/", 1)
            if key in requested or name in requested or (f"{name}" in requested):
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


async def _run_one_module_async(
    module_cls: type[ReconModule],
    target: str,
    job_id: str,
    target_id: str,
) -> tuple[str, int, list[str]]:
    module = module_cls()
    label = f"{module.category}/{module.name}"
    errors: list[str] = []

    try:
        findings = await module.run(target)
    except Exception as e:
        tb = traceback.format_exc()
        errors.append(f"{label}: {e}")
        if "--debug" in sys.argv:
            console.print(f"[red]  {label}: {e}[/red]")
            console.print(f"[dim]{tb[-500:]}[/dim]")
        return label, 0, errors

    if not findings:
        return label, 0, []

    non_error = [f for f in findings if f.type != "error"]
    error_findings = [f for f in findings if f.type == "error"]
    for ef in error_findings:
        errors.append(f"{label}: {ef.value[:80]}")

    db = SessionLocal()
    try:
        for f in non_error:
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

        for f in error_findings:
            db_finding = DBFinding(
                target_id=target_id,
                job_id=job_id,
                source=f.source,
                type="error",
                value=f.value,
                context=f.context,
                severity="info",
                confidence=0.0,
                raw_json=json.dumps(f.raw) if f.raw else None,
            )
            db.add(db_finding)

        job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if job:
            job.items_found = len(non_error)
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        db.rollback()
        errors.append(f"{label}: DB error: {e}")
    finally:
        db.close()

    return label, len(non_error), errors


def run_scan(
    target: str,
    module_filter: Optional[str] = None,
    config_path: str = "reconi.yaml",
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
        db.commit()
    finally:
        db.close()

    console.print()
    console.print(f"[bold blue]  Recon: [white]{target}[/white][/bold blue]")
    console.print(f"[dim]  Modules: {len(modules)} | Concurrency: {max_concurrency}[/dim]")
    console.print()

    sem = asyncio.Semaphore(max_concurrency)
    total_findings = 0
    completed = 0
    total_errors: list[str] = []
    t0 = time.monotonic()

    async def _run_one(i: int):
        nonlocal total_findings, completed
        cat, name, cls = modules[i]
        job_id = job_ids[i]
        label = f"{cat}/{name}"

        async with sem:
            lbl, count, errs = await _run_one_module_async(
                cls, target, job_id, target_record.id
            )
            total_findings += count
            completed += 1
            total_errors.extend(errs)

            icon = "[green]✓[/green]" if count > 0 else "[dim]-[/dim]"
            if errs:
                icon = "[yellow]![/yellow]"
            eta = ""
            if completed > 0:
                rate = (time.monotonic() - t0) / completed
                remaining = (len(modules) - completed) * rate
                eta = f" [dim](ETA: {remaining:.0f}s)[/dim]"
            console.print(f"  {icon} {label:<40} [dim]{count:>4} findings[/dim]{eta}")

    async def _run_all():
        tasks = [_run_one(i) for i in range(len(modules))]
        await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(_run_all())

    elapsed = time.monotonic() - t0
    console.print()
    console.print(f"[bold green]  Scan complete: {total_findings} findings | {elapsed:.1f}s[/bold green]")

    if total_errors:
        console.print(f"[yellow]  {len(total_errors)} errors (use --debug for details)[/yellow]")

    console.print(f"[dim]  Run 'reconi findings -t {target}' to view results[/dim]")

    return total_findings
