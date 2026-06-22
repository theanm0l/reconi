"""Giters scraping — search giters.com for repositories and users."""
import asyncio
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


class GitersModule(ReconModule):
    name = "giters"
    category = "code_mining"
    description = "Scrape giters.com for repositories and user profiles mentioning a domain"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        search_url = f"https://www.giters.com/search?q={domain}"

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            ) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                text = resp.text

            repo_patterns = [
                re.compile(r'https?://www\.giters\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)'),
                re.compile(r'href="/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"'),
            ]

            seen = set()
            for pattern in repo_patterns:
                for match in pattern.finditer(text):
                    repo_path = match.group(1)
                    if repo_path in seen or "/" not in repo_path:
                        continue
                    seen.add(repo_path)
                    findings.append(Finding(
                        source=self.name,
                        type="repo",
                        value=f"https://www.giters.com/{repo_path}",
                        context=f"Giters repo/user matching {domain}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.5,
                    ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        if not findings:
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(30),
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                ) as client:
                    alt_url = f"https://www.giters.com/search?q={domain}&type=repositories"
                    resp = await client.get(alt_url)
                    resp.raise_for_status()
                    text = resp.text

                user_pattern = re.compile(r'href="/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"')
                seen = set()
                for match in user_pattern.finditer(text):
                    repo_path = match.group(1)
                    if repo_path in seen or "/" not in repo_path:
                        continue
                    seen.add(repo_path)
                    findings.append(Finding(
                        source=self.name,
                        type="repo",
                        value=f"https://www.giters.com/{repo_path}",
                        context=f"Giters repository matching {domain}",
                        url_found_on=alt_url,
                        severity="info",
                        confidence=0.5,
                    ))

            except Exception:
                pass

        return findings


@celery_app.task(name="code_mining.giters")
def run_giters_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GitersModule()
            results = await module.run(target)

            for f in results:
                db_finding = DBFinding(
                    target_id=job.target_id if job else "",
                    job_id=job_id,
                    source=f.source,
                    type=f.type,
                    value=f.value,
                    context=f.context,
                    url_found_on=f.url_found_on,
                    confidence=f.confidence,
                    severity=f.severity,
                    raw_json=f.raw,
                )
                db.add(db_finding)

            if job:
                job.status = "completed"
                job.items_found = len(results)
                db.commit()
        except Exception as e:
            if job:
                job.status = "failed"
                job.error_message = str(e)
                db.commit()
        finally:
            db.close()

    asyncio.run(_run())
