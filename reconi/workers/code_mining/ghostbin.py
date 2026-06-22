"""Ghostbin scraping — search ghostbin.com for domain mentions."""
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


class GhostbinModule(ReconModule):
    name = "ghostbin"
    category = "code_mining"
    description = "Scrape ghostbin.com search results for domain mentions"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        search_url = f"https://ghostbin.com/search?q={domain}"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                text = resp.text

            paste_paths = re.findall(r'href="(/paste/[^"]+)"', text)
            seen = set()
            for path in paste_paths[:30]:
                if path in seen:
                    continue
                seen.add(path)

                await asyncio.sleep(0.5)
                try:
                    async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                        paste_resp = await client.get(f"https://ghostbin.com{path}")
                        paste_text = paste_resp.text
                except Exception:
                    findings.append(Finding(
                        source=self.name,
                        type="paste",
                        value=f"https://ghostbin.com{path}",
                        context=f"Ghostbin paste matching {domain}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.5,
                    ))
                    continue

                context_snippet = paste_text[:300] if paste_text else ""
                findings.append(Finding(
                    source=self.name,
                    type="paste",
                    value=f"https://ghostbin.com{path}",
                    context=context_snippet,
                    url_found_on=search_url,
                    severity="info",
                    confidence=0.5,
                ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        if not findings:
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                    alt_url = "https://ghostbin.com/recent"
                    resp = await client.get(alt_url)
                    resp.raise_for_status()
                    text = resp.text

                paste_paths = re.findall(r'href="(/paste/[^"]+)"', text)
                for path in paste_paths[:30]:
                    findings.append(Finding(
                        source=self.name,
                        type="paste",
                        value=f"https://ghostbin.com{path}",
                        context="Recent ghostbin paste",
                        url_found_on=alt_url,
                        severity="info",
                        confidence=0.3,
                    ))

            except Exception:
                pass

        return findings


@celery_app.task(name="code_mining.ghostbin")
def run_ghostbin_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GhostbinModule()
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
