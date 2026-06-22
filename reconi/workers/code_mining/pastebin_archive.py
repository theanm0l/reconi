"""Pastebin archive scraping — psbdmp, pastebin archive, Ubuntu snippets."""
import asyncio
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


class PastebinArchiveModule(ReconModule):
    name = "pastebin_archive"
    category = "code_mining"
    description = "Search paste archives (psbdmp.ws, pastebin.com/archive, Ubuntu snippets) for domain mentions"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                search_url = f"https://psbdmp.ws/api/v3/search?q={domain}"
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()
                paste_ids = data if isinstance(data, list) else data.get("data", data.get("results", []))

            if isinstance(paste_ids, list):
                for entry in paste_ids[:50]:
                    await asyncio.sleep(0.5)
                    pid = entry if isinstance(entry, str) else entry.get("id", "")
                    if pid:
                        findings.append(Finding(
                            source=self.name,
                            type="paste",
                            value=f"https://psbdmp.ws/{pid}",
                            context=f"psbdmp paste matching {domain}",
                            url_found_on=search_url,
                            severity="info",
                            confidence=0.5,
                            raw={"paste_id": pid},
                        ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=f"psbdmp: {e}", severity="info", confidence=0.0))

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                archive_url = "https://pastebin.com/archive"
                resp = await client.get(archive_url)
                resp.raise_for_status()
                text = resp.text

            import re as _re
            paste_links = _re.findall(r'href="/([A-Za-z0-9]{8,})"', text)
            for pid in paste_links[:30]:
                paste_url = f"https://pastebin.com/{pid}"
                findings.append(Finding(
                    source=self.name,
                    type="paste",
                    value=paste_url,
                    context="Recent pastebin archive entry",
                    url_found_on=archive_url,
                    severity="info",
                    confidence=0.3,
                    raw={"paste_id": pid},
                ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=f"pastebin_archive: {e}", severity="info", confidence=0.0))

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                snippets_url = f"https://snippets.ubuntu.com/search?q={domain}"
                resp = await client.get(snippets_url)
                resp.raise_for_status()
                text = resp.text

            import re as _re
            snippet_links = _re.findall(r'href="(/[^"]+)"', text)
            for link in snippet_links[:30]:
                if link.startswith("/") and len(link) > 1:
                    findings.append(Finding(
                        source=self.name,
                        type="paste",
                        value=f"https://snippets.ubuntu.com{link}",
                        context=f"Ubuntu snippet matching {domain}",
                        url_found_on=snippets_url,
                        severity="info",
                        confidence=0.4,
                    ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=f"ubuntu_snippets: {e}", severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.pastebin_archive")
def run_pastebin_archive_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = PastebinArchiveModule()
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
