"""Searchcode API — search public source code for domain mentions."""
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


class SearchcodeModule(ReconModule):
    name = "searchcode"
    category = "code_mining"
    description = "Search searchcode.com API for source code files referencing a domain"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        search_url = f"https://searchcode.com/api/codesearch_I/?q={domain}&per_page=100"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(45)) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()

            results = data.get("results") if isinstance(data, dict) else (data if isinstance(data, list) else [])

            if isinstance(results, list):
                for result in results[:50]:
                    await asyncio.sleep(0.5)

                    repo = result.get("repo", "") if isinstance(result, dict) else ""
                    filename = result.get("filename", "") if isinstance(result, dict) else ""
                    file_url = result.get("url", "") if isinstance(result, dict) else ""
                    lines = result.get("lines", result.get("highlight", {})) if isinstance(result, dict) else {}

                    context_lines = ""
                    if isinstance(lines, dict):
                        context_parts = []
                        for key, val in lines.items():
                            context_parts.append(f"L{key}: {val}")
                        context_lines = " | ".join(context_parts[:5])

                    findings.append(Finding(
                        source=self.name,
                        type="code",
                        value=file_url or f"{repo}/{filename}" if repo and filename else "",
                        context=context_lines[:500] if context_lines else f"{repo}/{filename}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.6,
                        raw={
                            "repo": repo,
                            "filename": filename,
                            "language": result.get("language", "") if isinstance(result, dict) else "",
                        },
                    ))

            if isinstance(data, dict):
                pagination = data.get("page", data.get("nextpage", {}))
                total = data.get("total", data.get("match_count", 0))
                if total and int(total) > 100:
                    page_count = min(int(total) // 100 + 1, 5)
                    for page in range(1, page_count):
                        await asyncio.sleep(0.5)
                        try:
                            async with httpx.AsyncClient(timeout=httpx.Timeout(45)) as client:
                                page_resp = await client.get(f"{search_url}&p={page}")
                                page_resp.raise_for_status()
                                page_data = page_resp.json()

                            page_results = page_data.get("results") if isinstance(page_data, dict) else (page_data if isinstance(page_data, list) else [])
                            if isinstance(page_results, list):
                                for result in page_results[:20]:
                                    repo = result.get("repo", "")
                                    filename = result.get("filename", "")
                                    file_url = result.get("url", "")
                                    findings.append(Finding(
                                        source=self.name,
                                        type="code",
                                        value=file_url or f"{repo}/{filename}" if repo and filename else "",
                                        context=f"{repo}/{filename}",
                                        url_found_on=search_url,
                                        severity="info",
                                        confidence=0.5,
                                        raw={"repo": repo, "filename": filename},
                                    ))
                        except Exception:
                            continue

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.searchcode")
def run_searchcode_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = SearchcodeModule()
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
