"""Intelligence X — darknet and data-leak search module."""

import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class IntelxModule(ReconModule):
    name = "intelx"
    category = "leaks"
    description = "Search Intelligence X for data leaks and documents related to a domain"
    requires_api_key = True
    rate_limit_delay = 2.0

    def __init__(self) -> None:
        self.api_key = os.environ.get("INTELX_API_KEY", "")

    async def _search(self, client: httpx.AsyncClient, term: str) -> list[dict]:
        headers = {"x-key": self.api_key}
        url = "https://2.intelx.io/intelligent/search"
        params = {"term": term, "maxresults": 100}
        try:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            records = data.get("records", [])
            results = []
            for rec in records:
                sid = rec.get("systemid") or rec.get("sid", "")
                if sid:
                    results.append({"sid": sid, "name": rec.get("name", ""),
                                    "date": rec.get("date", ""), "bucket": rec.get("bucket", ""),
                                    "media": rec.get("media", ""), "storageid": rec.get("storageid", "")})
            return results
        except Exception:
            return []

    async def _fetch_preview(self, client: httpx.AsyncClient, sid: str) -> str:
        headers = {"x-key": self.api_key}
        url = f"https://2.intelx.io/intelligent/file/view?sid={sid}"
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.text[:5000]
        except Exception:
            return ""

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        if not self.api_key:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="INTELX_API_KEY not set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        searches = [
            domain,
            f"{domain} password",
            f"{domain} secret",
        ]

        seen_sids: set[str] = set()

        async with httpx.AsyncClient(timeout=httpx.Timeout(90)) as client:
            for term in searches:
                results = await self._search(client, term)
                for result in results:
                    sid = result["sid"]
                    if sid in seen_sids:
                        continue
                    seen_sids.add(sid)

                    context = self._classify_result(result.get("name", ""), result.get("bucket", ""))

                    name = result.get("name", "")
                    value = f"IntelX:{sid}:{name}" if name else f"IntelX:{sid}"

                    findings.append(Finding(
                        source=self.name,
                        type="intelx_result",
                        value=value,
                        context=context,
                        url_found_on=f"https://2.intelx.io/intelligent/search?term={term}",
                        severity="medium",
                        confidence=0.7,
                        raw=result,
                    ))

                    content = await self._fetch_preview(client, sid)
                    if content:
                        extracted = self._extract_sensitive(content)
                        for snippet in extracted:
                            findings.append(Finding(
                                source=self.name,
                                type="intelx_result",
                                value=snippet[:200],
                                context=f"Matched content from {name}",
                                url_found_on=f"https://2.intelx.io/intelligent/file/view?sid={sid}",
                                severity="high",
                                confidence=0.75,
                                raw={"sid": sid, "matched": snippet[:500]},
                            ))

                await asyncio.sleep(self.rate_limit_delay)

        return findings

    def _classify_result(self, name: str, bucket: str) -> str:
        name_lower = (name + bucket).lower()
        if any(k in name_lower for k in ["password", "credential", "secret"]):
            return "Potential credential leak"
        if any(k in name_lower for k in ["config", ".env", ".yml", ".json", ".ini"]):
            return "Configuration file"
        if any(k in name_lower for k in [".py", ".js", ".go", ".java", ".php", "source"]):
            return "Source code"
        if any(k in name_lower for k in [".pdf", ".doc", ".xls", ".csv", "document"]):
            return "Document"
        if any(k in name_lower for k in [".db", ".sql", "dump"]):
            return "Database dump"
        return f"IntelX result (bucket: {bucket})"

    def _extract_sensitive(self, content: str) -> list[str]:
        snippets: list[str] = []
        patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "email"),
            (r'(?:password|passwd|pwd)[\s:=]+["\']?([^\s"\']{4,})', "password"),
            (r'(?:api[_-]?key|apikey|api_secret)[\s:=]+["\']?([^\s"\']{8,})', "api_key"),
        ]
        for pattern, label in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                snippets.append(f"[{label}] {match.group(0)}")
        return snippets[:20]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="leaks.intelx")
def run_intelx_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = IntelxModule()
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
