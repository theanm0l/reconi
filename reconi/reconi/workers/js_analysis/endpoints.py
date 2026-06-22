"""JS-based API endpoint discovery from JavaScript files via Wayback/Gau."""
import asyncio
import json
import random
import re
from urllib.parse import urljoin, urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

ENDPOINT_PATTERNS = [
    r"""["']/(?:api|v[0-9]+|graphql|internal|admin|login|signup|auth|oauth|callback|webhook|payment|billing|stripe)[^"'\s]*["']""",
    r"""fetch\s*\(\s*["'][^"']+["']""",
    r"""axios\.[a-z]+\(\s*["']([^"']+)["']""",
    r"""\.get\(\s*["']([^"']+)["']""",
    r"""\.post\(\s*["']([^"']+)["']""",
    r"""\.put\(\s*["']([^"']+)["']""",
    r"""\.delete\(\s*["']([^"']+)["']""",
    r"""baseURL\s*:\s*["']([^"']+)["']""",
    r"""API_URL\s*=\s*["']([^"']+)["']""",
    r"""REACT_APP_\w+URL\s*=\s*["']([^"']+)["']""",
]

JS_EXTENSIONS = {".js", ".mjs", ".cjs"}


class EndpointsModule(ReconModule):
    name = "endpoints"
    category = "js_analysis"
    description = "Extract API endpoints from JavaScript files discovered via Wayback CDX and Gau"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            js_urls = await self._gather_js_urls(client, domain)
            if not js_urls:
                return findings

            sem = asyncio.Semaphore(10)

            async def fetch_and_analyze(url: str):
                async with sem:
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        resp.raise_for_status()
                        content = resp.text
                    except Exception:
                        return
                    endpoints = self._extract_endpoints(content, url)
                    for ep in endpoints:
                        findings.append(Finding(
                            source=self.name,
                            type="endpoint",
                            value=ep["value"],
                            context=ep.get("context"),
                            url_found_on=url,
                            severity="info",
                            confidence=ep.get("confidence", 0.6),
                        ))

            tasks = [fetch_and_analyze(url) for url in js_urls]
            for i in range(0, len(tasks), 20):
                batch = tasks[i:i + 20]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.8))

        return findings

    async def _gather_js_urls(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        js_urls: set[str] = set()
        js_pattern = re.compile(r"\.(?:js|mjs|cjs)(?:\?|#|$)", re.IGNORECASE)

        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50000"
            resp = await client.get(cdx_url)
            resp.raise_for_status()
            data = resp.json()
            for row in data[1:]:
                raw_url = row[0]
                if js_pattern.search(raw_url):
                    js_urls.add(raw_url)
        except Exception:
            pass

        try:
            gau_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=50000"
            resp = await client.get(gau_url)
            resp.raise_for_status()
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if line and js_pattern.search(line):
                    js_urls.add(line)
        except Exception:
            pass

        return list(js_urls)[:500]

    def _extract_endpoints(self, content: str, js_url: str) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                raw = match.group(0).strip()
                value = raw.strip("\"'")
                if len(value) < 3 or value in seen:
                    continue
                seen.add(value)
                results.append({
                    "value": value,
                    "context": f"Matched pattern: {pattern[:60]}...",
                    "confidence": 0.65,
                })

        return results


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="js_analysis.endpoints")
def run_endpoints_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = EndpointsModule()
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
