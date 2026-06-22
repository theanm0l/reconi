"""Sourcemap parsing — discover original source files and secrets from .map files."""
import asyncio
import json
import random
import re
from urllib.parse import urljoin, urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

SOURCE_MAP_PATTERN = re.compile(r"//#\s*sourceMappingURL\s*=\s*(.+)", re.IGNORECASE)
SECRET_PATTERNS = [
    re.compile(r"(?i)(?:api[_-]?key|apikey|api_secret|secret_key|private_key|access_key)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    re.compile(r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    re.compile(r"(?i)(?:token|jwt|bearer)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    re.compile(r"(?i)(?:mongodb|mysql|postgres|postgresql|redis)://[^\s'\"<>]+"),
    re.compile(r"(?i)(?:aws_access_key_id|aws_secret_access_key)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
]

JS_EXTENSIONS = {".js", ".mjs", ".cjs"}


class SourcemapsModule(ReconModule):
    name = "sourcemaps"
    category = "js_analysis"
    description = "Discover and parse JavaScript sourcemap files to extract original sources and secrets"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            js_urls = await self._gather_js_urls(client, domain)
            if not js_urls:
                return findings

            map_urls: list[str] = []
            sem = asyncio.Semaphore(10)

            async def find_maps(url: str) -> list[str]:
                found: list[str] = []
                try:
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    content = resp.text
                except Exception:
                    return found

                for m in SOURCE_MAP_PATTERN.finditer(content):
                    map_ref = m.group(1).strip().rstrip(";").strip("\"'")
                    if map_ref:
                        found.append(urljoin(url, map_ref))

                for suffix in [".map", "?sourcemap"]:
                    candidate = f"{url}{suffix}"
                    try:
                        resp2 = await client.head(candidate, follow_redirects=True)
                        if resp2.status_code == 200:
                            content_type = resp2.headers.get("content-type", "")
                            if "json" in content_type or "octet-stream" in content_type or candidate.endswith(".map"):
                                found.append(candidate)
                    except Exception:
                        pass

                return found

            tasks_for_maps = [find_maps(url) for url in js_urls]
            for i in range(0, len(tasks_for_maps), 20):
                batch = tasks_for_maps[i:i + 20]
                results = await asyncio.gather(*batch)
                for result_list in results:
                    for r in result_list:
                        if r not in map_urls:
                            map_urls.append(r)
                await asyncio.sleep(random.uniform(0.3, 0.8))

            async def parse_map(url: str):
                async with sem:
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        resp.raise_for_status()
                        data = resp.json()
                    except Exception:
                        return

                    sources = data.get("sources", [])
                    sources_content = data.get("sourcesContent", [])
                    content_by_source = dict(zip(sources, sources_content)) if sources and sources_content else {}

                    for src in sources:
                        findings.append(Finding(
                            source=self.name,
                            type="sourcemap",
                            value=src,
                            context="Original source file from sourcemap",
                            url_found_on=url,
                            severity="info",
                            confidence=0.8,
                            raw={"map_url": url},
                        ))

                        src_content = content_by_source.get(src, "")
                        if src_content:
                            for secret_pattern in SECRET_PATTERNS:
                                for secret_match in secret_pattern.finditer(src_content):
                                    secret_val = secret_match.group(0)
                                    findings.append(Finding(
                                        source=self.name,
                                        type="sourcemap",
                                        value=src,
                                        context=f"Potential secret found in sourcemap source: {secret_val[:120]}",
                                        url_found_on=url,
                                        severity="high",
                                        confidence=0.7,
                                        raw={"map_url": url, "pattern": secret_pattern.pattern},
                                    ))

                        if src.endswith((".ts", ".tsx", ".vue", ".jsx")):
                            findings.append(Finding(
                                source=self.name,
                                type="sourcemap",
                                value=src,
                                context=f"Original {_get_file_type(src)} source discovered",
                                url_found_on=url,
                                severity="medium",
                                confidence=0.9,
                                raw={"map_url": url},
                            ))

            tasks_parse = [parse_map(url) for url in map_urls[:200]]
            for i in range(0, len(tasks_parse), 10):
                batch = tasks_parse[i:i + 10]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.6))

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

        return list(js_urls)[:500]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


def _get_file_type(filename: str) -> str:
    if filename.endswith((".ts", ".tsx")):
        return "TypeScript"
    if filename.endswith(".vue"):
        return "Vue"
    if filename.endswith(".jsx"):
        return "JSX"
    if filename.endswith(".scss"):
        return "SCSS"
    return "source"


@celery_app.task(name="js_analysis.sourcemaps")
def run_sourcemaps_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = SourcemapsModule()
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
