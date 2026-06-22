"""Cloud storage bucket discovery — find and test S3, GCS, Azure, and DO buckets from JS/HTML."""
import asyncio
import random
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

S3_PATTERN = re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.s3[.-]?[a-z0-9-]*\.amazonaws\.com""", re.IGNORECASE)
S3_PATH_PATTERN = re.compile(r"""https?://s3[.-]?[a-z0-9-]*\.amazonaws\.com/[a-zA-Z0-9][a-zA-Z0-9.-]+""", re.IGNORECASE)
GCS_PATTERN = re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.storage\.googleapis\.com""", re.IGNORECASE)
AZURE_PATTERN = re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.blob\.core\.windows\.net""", re.IGNORECASE)
DO_PATTERN = re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.digitaloceanspaces\.com""", re.IGNORECASE)

BUCKET_PATTERNS = [
    (S3_PATTERN, "AWS S3"),
    (S3_PATH_PATTERN, "AWS S3 (path-style)"),
    (GCS_PATTERN, "Google Cloud Storage"),
    (AZURE_PATTERN, "Azure Blob Storage"),
    (DO_PATTERN, "DigitalOcean Spaces"),
]

PUBLIC_INDICATORS = [
    "<ListBucketResult",
    "<Contents>",
    "<Key>",
    "<Name>",
    "ListBucketResult",
]


class S3BucketsModule(ReconModule):
    name = "s3_buckets"
    category = "js_analysis"
    description = "Discover cloud storage bucket URLs in JavaScript and HTML, and test for public access"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            js_urls = await self._gather_js_urls(client, domain)
            html_urls = await self._gather_html_urls(client, domain)
            all_urls = list(set(js_urls + html_urls))[:300]

            discovered_buckets: dict[str, str] = {}
            sem = asyncio.Semaphore(10)

            async def analyze_url(url: str):
                try:
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    content = resp.text
                except Exception:
                    return

                for pattern, provider in BUCKET_PATTERNS:
                    for m in pattern.finditer(content):
                        bucket_url = m.group(0).rstrip("/")
                        clean_url = bucket_url.rstrip("/")
                        if clean_url not in discovered_buckets:
                            discovered_buckets[clean_url] = provider

            tasks = [analyze_url(url) for url in all_urls]
            for i in range(0, len(tasks), 20):
                batch = tasks[i:i + 20]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.8))

            async def test_bucket(url: str, provider: str):
                async with sem:
                    try:
                        resp = await client.get(url, timeout=httpx.Timeout(15), follow_redirects=True)
                        status = resp.status_code
                        body = resp.text[:500]

                        is_public = False
                        severity = "info"

                        if status == 200:
                            if any(indicator in body for indicator in PUBLIC_INDICATORS):
                                is_public = True
                                severity = "high"
                                context = f"Publicly accessible {provider} bucket — listing enabled"
                            elif len(body) > 0:
                                is_public = True
                                severity = "medium"
                                context = f"Publicly accessible {provider} bucket"
                            else:
                                is_public = True
                                severity = "medium"
                                context = f"{provider} bucket returned 200 OK"
                        elif status == 403:
                            context = f"{provider} bucket exists but access denied (403)"
                        elif status == 404:
                            context = f"{provider} bucket not found or deleted (404)"
                        else:
                            context = f"{provider} bucket returned status {status}"

                        if status != 404:
                            findings.append(Finding(
                                source=self.name,
                                type="cloud_storage",
                                value=url,
                                context=context,
                                url_found_on=url,
                                severity=severity,
                                confidence=0.8 if (status == 200 and is_public) else 0.5,
                                raw={"provider": provider, "status_code": status, "is_public": is_public},
                            ))
                    except Exception as e:
                        pass

            test_tasks = [test_bucket(url, provider) for url, provider in discovered_buckets.items()]
            for i in range(0, len(test_tasks), 10):
                batch = test_tasks[i:i + 10]
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

        return list(js_urls)[:300]

    async def _gather_html_urls(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        html_urls: set[str] = set()
        html_pattern = re.compile(r"\.(?:html?|php|asp|jsp)(?:\?|#|$)", re.IGNORECASE)

        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50000"
            resp = await client.get(cdx_url)
            resp.raise_for_status()
            data = resp.json()
            for row in data[1:]:
                raw_url = row[0]
                if html_pattern.search(raw_url) or not re.search(r"\.\w{2,4}(?:\?|#|$)", raw_url):
                    html_urls.add(raw_url)
        except Exception:
            pass

        return list(html_urls)[:300]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="js_analysis.s3_buckets")
def run_s3_buckets_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = S3BucketsModule()
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
