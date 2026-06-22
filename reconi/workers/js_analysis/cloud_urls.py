"""Cloud service URL discovery — extract and validate cloud-hosted service URLs from JavaScript."""
import asyncio
import random
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

CLOUD_URL_PATTERNS = [
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.cloudfront\.net""", re.IGNORECASE), "AWS CloudFront"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.azureedge\.net""", re.IGNORECASE), "Azure CDN"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.azurewebsites\.net""", re.IGNORECASE), "Azure Web App"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.herokuapp\.com""", re.IGNORECASE), "Heroku"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.netlify\.app""", re.IGNORECASE), "Netlify"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.vercel\.app""", re.IGNORECASE), "Vercel"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.firebaseapp\.com""", re.IGNORECASE), "Firebase Hosting"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.web\.app""", re.IGNORECASE), "Firebase/Google Web App"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.appspot\.com""", re.IGNORECASE), "Google App Engine"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.pages\.dev""", re.IGNORECASE), "Cloudflare Pages"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.storage\.googleapis\.com""", re.IGNORECASE), "Google Cloud Storage"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.cloudfunctions\.net""", re.IGNORECASE), "Google Cloud Functions"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.run\.app""", re.IGNORECASE), "Google Cloud Run"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.fly\.dev""", re.IGNORECASE), "Fly.io"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.railway\.app""", re.IGNORECASE), "Railway"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.render\.com""", re.IGNORECASE), "Render"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.amplifyapp\.com""", re.IGNORECASE), "AWS Amplify"),
    (re.compile(r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.onrender\.com""", re.IGNORECASE), "Render (onrender)"),
]

JS_EXTENSIONS = {".js", ".mjs", ".cjs"}


class CloudUrlsModule(ReconModule):
    name = "cloud_urls"
    category = "js_analysis"
    description = "Extract and validate cloud-hosted service URLs from JavaScript files"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            js_urls = await self._gather_js_urls(client, domain)
            if not js_urls:
                return findings

            discovered_urls: dict[str, str] = {}
            sem = asyncio.Semaphore(10)

            async def analyze_js(url: str):
                try:
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    content = resp.text
                except Exception:
                    return

                for pattern, provider in CLOUD_URL_PATTERNS:
                    for m in pattern.finditer(content):
                        cloud_url = m.group(0).rstrip("/").rstrip(".")
                        parsed = urlparse(cloud_url)
                        if parsed.hostname == domain or parsed.hostname == f"www.{domain}":
                            continue
                        hostname = parsed.hostname or cloud_url
                        if hostname not in discovered_urls:
                            discovered_urls[hostname] = provider

            tasks = [analyze_js(url) for url in js_urls[:200]]
            for i in range(0, len(tasks), 20):
                batch = tasks[i:i + 20]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.8))

            async def check_url(hostname: str, provider: str):
                async with sem:
                    for scheme in ["https", "http"]:
                        test_url = f"{scheme}://{hostname}"
                        try:
                            resp = await client.get(test_url, timeout=httpx.Timeout(10), follow_redirects=True)
                            status = resp.status_code

                            if status < 500:
                                findings.append(Finding(
                                    source=self.name,
                                    type="cloud_url",
                                    value=test_url,
                                    context=f"Reachable {provider} instance (HTTP {status})",
                                    url_found_on=test_url,
                                    severity="info" if status >= 400 else "medium",
                                    confidence=0.85,
                                    raw={"provider": provider, "status_code": status, "hostname": hostname},
                                ))
                                return
                        except Exception:
                            continue

                    findings.append(Finding(
                        source=self.name,
                        type="cloud_url",
                        value=hostname,
                        context=f"Discovered but unreachable {provider} hostname",
                        severity="info",
                        confidence=0.55,
                        raw={"provider": provider, "hostname": hostname, "reachable": False},
                    ))

            check_tasks = [check_url(hostname, provider) for hostname, provider in discovered_urls.items()]
            for i in range(0, len(check_tasks), 10):
                batch = check_tasks[i:i + 10]
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


@celery_app.task(name="js_analysis.cloud_urls")
def run_cloud_urls_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = CloudUrlsModule()
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
