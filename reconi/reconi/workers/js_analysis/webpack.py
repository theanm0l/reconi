"""Webpack bundle analysis — extract module names and detect exposed chunk files."""
import asyncio
import random
import re
from collections import defaultdict
from urllib.parse import urljoin, urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

WEBPACK_PATTERN = re.compile(r"""["']webpack:///([^"']+)["']""")
CHUNK_PATTERNS = [
    r"{module}\.bundle\.js",
    r"{module}\.chunk\.js",
    r"{module}\.bundle\.min\.js",
    r"{module}\.chunk\.min\.js",
]

NODE_MODULES_PREFIX = "node_modules/"
WEBPACK_SRC_PATTERNS = ["webpack:///src/", "webpack:///./src/", "webpack:///./", "webpack:///webpack/"]

JS_EXTENSIONS = {".js", ".mjs", ".cjs"}


class WebpackModule(ReconModule):
    name = "webpack"
    category = "js_analysis"
    description = "Analyze webpack bundles to extract internal module paths and detect exposed chunk files"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            js_urls = await self._gather_js_urls(client, domain)
            if not js_urls:
                return findings

            internal_modules: set[str] = set()
            third_party_modules: set[str] = set()
            sem = asyncio.Semaphore(10)

            async def analyze_url(url: str):
                try:
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    content = resp.text
                except Exception:
                    return

                for m in WEBPACK_PATTERN.finditer(content):
                    module_path = m.group(1).strip()

                    if WEBPACK_SRC_PREFIX.search(module_path):
                        internal_modules.add(module_path)
                    elif module_path.startswith(NODE_MODULES_PREFIX):
                        third_party_modules.add(module_path)
                    elif any(prefix in module_path for prefix in WEBPACK_SRC_PATTERNS):
                        internal_modules.add(module_path)
                    else:
                        internal_modules.add(module_path)

            WEBPACK_SRC_PREFIX = re.compile(r"^(?:src|\./src)/")

            async def check_chunks():
                chunks_found: set[str] = set()
                for js_url in js_urls[:100]:
                    filename = js_url.rsplit("/", 1)[-1].rsplit("?", 1)[0]
                    base_dir = js_url.rsplit("/", 1)[0] if "/" in js_url else ""
                    for name in re.findall(r"([a-zA-Z0-9_-]+)\.(?:bundle|chunk)\.js", filename):
                        for pattern in CHUNK_PATTERNS:
                            variant = pattern.replace("{module}", name)
                            candidate = f"{base_dir}/{variant}" if base_dir else variant
                            if candidate not in chunks_found:
                                try:
                                    resp = await client.head(candidate, follow_redirects=True)
                                    if resp.status_code == 200:
                                        chunks_found.add(candidate)
                                except Exception:
                                    pass
                return chunks_found

            tasks = [analyze_url(url) for url in js_urls[:200]]
            for i in range(0, len(tasks), 20):
                batch = tasks[i:i + 20]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.8))

            exposed_chunks = await check_chunks()

        for module_path in internal_modules:
            findings.append(Finding(
                source=self.name,
                type="webpack_module",
                value=module_path,
                context="Internal webpack module",
                severity="info",
                confidence=0.75,
            ))

        for module_path in third_party_modules:
            pkg_name = module_path.replace(NODE_MODULES_PREFIX, "").split("/")[0]
            findings.append(Finding(
                source=self.name,
                type="webpack_module",
                value=module_path,
                context=f"Third-party dependency: {pkg_name}",
                severity="info",
                confidence=0.85,
            ))

        for chunk_url in exposed_chunks:
            findings.append(Finding(
                source=self.name,
                type="webpack_module",
                value=chunk_url,
                context="Exposed webpack chunk file",
                severity="medium",
                confidence=0.7,
            ))

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


@celery_app.task(name="js_analysis.webpack")
def run_webpack_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = WebpackModule()
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
