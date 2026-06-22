"""Firebase configuration discovery and security validation from JavaScript files."""
import asyncio
import json
import random
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

FIREBASE_CONFIG_PATTERN = re.compile(r"firebaseConfig\s*=\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}", re.DOTALL)
FIREBASE_DEFAULTS_PATTERN = re.compile(r"__FIREBASE_DEFAULTS__\s*[:=]\s*(\{[^}]+\})", re.DOTALL)

FIELD_PATTERNS = {
    "apiKey": re.compile(r"""apiKey\s*:\s*["']([^"']+)["']"""),
    "authDomain": re.compile(r"""authDomain\s*:\s*["']([^"']+)["']"""),
    "projectId": re.compile(r"""projectId\s*:\s*["']([^"']+)["']"""),
    "storageBucket": re.compile(r"""storageBucket\s*:\s*["']([^"']+)["']"""),
    "messagingSenderId": re.compile(r"""messagingSenderId\s*:\s*["']([^"']+)["']"""),
    "appId": re.compile(r"""appId\s*:\s*["']([^"']+)["']"""),
    "databaseURL": re.compile(r"""databaseURL\s*:\s*["']([^"']+)["']"""),
    "measurementId": re.compile(r"""measurementId\s*:\s*["']([^"']+)["']"""),
}

FIREBASE_DB_URL = "https://{project_id}-default-rtdb.firebaseio.com"
FIREBASE_STORAGE_URL = "https://{project_id}.firebaseio.com"
JS_EXTENSIONS = {".js", ".mjs", ".cjs"}


class FirebaseModule(ReconModule):
    name = "firebase"
    category = "js_analysis"
    description = "Discover Firebase configurations in JavaScript and validate for security weaknesses"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            js_urls = await self._gather_js_urls(client, domain)
            if not js_urls:
                return findings

            firebase_configs: list[dict] = []
            sem = asyncio.Semaphore(10)

            async def analyze_url(url: str):
                try:
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    content = resp.text
                except Exception:
                    return

                for m in FIREBASE_CONFIG_PATTERN.finditer(content):
                    config_block = m.group(0)
                    parsed = await self._parse_config(config_block, url)
                    if parsed:
                        firebase_configs.append(parsed)

                for m in FIREBASE_DEFAULTS_PATTERN.finditer(content):
                    raw = m.group(0)
                    try:
                        parsed_defaults = json.loads(m.group(1))
                        firebase_configs.append({
                            "raw": raw,
                            "fields": parsed_defaults,
                            "url": url,
                        })
                    except Exception:
                        pass

                for name, pattern in FIELD_PATTERNS.items():
                    if name not in {"apiKey", "authDomain", "projectId"}:
                        continue
                    for field_match in pattern.finditer(content):
                        value = field_match.group(1)
                        exists = any(c.get("fields", {}).get(name) == value for c in firebase_configs)
                        if not exists:
                            findings.append(Finding(
                                source=self.name,
                                type="firebase_config",
                                value=f"{name}: {value}",
                                context=f"Standalone {name} found",
                                url_found_on=url,
                                severity="medium",
                                confidence=0.6,
                            ))

            tasks = [analyze_url(url) for url in js_urls[:200]]
            for i in range(0, len(tasks), 20):
                batch = tasks[i:i + 20]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.8))

            for config in firebase_configs:
                project_id = config.get("fields", {}).get("projectId", "")
                api_key = config.get("fields", {}).get("apiKey", "")

                findings.append(Finding(
                    source=self.name,
                    type="firebase_config",
                    value=f"Firebase project: {project_id}",
                    context=f"Full Firebase configuration discovered",
                    url_found_on=config.get("url"),
                    severity="high",
                    confidence=0.85,
                    raw={"config": config.get("fields"), "raw_config": config.get("raw")},
                ))

                if project_id:
                    security_issues = await self._check_security(client, project_id, api_key)
                    for issue in security_issues:
                        findings.append(issue)

        return findings

    async def _parse_config(self, config_block: str, url: str) -> dict | None:
        fields: dict = {}
        for name, pattern in FIELD_PATTERNS.items():
            m = pattern.search(config_block)
            if m:
                fields[name] = m.group(1)
        if fields:
            return {"raw": config_block, "fields": fields, "url": url}
        return None

    async def _check_security(self, client: httpx.AsyncClient, project_id: str, api_key: str) -> list[Finding]:
        issues: list[Finding] = []
        check_urls = []

        if api_key:
            check_urls.append(
                (f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}", "Firebase Auth signup open")
            )
            check_urls.append(
                (f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}", "Firebase Auth signin open")
            )

        check_urls.append((f"https://{project_id}.firebaseio.com/.json", "Firebase RTDB publicly readable"))

        for test_url, description in check_urls:
            try:
                resp = await client.get(test_url, timeout=httpx.Timeout(10))
                if resp.status_code == 200:
                    body = resp.text[:300]
                    weak_indicator = any(kw in body.lower() for kw in ["null", "error", "missing", "invalid", "unauthorized", "forbidden"])
                    is_actually_weak = resp.status_code == 200 and not weak_indicator

                    if is_actually_weak or "signUp" in test_url or "signInWithPassword" in test_url:
                        if resp.status_code in (200, 400):
                            issues.append(Finding(
                                source=self.name,
                                type="firebase_config",
                                value=project_id,
                                context=f"Weak security: {description} (accessible without auth)",
                                url_found_on=test_url,
                                severity="high",
                                confidence=0.75,
                                raw={"test_url": test_url, "status_code": resp.status_code},
                            ))
                elif resp.status_code == 200 and "null" not in resp.text.lower():
                    issues.append(Finding(
                        source=self.name,
                        type="firebase_config",
                        value=project_id,
                        context=f"{description}",
                        url_found_on=test_url,
                        severity="high",
                        confidence=0.6,
                        raw={"test_url": test_url, "status_code": resp.status_code},
                    ))
            except Exception:
                pass

        return issues

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


@celery_app.task(name="js_analysis.firebase")
def run_firebase_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = FirebaseModule()
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
