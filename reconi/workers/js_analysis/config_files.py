"""Configuration file discovery — find exposed config files and extract secrets."""
import asyncio
import random
import re
from urllib.parse import urljoin, urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

CONFIG_FILENAMES = [
    "config.js", "config.json", "config.yml", "config.yaml",
    "env.js", "env.json", ".env", ".env.local", ".env.production", ".env.development",
    "settings.js", "settings.json", "settings.yml",
    "app.config.js", "environment.js", "environment.json", "constants.js",
    ".npmrc", ".yarnrc", ".bowerrc",
    "appsettings.json", "appsettings.Development.json",
    "web.config", "package.json",
]

SECRET_PATTERNS = [
    re.compile(r"""(?:password|passwd|pwd|secret|token|key|api_key|api_secret|auth|db_pass|db_user|aws_access|aws_secret|private_key|access_token|refresh_token|client_secret|consumer_key|consumer_secret|app_secret|admin_password|master_key|encryption_key|jwt_secret|session_secret|cookie_secret)\s*[:=]\s*["']([^"'\s]{8,})["']""", re.IGNORECASE),
    re.compile(r"""(?:mongodb|mysql|postgres|postgresql|redis|sqlite)://[^\s"'<>]+""", re.IGNORECASE),
    re.compile(r"""(?:DATABASE_URL|DB_URL|MONGO_URL|REDIS_URL)\s*=\s*["']([^"']{8,})["']""", re.IGNORECASE),
    re.compile(r"""(?:SMTP_HOST|SMTP_PORT|SMTP_USER|SMTP_PASS|MAIL_)\w*\s*[:=]\s*["']([^"']{3,})["']""", re.IGNORECASE),
    re.compile(r"""(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*[:=]\s*["']([^"']{8,})["']""", re.IGNORECASE),
    re.compile(r"""sk-[a-zA-Z0-9]{20,}"""),
    re.compile(r"""(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}"""),
    re.compile(r"""AKIA[0-9A-Z]{16}"""),
    re.compile(r"""ya29\.[0-9A-Za-z\-_]+"""),
]


class ConfigFilesModule(ReconModule):
    name = "config_files"
    category = "js_analysis"
    description = "Discover exposed configuration files via Wayback/Gau and extract secrets"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
            config_urls = await self._find_config_urls(client, domain)
            if not config_urls:
                return findings

            sem = asyncio.Semaphore(10)

            async def analyze_config(url: str):
                async with sem:
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        resp.raise_for_status()
                        content = resp.text
                    except Exception:
                        return

                    findings.append(Finding(
                        source=self.name,
                        type="config_file",
                        value=url,
                        context="Exposed configuration file found",
                        url_found_on=url,
                        severity="medium",
                        confidence=0.85,
                    ))

                    secrets = self._extract_secrets(content, url)
                    for secret in secrets:
                        findings.append(secret)

            tasks = [analyze_config(url) for url in config_urls][:100]
            for i in range(0, len(tasks), 10):
                batch = tasks[i:i + 10]
                await asyncio.gather(*batch)
                await asyncio.sleep(random.uniform(0.3, 0.8))

        return findings

    async def _find_config_urls(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        found_urls: set[str] = set()

        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50000"
            resp = await client.get(cdx_url)
            resp.raise_for_status()
            data = resp.json()
            for row in data[1:]:
                raw_url = row[0].strip()
                for config_name in CONFIG_FILENAMES:
                    if raw_url.endswith(config_name) or f"/{config_name}" in raw_url or f"/{config_name}?" in raw_url:
                        found_urls.add(raw_url)
                        break
                    if config_name.startswith(".") and config_name in raw_url and raw_url.endswith(config_name.rsplit(".", 1)[-1]):
                        found_urls.add(raw_url)
                        break
        except Exception:
            pass

        common_paths: list[str] = []
        for config_name in CONFIG_FILENAMES:
            common_paths.append(f"https://{domain}/{config_name}")
            common_paths.append(f"http://{domain}/{config_name}")

        for candidate in common_paths:
            try:
                resp = await client.head(candidate, follow_redirects=True, timeout=httpx.Timeout(8))
                if resp.status_code == 200:
                    found_urls.add(candidate)
            except Exception:
                pass

        return list(found_urls)

    def _extract_secrets(self, content: str, url: str) -> list[Finding]:
        results: list[Finding] = []
        seen: set[str] = set()

        for pattern in SECRET_PATTERNS:
            for m in pattern.finditer(content):
                groups = m.groups()
                if groups:
                    secret_val = groups[0]
                else:
                    secret_val = m.group(0)

                if secret_val in seen:
                    continue
                seen.add(secret_val)

                if len(secret_val) < 8:
                    continue

                results.append(Finding(
                    source=self.name,
                    type="secret_in_config",
                    value=url,
                    context=f"Secret found: {secret_val[:80]}... (pattern: {pattern.pattern[:60]}...)",
                    url_found_on=url,
                    severity="high",
                    confidence=0.7,
                    raw={"secret_value_length": len(secret_val), "pattern": pattern.pattern[:80]},
                ))

        return results


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="js_analysis.config_files")
def run_config_files_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = ConfigFilesModule()
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
