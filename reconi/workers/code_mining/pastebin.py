"""Pastebin scraping — search psbdmp.ws and pastebin.com for domain mentions."""
import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

_SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), "email"),
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|token|apikey|api_key|auth)\s*[:=]\s*["\']?([^\s"\'<>]{8,})'), "credential"),
    (re.compile(r'(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s<>"\'{}|\\^`\[\]]+'), "db_url"),
    (re.compile(r'(?i)https?://[^\s<>"\'{}|\\^`\[\]]+'), "url"),
    (re.compile(r'(?i)-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE\s?KEY'), "private_key"),
    (re.compile(r'(?i)(?:api|app|auth|client)_?(?:key|token|secret)?\s*[:=]\s*["\']?([^\s"\'<>]{16,})'), "api_key"),
]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


class PastebinModule(ReconModule):
    name = "pastebin"
    category = "code_mining"
    description = "Search psbdmp.ws and pastebin.com for pastes mentioning a domain"
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
                for paste_id_entry in paste_ids[:50]:
                    await asyncio.sleep(0.5)
                    pid = paste_id_entry if isinstance(paste_id_entry, str) else paste_id_entry.get("id", "")
                    if not pid:
                        continue

                    try:
                        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                            dump_url = f"https://psbdmp.ws/api/v3/dump/{pid}"
                            dump_resp = await client.get(dump_url)
                            if dump_resp.status_code != 200:
                                continue
                            dump_data = dump_resp.json()
                            content = dump_data.get("content", dump_data.get("text", "")) if isinstance(dump_data, dict) else str(dump_data)
                    except Exception:
                        continue

                    paste_url = f"https://psbdmp.ws/{pid}"
                    for pattern, label in _SENSITIVE_PATTERNS:
                        match = pattern.search(content)
                        if match:
                            matched = match.group(0)
                            findings.append(Finding(
                                source=self.name,
                                type="paste",
                                value=paste_url,
                                context=f"Found {label}: {matched[:100]}",
                                url_found_on=search_url,
                                severity="high" if label in ("credential", "private_key", "db_url", "api_key") else "medium",
                                confidence=0.7,
                                raw={"paste_id": pid, "detected": label},
                            ))
                            break
                    else:
                        findings.append(Finding(
                            source=self.name,
                            type="paste",
                            value=paste_url,
                            context=content[:200] if content else "",
                            url_found_on=search_url,
                            severity="info",
                            confidence=0.3,
                            raw={"paste_id": pid},
                        ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=f"psbdmp: {e}", severity="info", confidence=0.0))

        pastebin_key = os.getenv("PASTEBIN_API_KEY", "")
        if pastebin_key:
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                    scrape_url = f"https://scrape.pastebin.com/api_scraping.php?limit=250"
                    resp = await client.get(scrape_url)
                    resp.raise_for_status()
                    pastes = resp.json()

                for paste in pastes[:50]:
                    await asyncio.sleep(0.5)
                    paste_key = paste.get("key", "")
                    scrape_url_paste = paste.get("scrape_url", "")
                    title = paste.get("title", "")

                    if domain.lower() in title.lower():
                        paste_url = f"https://pastebin.com/{paste_key}"
                        content = ""
                        if scrape_url_paste:
                            try:
                                async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                                    content_resp = await client.get(scrape_url_paste)
                                    content = content_resp.text
                            except Exception:
                                pass

                        for pattern, label in _SENSITIVE_PATTERNS:
                            match = pattern.search(content)
                            if match:
                                findings.append(Finding(
                                    source=self.name,
                                    type="paste",
                                    value=paste_url,
                                    context=f"Found {label}: {match.group(0)[:100]}",
                                    url_found_on=scrape_url,
                                    severity="high" if label in ("credential", "private_key", "db_url", "api_key") else "medium",
                                    confidence=0.7,
                                    raw={"paste_key": paste_key, "detected": label},
                                ))
                                break
                        else:
                            findings.append(Finding(
                                source=self.name,
                                type="paste",
                                value=paste_url,
                                context=title[:200],
                                url_found_on=scrape_url,
                                severity="info",
                                confidence=0.3,
                                raw={"paste_key": paste_key},
                            ))

            except Exception as e:
                findings.append(Finding(source=self.name, type="error", value=f"pastebin_com: {e}", severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.pastebin")
def run_pastebin_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = PastebinModule()
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
