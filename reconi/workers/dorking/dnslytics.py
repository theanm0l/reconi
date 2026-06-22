"""DNSlytics dorking module — scrape DNSlytics for domain info and related domains."""

import asyncio
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class DNSLyticsModule(ReconModule):
    name = "dnslytics"
    category = "dorking"
    description = "Scrape DNSlytics for domain info, IP, nameservers, and related domains"
    requires_api_key = False
    rate_limit_delay = 2.0

    async def _scrape_domain_info(
        self, client: httpx.AsyncClient, domain: str
    ) -> dict[str, str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        info: dict[str, str] = {}
        try:
            resp = await client.get(
                f"https://www.dnslytics.com/domain/{domain}",
                headers=headers,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            # Extract IP addresses
            for row in soup.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 2:
                    key = cells[0].get_text(strip=True).lower()
                    val = cells[1].get_text(strip=True)
                    if key in ("ip address", "a record", "ip"):
                        info["ip"] = val
                    elif key in ("nameservers", "name servers"):
                        info["nameservers"] = val
            # Extract any hrefs pointing to reverse-ip
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if isinstance(href, str) and "reverse-ip" in href:
                    ip_part = href.rstrip("/").rsplit("/", 1)[-1]
                    if ip_part:
                        info.setdefault("reverse_ip_target", ip_part)
            return info
        except Exception:
            return info

    async def _scrape_related_domains(
        self, client: httpx.AsyncClient, domain: str
    ) -> list[str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        domains: list[str] = []
        try:
            resp = await client.get(
                f"https://www.dnslytics.com/domain/{domain}",
                headers=headers,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                text = link.get_text(strip=True)
                if isinstance(href, str) and href.startswith("/domain/") and text:
                    d = href.replace("/domain/", "").strip("/")
                    if d and d != domain:
                        domains.append(d)
            return list(dict.fromkeys(domains))
        except Exception:
            return domains

    async def _scrape_reverse_ip(
        self, client: httpx.AsyncClient, ip: str
    ) -> list[str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        domains: list[str] = []
        try:
            resp = await client.get(
                f"https://www.dnslytics.com/reverse-ip?ip={ip}",
                headers=headers,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                text = link.get_text(strip=True)
                if isinstance(href, str) and href.startswith("/domain/") and text:
                    d = href.replace("/domain/", "").strip("/")
                    if d:
                        domains.append(d)
            return list(dict.fromkeys(domains))
        except Exception:
            return domains

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            info = await self._scrape_domain_info(client, domain)
            await asyncio.sleep(self.rate_limit_delay)
            ip = info.get("ip", "")
            nameservers = info.get("nameservers", "")
            if ip or nameservers:
                findings.append(
                    Finding(
                        source=self.name,
                        type="dns_info",
                        value=ip or domain,
                        context=f"nameservers: {nameservers}" if nameservers else f"domain: {domain}",
                        url_found_on=f"https://www.dnslytics.com/domain/{domain}",
                        severity="info",
                        confidence=0.6,
                        raw={"domain": domain, "ip": ip, "nameservers": nameservers},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            related = await self._scrape_related_domains(client, domain)
            await asyncio.sleep(self.rate_limit_delay)
            for rel in related:
                findings.append(
                    Finding(
                        source=self.name,
                        type="related_domain",
                        value=rel,
                        context=f"related to: {domain}",
                        url_found_on=f"https://www.dnslytics.com/domain/{domain}",
                        severity="info",
                        confidence=0.5,
                        raw={"related_domain": rel, "source_domain": domain},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            if ip:
                reverse_results = await self._scrape_reverse_ip(client, ip)
                for rev_domain in reverse_results:
                    if rev_domain == domain:
                        continue
                    findings.append(
                        Finding(
                            source=self.name,
                            type="related_domain",
                            value=rev_domain,
                            context=f"reverse-IP on {ip}",
                            url_found_on=f"https://www.dnslytics.com/reverse-ip?ip={ip}",
                            severity="info",
                            confidence=0.5,
                            raw={"ip": ip, "related_domain": rev_domain},
                            found_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
        return findings


dnslytics_module = DNSLyticsModule()


@celery_app.task(name="dorking.dnslytics")
def run_dnslytics_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await dnslytics_module.run(target)
        return [f.__dict__ for f in findings]

    results = asyncio.run(_run())
    db = SessionLocal()
    try:
        job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if job:
            job.items_found = len(results)
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return results
