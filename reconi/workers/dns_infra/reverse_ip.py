"""Reverse IP lookup module — discover domains sharing the same IP address."""
import asyncio
import os
import re
import socket
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


def _resolve_domain(target: str) -> list[str]:
    domain = _extract_domain(target)
    ips: set[str] = set()
    try:
        _, _, addresses = socket.gethostbyname_ex(domain)
        ips.update(addresses)
    except socket.gaierror:
        try:
            ip = socket.gethostbyname(domain)
            ips.add(ip)
        except socket.gaierror:
            pass
    return sorted(ips)


class ReverseIPModule(ReconModule):
    name = "reverse_ip"
    category = "dns_infra"
    description = "Discover all domains hosted on the same IP addresses as the target"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        ips = _resolve_domain(target)

        if not ips:
            findings.append(Finding(
                source=self.name,
                type="error",
                value=f"Could not resolve IP addresses for {domain}",
                severity="info",
                confidence=0.0,
            ))
            return findings

        for ip in ips:
            findings.append(Finding(
                source=self.name,
                type="reverse_ip",
                value=ip,
                context=f"Resolved IP for {domain}",
                severity="info",
                confidence=1.0,
                raw={"domain": domain, "ip": ip},
            ))

            api_key = os.environ.get("VIEWDNS_API_KEY", "")
            if api_key:
                findings.extend(await self._viewdns_lookup(ip, api_key))
            findings.extend(await self._domaintools_scrape(ip, domain))
            findings.extend(await self._yougetsignal_lookup(ip, domain))
            findings.extend(await self._hackertarget_lookup(ip, domain))

        return findings

    async def _viewdns_lookup(self, ip: str, api_key: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={api_key}&output=json"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            domains_data = data.get("response", {}).get("domains", [])
            if isinstance(domains_data, list):
                for entry in domains_data:
                    if isinstance(entry, dict):
                        domain_name = entry.get("name", "")
                    else:
                        domain_name = str(entry)
                    if domain_name:
                        findings.append(Finding(
                            source=self.name,
                            type="reverse_ip",
                            value=domain_name,
                            context=f"Shares IP {ip} (ViewDNS)",
                            url_found_on=url,
                            severity="info",
                            confidence=0.8,
                            raw={"ip": ip, "source": "viewdns"},
                        ))
        except Exception:
            pass
        return findings

    async def _domaintools_scrape(self, ip: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://reverseip.domaintools.com/search/?q={ip}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                },
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "lxml")
            for link in soup.select("a.domain"):
                domain_name = link.get_text(strip=True)
                if domain_name and domain_name != domain:
                    findings.append(Finding(
                        source=self.name,
                        type="reverse_ip",
                        value=domain_name,
                        context=f"Shares IP {ip} (DomainTools)",
                        url_found_on=url,
                        severity="info",
                        confidence=0.6,
                        raw={"ip": ip, "source": "domaintools"},
                    ))
        except Exception:
            pass
        return findings

    async def _yougetsignal_lookup(self, ip: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        url = "https://www.yougetsignal.com/tools/web-sites-on-web-server/"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest",
                },
            ) as client:
                resp = await client.post(url, data={"remoteAddress": ip})
                resp.raise_for_status()

            data = resp.json()
            domain_list = data.get("domainArray", data if isinstance(data, list) else [])
            if isinstance(domain_list, list):
                for entry in domain_list:
                    domain_name = entry if isinstance(entry, str) else entry.get(0, entry.get("name", ""))
                    if domain_name and str(domain_name).strip() and domain_name != domain:
                        findings.append(Finding(
                            source=self.name,
                            type="reverse_ip",
                            value=str(domain_name).strip(),
                            context=f"Shares IP {ip} (YouGetSignal)",
                            url_found_on=url,
                            severity="info",
                            confidence=0.6,
                            raw={"ip": ip, "source": "yougetsignal"},
                        ))
        except Exception:
            pass
        return findings

    async def _hackertarget_lookup(self, ip: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                    for line in resp.text.strip().split("\n"):
                        domain_name = line.strip()
                        if domain_name and domain_name != domain:
                            domain_name = re.sub(r"^https?://", "", domain_name)
                            domain_name = domain_name.rstrip("/")
                            findings.append(Finding(
                                source=self.name,
                                type="reverse_ip",
                                value=domain_name,
                                context=f"Shares IP {ip} (HackerTarget)",
                                url_found_on=url,
                                severity="info",
                                confidence=0.7,
                                raw={"ip": ip, "source": "hackertarget"},
                            ))
        except Exception:
            pass
        return findings


@celery_app.task(name="dns_infra.reverse_ip")
def run_reverse_ip_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = ReverseIPModule()
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
