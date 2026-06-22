"""ASN enumeration module — identify ASN, IP ranges, and network info for a target."""
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


def _resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return ""


class ASNEnumModule(ReconModule):
    name = "asn_enum"
    category = "dns_infra"
    description = "Enumerate ASN details, IP ranges, and BGP prefixes for a domain"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        ip = _resolve_ip(domain)

        if ip:
            findings.append(Finding(
                source=self.name,
                type="asn_info",
                value=ip,
                context=f"Resolved IP for {domain}",
                severity="info",
                confidence=1.0,
                raw={"domain": domain, "ip": ip},
            ))

            findings.extend(await self._ipinfo_lookup(ip))
            findings.extend(await self._bgpview_lookup(ip))
            asns = await self._bgpview_ip_lookup(ip, findings)
            findings.extend(asns)

        findings.extend(await self._bgphe_scrape(domain))
        return findings

    async def _ipinfo_lookup(self, ip: str) -> list[Finding]:
        findings: list[Finding] = []
        token = os.environ.get("IPINFO_TOKEN", "")
        if token:
            url = f"https://ipinfo.io/{ip}?token={token}"
        else:
            url = f"https://ipinfo.io/{ip}/json"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            org = data.get("org", "")
            asn_match = re.search(r"AS(\d+)", org) if org else None
            asn = asn_match.group(1) if asn_match else ""

            context_parts = []
            if org:
                context_parts.append(org)
            if data.get("city"):
                context_parts.append(data["city"])
            if data.get("country"):
                context_parts.append(data["country"])

            findings.append(Finding(
                source=self.name,
                type="asn_info",
                value=ip,
                context=" | ".join(context_parts) if context_parts else f"ipinfo.io data for {ip}",
                url_found_on=url,
                severity="info",
                confidence=0.85,
                raw={
                    "ip": ip,
                    "org": org,
                    "asn": asn,
                    "hostname": data.get("hostname", ""),
                    "city": data.get("city", ""),
                    "region": data.get("region", ""),
                    "country": data.get("country", ""),
                    "loc": data.get("loc", ""),
                },
            ))

            if asn:
                findings.append(Finding(
                    source=self.name,
                    type="asn_info",
                    value=f"AS{asn}",
                    context=f"ASN for {ip}: {org}",
                    severity="info",
                    confidence=0.85,
                    raw={"ip": ip, "asn": asn, "org": org},
                ))

        except Exception:
            pass
        return findings

    async def _bgpview_lookup(self, ip: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://api.bgpview.io/ip/{ip}"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            ip_data = data.get("data", {})
            if not ip_data:
                return findings

            prefixes = ip_data.get("prefixes", [])
            for prefix_entry in prefixes:
                prefix_data = prefix_entry.get("prefix", "")
                prefix = prefix_data if isinstance(prefix_data, str) else str(prefix_data)
                asn_entry = prefix_entry.get("asn", {})
                asn_number = asn_entry.get("asn", "") if isinstance(asn_entry, dict) else ""
                asn_name = asn_entry.get("name", "") if isinstance(asn_entry, dict) else ""
                asn_desc = asn_entry.get("description", "") if isinstance(asn_entry, dict) else ""

                findings.append(Finding(
                    source=self.name,
                    type="asn_info",
                    value=prefix,
                    context=f"BGP prefix for {ip}: AS{asn_number} ({asn_name})",
                    url_found_on=url,
                    severity="info",
                    confidence=0.85,
                    raw={
                        "ip": ip,
                        "prefix": prefix,
                        "asn": asn_number,
                        "asn_name": asn_name,
                        "asn_description": asn_desc,
                        "source": "bgpview",
                    },
                ))

        except Exception:
            pass
        return findings

    async def _bgpview_ip_lookup(self, ip: str, existing: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        asns_seen: set[str] = set()

        for f in existing:
            raw = f.raw or {}
            asn_val = str(raw.get("asn", ""))
            if asn_val:
                asns_seen.add(asn_val)

        for asn in sorted(asns_seen):
            prefixes = await self._bgpview_prefixes(asn, ip)
            findings.extend(prefixes)

        return findings

    async def _bgpview_prefixes(self, asn: str, ip: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            prefix_data = data.get("data", {})
            ipv4_prefixes = prefix_data.get("ipv4_prefixes", [])
            ipv6_prefixes = prefix_data.get("ipv6_prefixes", [])

            for entry in ipv4_prefixes + ipv6_prefixes:
                prefix = entry.get("prefix", "")
                parent = entry.get("parent", {}) if isinstance(entry.get("parent"), dict) else {}
                description = entry.get("description", "")

                if prefix:
                    findings.append(Finding(
                        source=self.name,
                        type="asn_info",
                        value=prefix,
                        context=f"AS{asn} prefix: {description}" if description else f"AS{asn} IP range",
                        url_found_on=url,
                        severity="info",
                        confidence=0.8,
                        raw={
                            "asn": asn,
                            "prefix": prefix,
                            "description": description,
                            "parent_prefix": parent.get("prefix", ""),
                            "source": "bgpview_prefixes",
                        },
                    ))

        except Exception:
            pass
        return findings

    async def _bgphe_scrape(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://bgp.he.net/dns/{domain}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                },
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "lxml")
            raw_text = soup.get_text(" ", strip=True)

            as_patterns = [
                r"AS(\d+)\s",
                r"ASN:\s*(\d+)",
                r"AS\s*(\d+)",
            ]
            asns_found: set[str] = set()
            for pattern in as_patterns:
                for match in re.finditer(pattern, raw_text):
                    asns_found.add(match.group(1))

            for asn in sorted(asns_found):
                findings.append(Finding(
                    source=self.name,
                    type="asn_info",
                    value=f"AS{asn}",
                    context=f"ASN found via bgp.he.net for {domain}",
                    url_found_on=url,
                    severity="info",
                    confidence=0.6,
                    raw={"asn": asn, "domain": domain, "source": "bgphe"},
                ))

        except Exception:
            pass
        return findings


@celery_app.task(name="dns_infra.asn_enum")
def run_asn_enum_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = ASNEnumModule()
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
