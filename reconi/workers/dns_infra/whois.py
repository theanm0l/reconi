"""WhoIs lookup module — domain registration details, history, and contacts."""
import asyncio
import os
import re
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


class WhoisModule(ReconModule):
    name = "whois"
    category = "dns_infra"
    description = "Retrieve WHOIS registration details, contacts, and history for a domain"
    requires_api_key = False
    rate_limit_delay = 2.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        api_key = os.environ.get("WHOISXML_API_KEY", "")

        try:
            if api_key:
                findings.extend(await self._whoisxml_lookup(domain, api_key))
                findings.extend(await self._whois_history(domain, api_key))
            else:
                findings.extend(await self._scrape_whois(domain))
        except Exception as e:
            findings.append(Finding(
                source=self.name,
                type="error",
                value=str(e),
                severity="info",
                confidence=0.0,
            ))

        return findings

    async def _whoisxml_lookup(self, domain: str, api_key: str) -> list[Finding]:
        findings: list[Finding] = []
        url = (
            "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            f"?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
        )
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            whois_record = data.get("WhoisRecord", {})
            if not whois_record:
                return findings

            registrant = whois_record.get("registrant", {}) or {}
            administrative = whois_record.get("administrativeContact", {}) or {}
            technical = whois_record.get("technicalContact", {}) or {}

            org = whois_record.get("registrarName", "")
            reg_details = {
                "domain": domain,
                "registrar": org,
                "created_date": whois_record.get("createdDate", ""),
                "expires_date": whois_record.get("expiresDate", ""),
                "updated_date": whois_record.get("updatedDate", ""),
                "nameservers": whois_record.get("nameServers", {}).get("hostNames", [])
                if isinstance(whois_record.get("nameServers"), dict)
                else [],
                "registrant_name": registrant.get("name", ""),
                "registrant_org": registrant.get("organization", ""),
                "registrant_email": registrant.get("email", ""),
                "registrant_phone": registrant.get("telephone", ""),
                "registrant_address": ", ".join(
                    filter(None, [
                        registrant.get("street1", ""),
                        registrant.get("city", ""),
                        registrant.get("state", ""),
                        registrant.get("postalCode", ""),
                        registrant.get("country", ""),
                    ])
                ),
                "admin_name": administrative.get("name", ""),
                "admin_email": administrative.get("email", ""),
                "tech_name": technical.get("name", ""),
                "tech_email": technical.get("email", ""),
                "status": whois_record.get("status", ""),
                "raw_text": whois_record.get("rawText", ""),
            }

            context_parts = []
            if reg_details["registrant_name"]:
                context_parts.append(f"Registrant: {reg_details['registrant_name']}")
            if reg_details["registrant_org"]:
                context_parts.append(f"Org: {reg_details['registrant_org']}")
            if reg_details["registrar"]:
                context_parts.append(f"Registrar: {reg_details['registrar']}")
            if reg_details["created_date"]:
                context_parts.append(f"Created: {reg_details['created_date']}")
            if reg_details["expires_date"]:
                context_parts.append(f"Expires: {reg_details['expires_date']}")

            findings.append(Finding(
                source=self.name,
                type="whois_info",
                value=domain,
                context=" | ".join(context_parts) if context_parts else f"WHOIS data for {domain}",
                url_found_on=url,
                severity="info",
                confidence=0.9,
                raw=reg_details,
            ))

            if reg_details["registrant_email"]:
                findings.append(Finding(
                    source=self.name,
                    type="whois_info",
                    value=reg_details["registrant_email"],
                    context=f"Registrant email for {domain} ({reg_details['registrant_name']})",
                    severity="info",
                    confidence=0.85,
                    raw={"type": "registrant_email", "domain": domain},
                ))

            for ns in reg_details["nameservers"]:
                if ns:
                    findings.append(Finding(
                        source=self.name,
                        type="dns_record",
                        value=ns,
                        context=f"Nameserver for {domain}",
                        severity="info",
                        confidence=0.9,
                        raw={"type": "nameserver", "domain": domain},
                    ))

        except Exception as e:
            findings.append(Finding(
                source=self.name,
                type="error",
                value=f"WHOISXML API error: {e}",
                severity="info",
                confidence=0.0,
            ))

        return findings

    async def _whois_history(self, domain: str, api_key: str) -> list[Finding]:
        findings: list[Finding] = []
        url = (
            "https://whois-history.whoisxmlapi.com/api/v1"
            f"?apiKey={api_key}&domainName={domain}"
        )
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            records = data.get("WhoisHistory", [])
            for record in records[:10]:
                reg_name = record.get("registrant", {}).get("name", "") if isinstance(record.get("registrant"), dict) else ""
                record_date = record.get("createdDate", "")
                findings.append(Finding(
                    source=self.name,
                    type="whois_info",
                    value=domain,
                    context=f"WHOIS history record ({record_date}): {reg_name}",
                    severity="info",
                    confidence=0.7,
                    raw={"type": "whois_history", "domain": domain, "record": record},
                ))

        except Exception:
            pass

        return findings

    async def _scrape_whois(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://www.whois.com/whois/{domain}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "lxml")
            raw_text = soup.get_text("\n", strip=True)

            reg_details: dict = {"domain": domain, "raw_text": raw_text[:5000]}

            patterns = {
                "registrar": r"Registrar:\s*(.+)",
                "creation_date": r"Creation Date:\s*(.+)",
                "expiry_date": r"(?:Registry Expiry Date|Expiry Date):\s*(.+)",
                "registrant_name": r"Registrant Name:\s*(.+)",
                "registrant_org": r"Registrant Organization:\s*(.+)",
                "registrant_email": r"Registrant Email:\s*(.+)",
                "registrant_phone": r"Registrant Phone:\s*(.+)",
                "admin_name": r"Admin Name:\s*(.+)",
                "admin_email": r"Admin Email:\s*(.+)",
                "name_server": r"Name Server:\s*(.+)",
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, raw_text, re.IGNORECASE)
                if match:
                    reg_details[key] = match.group(1).strip()

            nameservers = set()
            for match in re.finditer(r"Name Server:\s*(.+)", raw_text, re.IGNORECASE):
                nameservers.add(match.group(1).strip().lower())
            nameservers.update(
                m.group(1).strip().lower()
                for m in re.finditer(r"nserver:\s*(.+)", raw_text, re.IGNORECASE)
            )
            reg_details["nameservers"] = sorted(nameservers)

            context_parts = []
            if reg_details.get("registrant_name"):
                context_parts.append(f"Registrant: {reg_details['registrant_name']}")
            if reg_details.get("registrant_org"):
                context_parts.append(f"Org: {reg_details['registrant_org']}")
            if reg_details.get("registrar"):
                context_parts.append(f"Registrar: {reg_details['registrar']}")
            if reg_details.get("creation_date"):
                context_parts.append(f"Created: {reg_details['creation_date']}")
            if reg_details.get("expiry_date"):
                context_parts.append(f"Expires: {reg_details['expiry_date']}")

            findings.append(Finding(
                source=self.name,
                type="whois_info",
                value=domain,
                context=" | ".join(context_parts) if context_parts else f"WHOIS data for {domain} (scraped)",
                url_found_on=url,
                severity="info",
                confidence=0.6,
                raw=reg_details,
            ))

            if reg_details.get("registrant_email"):
                findings.append(Finding(
                    source=self.name,
                    type="whois_info",
                    value=reg_details["registrant_email"],
                    context=f"Registrant email for {domain} ({reg_details.get('registrant_name', '')})",
                    severity="info",
                    confidence=0.5,
                    raw={"type": "registrant_email", "domain": domain},
                ))

            for ns in reg_details.get("nameservers", []):
                if ns:
                    findings.append(Finding(
                        source=self.name,
                        type="dns_record",
                        value=ns,
                        context=f"Nameserver for {domain}",
                        severity="info",
                        confidence=0.6,
                        raw={"type": "nameserver", "domain": domain},
                    ))

        except Exception as e:
            findings.append(Finding(
                source=self.name,
                type="error",
                value=f"WHOIS scrape error: {e}",
                severity="info",
                confidence=0.0,
            ))

        return findings


@celery_app.task(name="dns_infra.whois")
def run_whois_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = WhoisModule()
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
