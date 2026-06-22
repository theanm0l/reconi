"""SPF & DMARC analysis module — email security configuration and misconfiguration detection."""
import asyncio
import re
from urllib.parse import urlparse

import httpx

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

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


KNOWN_EMAIL_SERVICES = {
    "sendgrid": "sendgrid",
    "mailgun": "mailgun",
    "office365": "office365 / Exchange Online",
    "outlook": "office365 / Exchange Online",
    "google": "Google Workspace / Gmail",
    "_spf.google.com": "Google Workspace / Gmail",
    "googlemail": "Google Workspace / Gmail",
    "sparkpost": "SparkPost",
    "mailchimp": "Mailchimp / Mandrill",
    "mandrill": "Mailchimp / Mandrill",
    "amazonses": "Amazon SES",
    "zendesk": "Zendesk",
    "zoho": "Zoho Mail",
    "mailjet": "Mailjet",
    "postmark": "Postmark",
    "spf.protection.outlook.com": "Office365",
    "sendinblue": "Sendinblue / Brevo",
    "hubspot": "HubSpot",
    "salesforce": "Salesforce",
    "mailerlite": "MailerLite",
    "activecampaign": "ActiveCampaign",
    "convertkit": "ConvertKit",
    "klaviyo": "Klaviyo",
    "constantcontact": "Constant Contact",
    "mailpoet": "MailPoet",
    "aweber": "AWeber",
    "getresponse": "GetResponse",
}


class SPFDmarcModule(ReconModule):
    name = "spf_dmarc"
    category = "dns_infra"
    description = "Analyze SPF and DMARC DNS records for email security posture and misconfigurations"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        if not HAS_DNSPYTHON:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="dnspython not installed — required for SPF/DMARC TXT record lookups",
                severity="warning",
                confidence=1.0,
            ))
            return findings

        findings.extend(await self._analyze_spf(domain))
        findings.extend(await self._analyze_dmarc(domain))
        return findings

    async def _resolve_txt(self, name: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT")
            return ["".join(s.decode("utf-8") if isinstance(s, bytes) else s for s in r.strings) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return []

    async def _analyze_spf(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            records = await self._resolve_txt(domain)
        except Exception:
            records = []

        spf_records = [r for r in records if "v=spf1" in r]

        if not spf_records:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=domain,
                context="No SPF record found — domain may be vulnerable to email spoofing",
                severity="high",
                confidence=0.9,
                raw={"domain": domain, "record_type": "SPF", "issue": "missing_spf"},
            ))
            return findings

        for spf in spf_records:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=spf,
                context=f"SPF record for {domain}",
                severity="info",
                confidence=1.0,
                raw={"domain": domain, "record_type": "SPF", "raw_record": spf},
            ))

            parsed = self._parse_spf(spf, domain)
            findings.extend(parsed)

        return findings

    def _parse_spf(self, spf_record: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        mechanisms = spf_record.lower().split()

        includes = []
        ip4_ranges = []
        ip6_ranges = []
        mx = False
        a_mechanism = False
        redirect = None
        has_all = False
        all_mechanism = None

        for mech in mechanisms:
            if mech == "v=spf1":
                continue
            if mech.startswith("include:"):
                included = mech[len("include:"):]
                includes.append(included)
                for svc_key, svc_label in KNOWN_EMAIL_SERVICES.items():
                    if svc_key in included.lower():
                        findings.append(Finding(
                            source=self.name,
                            type="dns_record",
                            value=included,
                            context=f"Email service detected via SPF include: {svc_label}",
                            severity="info",
                            confidence=0.8,
                            raw={
                                "domain": domain,
                                "record_type": "SPF",
                                "service": svc_label,
                                "include": included,
                            },
                        ))
            elif mech.startswith("ip4:"):
                ip4_ranges.append(mech[len("ip4:"):])
            elif mech.startswith("ip6:"):
                ip6_ranges.append(mech[len("ip6:"):])
            elif mech == "mx":
                mx = True
            elif mech == "a":
                a_mechanism = True
            elif mech.startswith("redirect="):
                redirect = mech[len("redirect="):]
                findings.append(Finding(
                    source=self.name,
                    type="dns_record",
                    value=redirect,
                    context=f"SPF redirect to {redirect} for {domain}",
                    severity="info",
                    confidence=0.8,
                    raw={"domain": domain, "record_type": "SPF", "redirect": redirect},
                ))
            elif mech in ("+all", "all"):
                has_all = True
                all_mechanism = mech
            elif mech in ("~all", "-all", "?all"):
                has_all = True
                all_mechanism = mech

        if ip4_ranges:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=", ".join(ip4_ranges),
                context=f"SPF authorized IPv4 ranges for {domain}",
                severity="info",
                confidence=0.9,
                raw={"domain": domain, "record_type": "SPF", "ip4": ip4_ranges},
            ))

        if ip6_ranges:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=", ".join(ip6_ranges),
                context=f"SPF authorized IPv6 ranges for {domain}",
                severity="info",
                confidence=0.9,
                raw={"domain": domain, "record_type": "SPF", "ip6": ip6_ranges},
            ))

        if all_mechanism == "+all" or all_mechanism == "all":
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=all_mechanism,
                context=f"SPF misconfiguration: '{all_mechanism}' allows ALL senders — email spoofing possible",
                severity="critical",
                confidence=1.0,
                raw={
                    "domain": domain,
                    "record_type": "SPF",
                    "issue": "allow_all",
                    "mechanism": all_mechanism,
                },
            ))
        elif not has_all:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=spf_record,
                context="SPF record missing 'all' mechanism — behavior depends on receiver policy",
                severity="medium",
                confidence=0.9,
                raw={
                    "domain": domain,
                    "record_type": "SPF",
                    "issue": "missing_all_mechanism",
                },
            ))
        elif all_mechanism == "?all":
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=all_mechanism,
                context="SPF uses '?all' (neutral) — does not protect against email spoofing",
                severity="medium",
                confidence=1.0,
                raw={
                    "domain": domain,
                    "record_type": "SPF",
                    "issue": "neutral_all",
                    "mechanism": all_mechanism,
                },
            ))

        return findings

    async def _analyze_dmarc(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"

        try:
            records = await self._resolve_txt(dmarc_domain)
        except Exception:
            records = []

        dmarc_records = [r for r in records if "v=DMARC1" in r]

        if not dmarc_records:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=dmarc_domain,
                context="No DMARC record found — domain vulnerable to email spoofing and brand impersonation",
                severity="high",
                confidence=0.95,
                raw={"domain": domain, "record_type": "DMARC", "issue": "missing_dmarc"},
            ))
            return findings

        for record in dmarc_records:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=record,
                context=f"DMARC record for {domain}",
                severity="info",
                confidence=1.0,
                raw={"domain": domain, "record_type": "DMARC", "raw_record": record},
            ))

            parsed = self._parse_dmarc(record, domain)
            findings.extend(parsed)

        return findings

    def _parse_dmarc(self, dmarc_record: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []

        tags = {}
        for part in dmarc_record.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip().lower()] = value.strip()

        policy = tags.get("p", "")
        pct = tags.get("pct", "100")
        rua = tags.get("rua", "")
        ruf = tags.get("ruf", "")
        sp = tags.get("sp", "")
        fo = tags.get("fo", "")

        if policy == "none":
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=f"p={policy}",
                context=f"Weak DMARC policy: p=none — no enforcement, spoofing emails pass through",
                severity="high",
                confidence=1.0,
                raw={
                    "domain": domain,
                    "record_type": "DMARC",
                    "issue": "weak_policy_none",
                    "policy": policy,
                },
            ))
        elif policy == "quarantine":
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=f"p={policy}",
                context=f"DMARC policy: quarantine — suspicious emails sent to spam",
                severity="low",
                confidence=1.0,
                raw={"domain": domain, "record_type": "DMARC", "policy": policy},
            ))
        elif policy == "reject":
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=f"p={policy}",
                context=f"DMARC policy: reject — strong protection against spoofing",
                severity="info",
                confidence=1.0,
                raw={"domain": domain, "record_type": "DMARC", "policy": policy},
            ))

        if int(pct) < 100:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=f"pct={pct}",
                context=f"DMARC only applies to {pct}% of email — inconsistent enforcement",
                severity="medium",
                confidence=1.0,
                raw={
                    "domain": domain,
                    "record_type": "DMARC",
                    "issue": "partial_enforcement",
                    "pct": pct,
                },
            ))

        if rua:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=rua,
                context=f"DMARC aggregate reports sent to: {rua}",
                severity="info",
                confidence=0.9,
                raw={"domain": domain, "record_type": "DMARC", "rua": rua},
            ))

        if ruf:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=ruf,
                context=f"DMARC forensic reports sent to: {ruf}",
                severity="info",
                confidence=0.9,
                raw={"domain": domain, "record_type": "DMARC", "ruf": ruf},
            ))

        if sp:
            findings.append(Finding(
                source=self.name,
                type="dns_record",
                value=f"sp={sp}",
                context=f"DMARC subdomain policy: {sp}",
                severity="info",
                confidence=0.9,
                raw={"domain": domain, "record_type": "DMARC", "sp": sp},
            ))

        return findings


@celery_app.task(name="dns_infra.spf_dmarc")
def run_spf_dmarc_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = SPFDmarcModule()
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
