"""CNAME analysis module — detect subdomain takeover vulnerabilities via CNAME record inspection."""
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


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "cdn", "api", "admin", "dev", "staging",
    "test", "blog", "shop", "app", "portal", "dashboard",
]

TAKEOVER_SERVICES = {
    "amazonaws.com": ("AWS S3/CloudFront", "https://{value}.s3.amazonaws.com"),
    "cloudfront.net": ("AWS CloudFront", "https://{value}"),
    "github.io": ("GitHub Pages", "https://{value}"),
    "azurewebsites.net": ("Azure App Service", "https://{value}"),
    "herokuapp.com": ("Heroku", "https://{value}"),
    "surge.sh": ("Surge.sh", "https://{value}"),
    "bitbucket.io": ("Bitbucket Pages", "https://{value}"),
    "fastly.net": ("Fastly CDN", "https://{value}"),
    "shopify.com": ("Shopify", "https://{value}"),
    "zendesk.com": ("Zendesk", "https://{value}"),
    "readme.io": ("ReadMe Docs", "https://{value}"),
    "cargocollective.com": ("Cargo Collective", "https://{value}"),
}


class CnameAnalysisModule(ReconModule):
    name = "cname_analysis"
    category = "dns_infra"
    description = "Check CNAME records for subdomain takeover vulnerabilities against known services"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        if not HAS_DNSPYTHON:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="dnspython not installed — required for CNAME record lookups",
                severity="warning",
                confidence=1.0,
            ))
            return findings

        subdomains = COMMON_SUBDOMAINS
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            findings.extend(await self._check_subdomain_cname(fqdn, domain))

        return findings

    async def _resolve_cname(self, fqdn: str) -> str | None:
        try:
            answers = dns.resolver.resolve(fqdn, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
                return cname.lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        return None

    async def _check_subdomain_cname(self, fqdn: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []

        cname = await self._resolve_cname(fqdn)
        if not cname:
            return findings

        findings.append(Finding(
            source=self.name,
            type="dns_record",
            value=cname,
            context=f"CNAME record for {fqdn} points to {cname}",
            severity="info",
            confidence=1.0,
            raw={"fqdn": fqdn, "cname": cname, "domain": domain},
        ))

        for service_domain, (service_name, check_url_template) in TAKEOVER_SERVICES.items():
            if not cname.endswith(f".{service_domain}") and cname != service_domain:
                continue

            is_vulnerable = False
            evidence = ""

            try:
                check_url = check_url_template.format(value=cname)
                evidence, is_vulnerable = await self._check_takeover(cname, check_url, service_name)
            except Exception:
                pass

            severity = "critical" if is_vulnerable else "high"
            confidence = 0.9 if is_vulnerable else 0.5
            context = (
                f"Potential {service_name} takeover: {fqdn} -> {cname}"
                if not is_vulnerable
                else f"VULNERABLE to {service_name} takeover: {fqdn} -> {cname} — {evidence}"
            )

            findings.append(Finding(
                source=self.name,
                type="cname_takeover",
                value=f"{fqdn} -> {cname}",
                context=context,
                severity=severity,
                confidence=confidence,
                raw={
                    "fqdn": fqdn,
                    "cname": cname,
                    "service": service_name,
                    "vulnerable": is_vulnerable,
                    "evidence": evidence,
                },
            ))

        return findings

    async def _check_takeover(self, cname: str, check_url: str, service: str) -> tuple[str, bool]:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10),
                headers={"User-Agent": "Reconi/1.0 SubdomainTakeoverCheck"},
                follow_redirects=False,
            ) as client:
                resp = await client.get(check_url)

            status = resp.status_code
            text = (resp.text or "").lower()
            headers = resp.headers

            indicators: list[tuple[str, list[str], str]] = []
            if service == "AWS S3/CloudFront":
                indicators = [
                    ("NoSuchBucket", ["nosuchbucket"], "S3 bucket does not exist"),
                    ("404 Not Found", ["code: nosuchbucket", "not found"], "CloudFront distribution unavailable"),
                ]
            elif service == "GitHub Pages":
                indicators = [
                    ("404", ["there isn't a github pages site here", "site not found"], "GitHub Pages site not claimed"),
                ]
            elif service == "Azure App Service":
                indicators = [
                    ("404", ["site not found", "web app not found"], "Azure Web App not found"),
                ]
            elif service == "Heroku":
                indicators = [
                    ("404", ["no such app"], "Heroku app does not exist"),
                ]
            elif service == "Surge.sh":
                indicators = [
                    ("404", ["not found", "project not found"], "Surge project not found"),
                ]
            elif service == "Bitbucket Pages":
                indicators = [
                    ("404", ["repository not found", "no workspace"], "Bitbucket repo not found"),
                ]
            elif service == "Fastly CDN":
                indicators = [
                    ("500", ["fastly error: unknown domain"], "Fastly domain not configured"),
                ]
            elif service in ("Shopify", "Zendesk", "ReadMe Docs", "Cargo Collective"):
                indicators = [
                    ("404", ["not found", "does not exist", "no such"], f"{service} resource not found"),
                ]

            for status_code, substrings, evidence_text in indicators:
                if status == int(status_code) or any(s in text for s in substrings):
                    return evidence_text, True

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return "Service returns 404 — likely unclaimed", True
        except Exception:
            pass

        return "", False


@celery_app.task(name="dns_infra.cname_analysis")
def run_cname_analysis_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = CnameAnalysisModule()
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
