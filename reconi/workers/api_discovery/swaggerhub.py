"""SwaggerHub — discover OpenAPI specs for a domain."""
import asyncio
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class SwaggerHubModule(ReconModule):
    name = "swaggerhub"
    category = "api_discovery"
    description = "Search SwaggerHub for public OpenAPI/Swagger specifications matching the target domain"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            search_url = f"https://api.swaggerhub.com/apis?query={domain}&limit=50&sort=UPDATED"
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()

            apis = data.get("apis", []) if isinstance(data, dict) else data
            if not isinstance(apis, list):
                apis = []

            for api in apis:
                name = api.get("name", "")
                description = api.get("description", "")
                owner = api.get("owner", "")
                versions = api.get("versions", [])
                swagger_url = api.get("swaggerUrl", "")
                swagger_urls = api.get("swaggerUrls", [])

                all_urls = []
                if swagger_url:
                    all_urls.append(swagger_url)
                if swagger_urls:
                    all_urls.extend(swagger_urls)

                if not all_urls:
                    findings.append(Finding(
                        source=self.name,
                        type="swagger_spec",
                        value=f"https://app.swaggerhub.com/apis/{owner}/{name}" if owner and name else name,
                        context=f"Description: {description}, Versions: {', '.join(v.get('version', '') for v in versions)}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.7,
                        raw=api,
                    ))
                    continue

                for spec_url in all_urls:
                    try:
                        spec_resp = await client.get(spec_url)
                        spec_resp.raise_for_status()
                        spec = spec_resp.json()

                        endpoints = _extract_endpoints(spec)
                        findings.append(Finding(
                            source=self.name,
                            type="swagger_spec",
                            value=spec_url,
                            context="\n".join(endpoints[:100]) if endpoints else f"Spec for {name} by {owner}",
                            url_found_on=spec_url,
                            severity="info",
                            confidence=0.85,
                            raw=spec,
                        ))
                        await asyncio.sleep(0.3)
                    except Exception:
                        findings.append(Finding(
                            source=self.name,
                            type="swagger_spec",
                            value=spec_url,
                            context=f"Name: {name}, Owner: {owner}, Description: {description}",
                            url_found_on=search_url,
                            severity="info",
                            confidence=0.6,
                        ))

        except Exception as e:
            findings.append(Finding(
                source=self.name,
                type="error",
                value=str(e),
                severity="info",
                confidence=0.0,
            ))

        return findings


def _extract_endpoints(spec: dict) -> list[str]:
    endpoints = []
    base_url = ""
    if "servers" in spec:
        base_url = spec["servers"][0]["url"].rstrip("/") if spec["servers"] else ""
    elif "host" in spec:
        scheme = spec.get("schemes", ["https"])[0]
        base_path = spec.get("basePath", "")
        base_url = f"{scheme}://{spec['host']}{base_path}"

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method in methods:
            if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                endpoints.append(f"{method.upper()} {base_url}{path}")

    return endpoints


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="api_discovery.swaggerhub")
def run_swaggerhub_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = SwaggerHubModule()
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
