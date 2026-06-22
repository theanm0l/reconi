"""Postman API — search and fetch collections for a domain."""
import asyncio
import os
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

POSTMAN_API_KEY = os.environ.get("POSTMAN_API_KEY", "")


class PostmanApiModule(ReconModule):
    name = "postman_api"
    category = "api_discovery"
    description = "Search Postman for public collections and APIs matching the target domain"
    requires_api_key = bool(POSTMAN_API_KEY)
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            search_url = f"https://www.postman.com/_api/ws/search-all?queryText={domain}&size=30&from=0"
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()

            items = data.get("data", {}).get("collections", [])
            items += data.get("data", {}).get("apis", [])
            items += data.get("data", {}).get("workspaces", [])

            for item in items:
                uid = item.get("uid") or item.get("id")
                name = item.get("name", "")
                publisher = item.get("publisher", {}).get("handle") or item.get("publisherHandle", "")
                entity_type = item.get("entityType", item.get("type", ""))

                if not uid:
                    findings.append(Finding(
                        source=self.name,
                        type="postman_collection",
                        value=name,
                        context=f"Publisher: {publisher}, Type: {entity_type}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.6,
                    ))
                    continue

                collection_url = f"https://www.postman.com/collections/{uid}"

                try:
                    detail_url = collection_url
                    detail_headers = {}
                    if POSTMAN_API_KEY:
                        detail_url = f"https://api.getpostman.com/collections/{uid}"
                        detail_headers["X-API-Key"] = POSTMAN_API_KEY

                    detail_resp = await client.get(detail_url, headers=detail_headers)
                    detail_resp.raise_for_status()
                    detail_data = detail_resp.json()

                    endpoints = []
                    if "collection" in detail_data:
                        collection = detail_data["collection"]
                        collection_name = collection.get("info", {}).get("name", name)
                        for item in _flatten_items(collection.get("item", [])):
                            request = item.get("request", {})
                            method = request.get("method", "GET")
                            url_obj = request.get("url", {})
                            raw_url = url_obj.get("raw", "") if isinstance(url_obj, dict) else str(url_obj)
                            if raw_url:
                                endpoints.append(f"{method} {raw_url}")
                            if "name" in item:
                                endpoints.append(f"[{item['name']}] {method} {raw_url}")

                        findings.append(Finding(
                            source=self.name,
                            type="postman_collection",
                            value=collection_name or name,
                            context="\n".join(endpoints[:50]) if endpoints else f"UID: {uid}, Publisher: {publisher}",
                            url_found_on=collection_url,
                            severity="info",
                            confidence=0.8,
                            raw=detail_data,
                        ))
                        await asyncio.sleep(0.5)

                except Exception:
                    findings.append(Finding(
                        source=self.name,
                        type="postman_collection",
                        value=name,
                        context=f"UID: {uid}, Publisher: {publisher}, URL: {collection_url}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.5,
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


def _flatten_items(items: list) -> list:
    result = []
    for item in items:
        if "item" in item:
            result.extend(_flatten_items(item.get("item", [])))
        if "request" in item:
            result.append(item)
    return result


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="api_discovery.postman_api")
def run_postman_api_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = PostmanApiModule()
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
