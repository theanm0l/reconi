"""GraphQL Introspection — probe common GraphQL endpoints with introspection queries."""
import asyncio
import json
from urllib.parse import urljoin, urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
    "/graphql/v1",
    "/api/gql",
    "/graphiql",
    "/playground",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "query IntrospectionQuery { __schema { types { name fields { name } } queryType { name fields { name } } mutationType { name fields { name } } subscriptionType { name fields { name } } } }"
})

INTROSPECTION_QUERY_SHORT = '{"query":"{__schema{queryType{name fields{name}}mutationType{name fields{name}}}}"}'


class GraphQLIntrospectModule(ReconModule):
    name = "graphql_introspect"
    category = "api_discovery"
    description = "Probe common GraphQL endpoints on the target for introspection capabilities"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        base_url = _normalize_target(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(15), follow_redirects=True) as client:
            for path in GRAPHQL_PATHS:
                url = urljoin(base_url, path)
                await _probe_endpoint(client, url, findings)

        return findings


async def _probe_endpoint(client: httpx.AsyncClient, url: str, findings: list[Finding]) -> None:
    module_name = "graphql_introspect"

    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        resp = await client.post(url, content=INTROSPECTION_QUERY, headers=headers)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    query_names = _extract_operation_names(data)
                    findings.append(Finding(
                        source=module_name,
                        type="graphql_endpoint",
                        value=url,
                        context=", ".join(query_names[:50]) if query_names else "GraphQL endpoint with introspection enabled",
                        url_found_on=url,
                        severity="info",
                        confidence=0.9,
                        raw=data,
                    ))
                    return
            except (json.JSONDecodeError, KeyError):
                pass

        resp2 = await client.post(url, content=INTROSPECTION_QUERY_SHORT, headers=headers)
        if resp2.status_code == 200:
            try:
                data2 = resp2.json()
                if "data" in data2:
                    query_names = _extract_operation_names(data2)
                    findings.append(Finding(
                        source=module_name,
                        type="graphql_endpoint",
                        value=url,
                        context=", ".join(query_names[:50]) if query_names else "GraphQL endpoint with introspection enabled",
                        url_found_on=url,
                        severity="info",
                        confidence=0.85,
                        raw=data2,
                    ))
                    return
            except (json.JSONDecodeError, KeyError):
                pass

        app_graphql_headers = {
            "Content-Type": "application/graphql",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        app_query = "{__schema{queryType{name}}}"
        resp3 = await client.post(url, content=app_query, headers=app_graphql_headers)
        if resp3.status_code == 200:
            try:
                data3 = resp3.json()
                if "data" in data3 and "__schema" in data3.get("data", {}):
                    findings.append(Finding(
                        source=module_name,
                        type="graphql_endpoint",
                        value=url,
                        context="GraphQL endpoint with introspection enabled (application/graphql)",
                        url_found_on=url,
                        severity="info",
                        confidence=0.8,
                        raw=data3,
                    ))
                    return
            except (json.JSONDecodeError, KeyError):
                pass

        if resp.status_code == 405 or resp.status_code == 400:
            resp_get = await client.get(url, headers={"Accept": "application/json"})
            if resp_get.status_code == 200 and "GraphQL" in resp_get.text[:500]:
                findings.append(Finding(
                    source=module_name,
                    type="graphql_endpoint",
                    value=url,
                    context="Possible GraphQL endpoint (GET response hints at GraphQL)",
                    url_found_on=url,
                    severity="info",
                    confidence=0.4,
                ))

    except Exception:
        pass


def _extract_operation_names(data: dict) -> list[str]:
    names = []
    schema = data.get("data", {}).get("__schema", {})
    for key in ("queryType", "mutationType", "subscriptionType"):
        type_info = schema.get(key)
        if type_info and isinstance(type_info, dict):
            op_name = type_info.get("name", "")
            fields = type_info.get("fields", [])
            if fields is None:
                fields = []
            field_names = [f.get("name", "") for f in fields if f and isinstance(f, dict)]
            if op_name:
                names.append(f"{key.replace('Type', '')}({op_name}): [{', '.join(field_names[:20])}]")
    return names


def _normalize_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{target}"


@celery_app.task(name="api_discovery.graphql_introspect")
def run_graphql_introspect_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GraphQLIntrospectModule()
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
