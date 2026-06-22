"""WSDL Discovery — probe and parse WSDL/SOAP endpoints on the target."""
import asyncio
from urllib.parse import urljoin, urlparse

import httpx
from lxml import etree

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

WSDL_PATHS = [
    "/service?wsdl",
    "/api?wsdl",
    "/soap?wsdl",
    "/webservice?wsdl",
    "/services?wsdl",
    "/Service?wsdl",
    "/WebService?wsdl",
    "/ws?wsdl",
    "/v1/soap?wsdl",
    "/v1/service?wsdl",
    "/wsdl",
    "/services/Soap?wsdl",
]

WSDL_NAMESPACES = {
    "wsdl": "http://schemas.xmlsoap.org/wsdl/",
    "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
    "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "tns": None,
}


class WsdlDiscoverModule(ReconModule):
    name = "wsdl_discover"
    category = "api_discovery"
    description = "Probe common WSDL/SOAP endpoints on the target and parse service metadata"
    requires_api_key = False
    rate_limit_delay = 0.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        base_url = _normalize_target(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(15), follow_redirects=True) as client:
            for path in WSDL_PATHS:
                url = urljoin(base_url, path)
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue

                    text = resp.text
                    if "wsdl" not in text.lower() and "definitions" not in text.lower():
                        continue

                    finding = _parse_wsdl(text, url)
                    if finding:
                        findings.append(finding)
                        await asyncio.sleep(0.3)

                except Exception:
                    pass

            robots_url = urljoin(base_url, "/robots.txt")
            try:
                robots_resp = await client.get(robots_url)
                if robots_resp.status_code == 200:
                    for line in robots_resp.text.splitlines():
                        line = line.strip()
                        if ".wsdl" in line.lower() or "?wsdl" in line.lower():
                            wsdl_path = line.split(":", 1)[-1].strip() if ":" in line else line
                            if wsdl_path.startswith("/"):
                                wsdl_url = urljoin(base_url, wsdl_path)
                                findings.append(Finding(
                                    source=self.name,
                                    type="wsdl_endpoint",
                                    value=wsdl_url,
                                    context="WSDL path found in robots.txt",
                                    url_found_on=robots_url,
                                    severity="info",
                                    confidence=0.5,
                                ))
            except Exception:
                pass

        return findings


def _parse_wsdl(xml_text: str, url: str) -> Finding | None:
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return None

    nsmap = dict(root.nsmap)
    wsdl_ns = None
    for prefix, uri in nsmap.items():
        if uri and "wsdl" in uri.lower():
            wsdl_ns = uri
            break

    if wsdl_ns is None:
        wsdl_ns = "http://schemas.xmlsoap.org/wsdl/"

    ns = {"wsdl": wsdl_ns, "soap": "http://schemas.xmlsoap.org/wsdl/soap/", "xsd": "http://www.w3.org/2001/XMLSchema"}

    service_name = ""
    svc_els = root.findall(".//wsdl:service", ns) or root.findall(".//{*}service")
    for svc in svc_els:
        service_name = svc.get("name", "")

    operations = []
    op_els = (
        root.findall(".//wsdl:operation", ns)
        or root.findall(".//{*}operation")
    )
    for op in op_els:
        op_name = op.get("name", "")
        input_el = op.find("wsdl:input", ns) or op.find("{*}input")
        output_el = op.find("wsdl:output", ns) or op.find("{*}output")
        input_msg = input_el.get("message", "").split(":")[-1] if input_el is not None else ""
        output_msg = output_el.get("message", "").split(":")[-1] if output_el is not None else ""
        operations.append(f"{op_name}(in={input_msg}, out={output_msg})")

    endpoint_urls = []
    port_els = root.findall(".//wsdl:port", ns) or root.findall(".//{*}port")
    for port in port_els:
        addr = port.find(".//soap:address", ns) or port.find(".//{*}address")
        if addr is not None:
            loc = addr.get("location", "")
            if loc:
                endpoint_urls.append(loc)

    messages = []
    msg_els = root.findall(".//wsdl:message", ns) or root.findall(".//{*}message")
    for msg in msg_els:
        msg_name = msg.get("name", "")
        parts = msg.findall("wsdl:part", ns) or msg.findall("{*}part")
        for part in parts:
            part_name = part.get("name", "")
            part_type = part.get("type", part.get("element", ""))
            if msg_name and part_name:
                messages.append(f"{msg_name}.{part_name}: {part_type}")

    context_parts = []
    if service_name:
        context_parts.append(f"Service: {service_name}")
    if operations:
        context_parts.append("Operations: " + "; ".join(operations[:30]))
    if endpoint_urls:
        context_parts.append("Endpoints: " + ", ".join(endpoint_urls[:10]))
    if messages:
        context_parts.append("Messages: " + "; ".join(messages[:20]))

    return Finding(
        source="wsdl_discover",
        type="wsdl_endpoint",
        value=url,
        context="\n".join(context_parts) if context_parts else "WSDL endpoint found",
        url_found_on=url,
        severity="info",
        confidence=0.85 if operations else 0.6,
    )


def _normalize_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{target}"


@celery_app.task(name="api_discovery.wsdl_discover")
def run_wsdl_discover_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = WsdlDiscoverModule()
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
