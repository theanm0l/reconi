"""AI-powered analysis pipeline: triage, classification, validation, correlation, and reporting."""

import asyncio
import json
import logging
from typing import Any

from openai import AsyncOpenAI

from ..core.celery_app import celery_app
from ..core.config import settings
from ..core.database import SessionLocal, Finding as DBFinding, ReconJob
from ..core.plugin import Finding

logger = logging.getLogger(__name__)

MAX_BATCH_SIZE = 25

TRIAGE_PROMPT = """You are a security finding triage filter. For each finding below, determine if it contains a REAL secret, credential, sensitive endpoint, or exploitable configuration — or if it is just noise, placeholder, test data, or benign content.

Return ONLY a JSON array of objects, each with:
- "index": the zero-based index of the finding
- "decision": "KEEP" or "DISCARD"
- "reason": brief one-line reason

Findings:
{findings_json}
"""

CLASSIFY_PROMPT = """You are a security findings classifier. For each finding below, classify it precisely.

Return ONLY a JSON array of objects, each with:
- "index": the zero-based index of the finding
- "type": one of [api_key, email, password, endpoint, config_exposure, cloud_storage, cname_takeover, breach_info, code_exposure, secret, other]
- "service": the service provider (aws, github, stripe, google, slack, discord, openai, twilio, mailchimp, heroku, etc.) or "unknown"
- "severity": one of [critical, high, medium, low, info]
- "cwe_id": the most relevant CWE ID (e.g. CWE-798, CWE-200, CWE-522) or null
- "reasoning": brief explanation

Findings:
{findings_json}
"""

VALIDATE_PROMPT = """You are a security findings validator. For each finding below, review the surrounding context and determine whether the finding represents a real, actionable security issue.

Consider:
- Is the key/token likely real or a placeholder/rotated?
- Is the endpoint internal (non-routable) or external?
- Could this lead to actual exploitation?

Return ONLY a JSON array of objects, each with:
- "index": the zero-based index of the finding
- "is_likely_real": true/false
- "confidence_adjustment": float from -0.5 to +0.5
- "notes": brief assessment

Findings:
{findings_json}
"""

CORRELATE_PROMPT = """You are a security findings correlation engine. Review all findings below and identify groups of related findings.

Look for:
- Same credential/key appearing across multiple sources
- Email + password combinations
- Breach data matching credentials
- Related infrastructure findings

Return ONLY a JSON object:
{
  "correlation_groups": [
    {
      "group_name": "descriptive name",
      "member_indices": [0, 3, 7],
      "relationship": "description of how these are related",
      "combined_severity": "critical|high|medium|low|info"
    }
  ]
}

Findings:
{findings_json}
"""

REPORT_PROMPT = """You are a security assessment report generator. Generate a comprehensive Markdown report for the following findings about target: {target}.

Sections to include:
1. Executive Summary (2-3 sentences)
2. Critical Findings (bullet list with details)
3. High Severity Findings
4. Medium Severity Findings
5. Statistics (counts by type, severity, service)
6. Recommendations (actionable remediation steps)
7. Appendix: Full Finding List (table format with index, type, service, severity, value summary)

Keep it professional and concise. Use proper Markdown formatting.

Findings:
{findings_json}
"""


def _get_client(triage: bool = False) -> AsyncOpenAI:
    cfg = settings.config.ai
    provider = cfg.provider
    api_key = cfg.api_key or settings.opencode_go_api_key

    if provider == "opencode-go" and api_key:
        return AsyncOpenAI(
            base_url=cfg.base_url,
            api_key=api_key,
        )

    fallback_host = settings.ollama_host or cfg.fallback_provider
    return AsyncOpenAI(
        base_url=f"{fallback_host}/v1",
        api_key="ollama",
    )


def _findings_to_json(findings: list[dict]) -> str:
    items = []
    for i, f in enumerate(findings):
        items.append({
            "index": i,
            "source": f.get("source", ""),
            "type": f.get("type", ""),
            "value": f.get("value", ""),
            "context": f.get("context", ""),
            "severity": f.get("severity", "info"),
        })
    return json.dumps(items, indent=2)


async def _call_ai(prompt: str, triage: bool = False, max_tokens: int = 4096) -> str:
    cfg = settings.config.ai
    model = cfg.triage_model if triage else cfg.analysis_model

    client = _get_client(triage=triage)
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
        )
        return response.choices[0].message.content or ""
    except Exception:
        logger.warning("Primary AI provider failed, attempting fallback to Ollama")
        fallback_client = AsyncOpenAI(
            base_url=f"{settings.ollama_host}/v1",
            api_key="ollama",
        )
        fallback_model = cfg.fallback_model
        response = await fallback_client.chat.completions.create(
            model=fallback_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
        )
        return response.choices[0].message.content or ""


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return json.loads(text)


async def ai_triage(findings: list[dict]) -> list[dict]:
    if not findings:
        return findings

    kept: list[dict] = []
    for batch_start in range(0, len(findings), MAX_BATCH_SIZE):
        batch = findings[batch_start:batch_start + MAX_BATCH_SIZE]
        prompt = TRIAGE_PROMPT.format(findings_json=_findings_to_json(batch))

        try:
            result_text = await _call_ai(prompt, triage=True)
            decisions = _extract_json(result_text)
            if isinstance(decisions, list):
                for d in decisions:
                    idx = d.get("index", -1)
                    if idx >= 0 and idx < len(batch) and d.get("decision") == "KEEP":
                        batch[idx]["_triage_reason"] = d.get("reason", "")
                        kept.append(batch[idx])
            else:
                kept.extend(batch)
        except Exception as e:
            logger.error("AI triage failed for batch: %s", e)
            kept.extend(batch)

    return kept


async def ai_classify(findings: list[dict]) -> list[dict]:
    if not findings:
        return findings

    for batch_start in range(0, len(findings), MAX_BATCH_SIZE):
        batch = findings[batch_start:batch_start + MAX_BATCH_SIZE]
        batch_indices = list(range(batch_start, batch_start + len(batch)))

        prompt = CLASSIFY_PROMPT.format(findings_json=_findings_to_json(
            [{**f, "_batch_index": i} for i, f in enumerate(batch)]
        ))

        try:
            result_text = await _call_ai(prompt, triage=False)
            classifications = _extract_json(result_text)
            if isinstance(classifications, list):
                for c in classifications:
                    idx = c.get("index", -1)
                    if 0 <= idx < len(batch):
                        batch[idx]["ai_type"] = c.get("type", batch[idx].get("type", "other"))
                        batch[idx]["ai_service"] = c.get("service", "unknown")
                        batch[idx]["ai_severity"] = c.get("severity", batch[idx].get("severity", "info"))
                        batch[idx]["cwe_id"] = c.get("cwe_id")
                        batch[idx]["_classification_reasoning"] = c.get("reasoning", "")
        except Exception as e:
            logger.error("AI classify failed for batch: %s", e)

    return findings


async def ai_validate(findings: list[dict]) -> list[dict]:
    if not findings:
        return findings

    for batch_start in range(0, len(findings), MAX_BATCH_SIZE):
        batch = findings[batch_start:batch_start + MAX_BATCH_SIZE]

        prompt = VALIDATE_PROMPT.format(findings_json=_findings_to_json(batch))

        try:
            result_text = await _call_ai(prompt, triage=False, max_tokens=2048)
            validations = _extract_json(result_text)
            if isinstance(validations, list):
                for v in validations:
                    idx = v.get("index", -1)
                    if 0 <= idx < len(batch):
                        batch[idx]["ai_is_real"] = v.get("is_likely_real", True)
                        batch[idx]["ai_confidence_adjustment"] = v.get("confidence_adjustment", 0.0)
                        batch[idx]["ai_notes"] = v.get("notes", "")
        except Exception as e:
            logger.error("AI validate failed for batch: %s", e)

    return findings


async def ai_correlate(findings: list[dict]) -> list[dict]:
    if len(findings) < 2:
        for f in findings:
            f["correlation_groups"] = []
        return findings

    prompt = CORRELATE_PROMPT.format(findings_json=_findings_to_json(findings))

    try:
        result_text = await _call_ai(prompt, triage=False, max_tokens=4096)
        correlation_data = _extract_json(result_text)
        groups = correlation_data.get("correlation_groups", []) if isinstance(correlation_data, dict) else []

        for f in findings:
            f["correlation_groups"] = []

        for group in groups:
            name = group.get("group_name", "unnamed")
            relationship = group.get("relationship", "")
            combined_severity = group.get("combined_severity", "info")
            member_indices = group.get("member_indices", [])
            for idx in member_indices:
                if 0 <= idx < len(findings):
                    findings[idx].setdefault("correlation_groups", []).append({
                        "group_name": name,
                        "relationship": relationship,
                        "combined_severity": combined_severity,
                    })
    except Exception as e:
        logger.error("AI correlate failed: %s", e)
        for f in findings:
            f.setdefault("correlation_groups", [])

    return findings


async def ai_report(findings: list[dict], target: str) -> str:
    if not findings:
        return f"# Security Assessment Report for {target}\n\nNo findings to report.\n"

    prompt = REPORT_PROMPT.format(
        target=target,
        findings_json=_findings_to_json(findings),
    )

    try:
        return await _call_ai(prompt, triage=False, max_tokens=8192)
    except Exception as e:
        logger.error("AI report generation failed: %s", e)
        return f"""# Security Assessment Report for {target}

## Executive Summary
Automated assessment detected {len(findings)} potential findings. AI report generation failed: {e}

## Findings
{_findings_to_json(findings)}
"""


def _findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [
        {
            "source": f.source,
            "type": f.type,
            "value": f.value,
            "context": f.context,
            "url_found_on": f.url_found_on,
            "severity": f.severity,
            "confidence": f.confidence,
            "raw": f.raw,
            "found_at": f.found_at,
        }
        for f in findings
    ]


def _dicts_to_findings(data: list[dict]) -> list[Finding]:
    return [
        Finding(
            source=d.get("source", "unknown"),
            type=d.get("type", d.get("ai_type", "unknown")),
            value=d.get("value", ""),
            context=d.get("context"),
            url_found_on=d.get("url_found_on"),
            severity=d.get("severity", d.get("ai_severity", "info")),
            confidence=d.get("confidence", 0.0),
            raw=d.get("raw"),
            found_at=d.get("found_at", ""),
        )
        for d in data
    ]
