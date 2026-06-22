"""Main analysis orchestration — ties all pipeline stages together."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ..core.cache import redis_client, CacheKeys
from ..core.celery_app import celery_app
from ..core.config import settings
from ..core.database import SessionLocal, Finding as DBFinding, ReconJob
from ..core.plugin import Finding

from .ai_pipeline import (
    ai_triage,
    ai_classify,
    ai_validate,
    ai_correlate,
    ai_report,
    _findings_to_dicts,
    _dicts_to_findings,
)
from .deduper import deduplicate_findings_data
from .scorer import score_finding
from .secret_detector import extract_secrets_from_findings
from .validator import run_validation

logger = logging.getLogger(__name__)

PIPELINE_STAGES = [
    "secret_detection",
    "ai_triage",
    "ai_classify",
    "deduplication",
    "live_validation",
    "ai_validation",
    "ai_correlation",
    "scoring",
    "report_generation",
    "save_to_db",
]


def _update_progress(job_id: str, stage: str, progress_pct: float, message: str = ""):
    key = CacheKeys.job_progress(job_id)
    try:
        redis_client.hset(key, mapping={
            "stage": stage,
            "progress": str(round(progress_pct, 1)),
            "message": message,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass


async def analyze_findings(job_id: str, target: str, raw_findings: list[Finding]) -> list[dict]:
    total_stages = len(PIPELINE_STAGES)
    results: list[dict] = _findings_to_dicts(raw_findings)
    logger.info("Starting analysis pipeline for job %s with %d findings", job_id, len(results))

    for stage_idx, stage_name in enumerate(PIPELINE_STAGES):
        progress = ((stage_idx + 0.5) / total_stages) * 100
        _update_progress(job_id, stage_name, progress, f"Running {stage_name}...")

        if stage_name == "secret_detection":
            try:
                secrets = extract_secrets_from_findings(raw_findings)
                secret_dicts = _findings_to_dicts(secrets)
                results.extend(secret_dicts)
                logger.info("Secret detection found %d additional findings", len(secret_dicts))
            except Exception as e:
                logger.error("Secret detection failed: %s", e)

        elif stage_name == "ai_triage":
            try:
                results = await ai_triage(results)
                logger.info("AI triage kept %d findings", len(results))
            except Exception as e:
                logger.error("AI triage failed: %s, continuing", e)

        elif stage_name == "ai_classify":
            try:
                results = await ai_classify(results)
                logger.info("AI classification complete for %d findings", len(results))
            except Exception as e:
                logger.error("AI classification failed: %s", e)

        elif stage_name == "deduplication":
            try:
                results = deduplicate_findings_data(results)
                logger.info("Deduplication reduced to %d unique findings", len(results))
            except Exception as e:
                logger.error("Deduplication failed: %s", e)

        elif stage_name == "live_validation":
            try:
                tasks = [run_validation(f) for f in results]
                validations = await asyncio.gather(*tasks, return_exceptions=True)
                for i, val in enumerate(validations):
                    if isinstance(val, Exception):
                        results[i]["_validation"] = {"is_valid": False, "detail": str(val), "confidence_boost": 0.0}
                    else:
                        results[i]["_validation"] = val
                logger.info("Live validation complete")
            except Exception as e:
                logger.error("Live validation failed: %s", e)

        elif stage_name == "ai_validation":
            try:
                results = await ai_validate(results)
                logger.info("AI validation complete")
            except Exception as e:
                logger.error("AI validation failed: %s", e)

        elif stage_name == "ai_correlation":
            try:
                results = await ai_correlate(results)
                logger.info("AI correlation complete, %d groups found", sum(
                    len(f.get("correlation_groups", [])) for f in results
                ))
            except Exception as e:
                logger.error("AI correlation failed: %s", e)

        elif stage_name == "scoring":
            try:
                for f in results:
                    f["confidence"] = round(score_finding(f), 2)
                logger.info("Scoring complete for %d findings", len(results))
            except Exception as e:
                logger.error("Scoring failed: %s", e)

        elif stage_name == "report_generation":
            try:
                report = await ai_report(results, target)
                results_extras = {"_report": report, "_generated_at": datetime.now(timezone.utc).isoformat()}
                for f in results:
                    f["_report"] = report
                _update_progress(job_id, "report_generation", progress, "Report generated")
                logger.info("Report generated (%d chars)", len(report))
            except Exception as e:
                logger.error("Report generation failed: %s", e)
                for f in results:
                    f["_report"] = f"Report generation failed: {e}"

        elif stage_name == "save_to_db":
            try:
                db = SessionLocal()
                report_content = results[0].get("_report", "") if results else ""
                for f in results:
                    db_finding = DBFinding(
                        target_id="",
                        job_id=job_id,
                        source=f.get("source", "unknown"),
                        type=f.get("ai_type", f.get("type", "unknown")),
                        value=f.get("value", ""),
                        context=f.get("context") or f.get("ai_notes"),
                        url_found_on=f.get("url_found_on"),
                        confidence=f.get("confidence", 0.0),
                        severity=f.get("severity", f.get("ai_severity", "info")),
                        is_validated=f.get("_validation", {}).get("is_valid", False),
                        is_false_positive=not f.get("ai_is_real", True),
                        cwe_id=f.get("cwe_id"),
                        ai_summary=f.get("_classification_reasoning", "")[:500],
                        raw_json={
                            k: v for k, v in f.items()
                            if k.startswith("_") or k in ("correlation_groups", "ai_service")
                        },
                    )
                    db.add(db_finding)
                db.commit()

                job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
                if job:
                    job.items_found = len(results)
                    job.status = "analyzing"
                    db.commit()
                db.close()
                logger.info("Saved %d findings to database", len(results))
            except Exception as e:
                logger.error("Save to DB failed: %s", e)
                try:
                    db.rollback()
                    db.close()
                except Exception:
                    pass

        progress = ((stage_idx + 1) / total_stages) * 100
        _update_progress(job_id, stage_name, progress, f"Completed {stage_name}")

    _update_progress(job_id, "complete", 100.0, "Analysis pipeline complete")
    return results


@celery_app.task(name="analysis.run_full_analysis_pipeline")
def run_full_analysis_pipeline(job_id: str, target: str):
    db = SessionLocal()
    try:
        job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if job:
            job.status = "analyzing"
            db.commit()

        db_findings = db.query(DBFinding).filter(DBFinding.job_id == job_id).all()
        raw_findings = [
            Finding(
                source=df.source,
                type=df.type,
                value=df.value,
                context=df.context,
                url_found_on=df.url_found_on,
                severity=df.severity,
                confidence=df.confidence,
                raw=df.raw_json,
                found_at=df.created_at.isoformat() if df.created_at else "",
            )
            for df in db_findings
        ]
        db.close()
    except Exception as e:
        logger.error("Failed to load findings from DB: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return {"error": str(e)}

    async def _run():
        return await analyze_findings(job_id, target, raw_findings)

    try:
        results = asyncio.run(_run())
        _update_progress(job_id, "complete", 100.0, "Full analysis pipeline complete")

        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "completed"
                job.items_found = len(results)
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        return {"status": "completed", "findings_count": len(results), "job_id": job_id}
    except Exception as e:
        logger.error("Analysis pipeline failed: %s", e)
        _update_progress(job_id, "failed", 0.0, str(e))
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
        return {"status": "failed", "error": str(e)}
