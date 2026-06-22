"""Celery application configuration — optional, works without Celery installed."""

try:
    from celery import Celery

    from .config import settings

    celery_app = Celery(
        "reconi",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=[
            "reconi.workers.url_discovery",
            "reconi.workers.dorking",
            "reconi.workers.code_mining",
            "reconi.workers.api_discovery",
            "reconi.workers.js_analysis",
            "reconi.workers.dns_infra",
            "reconi.workers.leaks",
            "reconi.workers.osint",
            "reconi.analysis.ai_pipeline",
            "reconi.analysis.secret_detector",
            "reconi.analysis.validator",
            "reconi.analysis.deduper",
            "reconi.analysis.scorer",
            "reconi.analysis.orchestrator",
        ],
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True,
    )
except ImportError:
    celery_app = None
