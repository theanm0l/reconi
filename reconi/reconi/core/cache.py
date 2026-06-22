"""Redis cache and queue client."""

from redis import Redis

from .config import settings

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def get_cache() -> Redis:
    return redis_client


class CacheKeys:
    @staticmethod
    def target_urls(target_id: str) -> str:
        return f"reconi:target:{target_id}:urls"

    @staticmethod
    def dedup_set(module: str) -> str:
        return f"reconi:dedup:{module}"

    @staticmethod
    def rate_limit(source: str) -> str:
        return f"reconi:ratelimit:{source}"

    @staticmethod
    def job_progress(job_id: str) -> str:
        return f"reconi:job:{job_id}:progress"
