"""Rate limiter and proxy rotation engine."""

import asyncio
import random
import time
from collections import defaultdict

import httpx


class RateLimiter:
    def __init__(self, default_delay: float = 1.0):
        self._last_request: dict[str, float] = defaultdict(float)
        self._default_delay = default_delay

    async def wait(self, source: str, custom_delay: float | None = None):
        delay = custom_delay or self._default_delay
        now = time.monotonic()
        elapsed = now - self._last_request.get(source, 0)
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        self._last_request[source] = time.monotonic()

    def throttle(self, source: str, delay: float):
        self._default_delay = delay


class ProxyRotator:
    _free_proxy_sources = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=protocolipport&format=text&timeout=20000",
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    ]

    def __init__(self, enabled: bool = False, proxies: list[str] | None = None):
        self.enabled = enabled
        self._proxies: list[str] = proxies or []
        self._index = 0
        self._healthy: set[str] = set()

    async def fetch_free_proxies(self) -> list[str]:
        proxies: set[str] = set()
        async with httpx.AsyncClient(timeout=httpx.Timeout(15)) as client:
            for url in self._free_proxy_sources:
                try:
                    resp = await client.get(url)
                    for line in resp.text.strip().splitlines():
                        line = line.strip()
                        if line and ":" in line and not line.startswith("#"):
                            proxies.add(f"http://{line}" if "://" not in line else line)
                except Exception:
                    continue
        return list(proxies)

    async def check_proxy(self, proxy: str) -> bool:
        try:
            async with httpx.AsyncClient(
                proxy=proxy, timeout=httpx.Timeout(10)
            ) as client:
                resp = await client.get("https://httpbin.org/ip")
                return resp.status_code == 200
        except Exception:
            return False

    async def refresh(self):
        fresh = await self.fetch_free_proxies()
        self._proxies = fresh
        self._healthy.clear()
        self._index = 0

    def next(self) -> str | None:
        if not self._proxies:
            return None
        proxy = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        return proxy

    def get_httpx_client(self) -> httpx.AsyncClient:
        if not self.enabled or not self._proxies:
            return httpx.AsyncClient(timeout=httpx.Timeout(30))
        proxy = self.next()
        if not proxy:
            return httpx.AsyncClient(timeout=httpx.Timeout(30))
        return httpx.AsyncClient(proxy=proxy, timeout=httpx.Timeout(30))


rate_limiter = RateLimiter()
proxy_rotator = ProxyRotator()
