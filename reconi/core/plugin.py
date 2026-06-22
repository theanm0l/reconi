"""Plugin architecture — base class for all recon modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    source: str
    type: str
    value: str
    context: str | None = None
    url_found_on: str | None = None
    severity: str = "info"
    confidence: float = 0.0
    raw: dict | None = None
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReconModule(ABC):
    name: str = ""
    category: str = ""
    description: str = ""
    requires_api_key: bool = False
    rate_limit_delay: float = 1.0

    @abstractmethod
    async def run(self, target: str) -> list[Finding]:
        pass

    def get_cache_key(self, target: str) -> str:
        return f"{self.category}:{self.name}:{target}"

    def __repr__(self) -> str:
        return f"ReconModule({self.category}/{self.name})"
