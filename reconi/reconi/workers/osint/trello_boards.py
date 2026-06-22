"""Trello boards OSINT module — discover Trello boards referencing a domain."""

import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class TrelloBoardsModule(ReconModule):
    name = "trello_boards"
    category = "osint"
    description = "Discover Trello boards mentioning a domain via Trello API or Google dorking"
    requires_api_key = False
    rate_limit_delay = 1.5

    def __init__(self) -> None:
        self.api_key = os.environ.get("TRELLO_API_KEY", "")
        self.token = os.environ.get("TRELLO_TOKEN", "")

    async def _trello_api_search(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = "https://api.trello.com/1/search"
        params = {"query": domain, "idBoards": "all",
                  "key": self.api_key, "token": self.token,
                  "board_fields": "name,url", "card_fields": "name,desc,url",
                  "cards_limit": 50, "boards_limit": 20}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return [resp.json()]
        except Exception:
            return []

    async def _google_scrape(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        query = f"site:trello.com {domain}"
        try:
            resp = await client.get(
                "https://www.google.com/search",
                params={"q": query, "num": 30},
                headers=headers,
            )
            urls: set[str] = set()
            for match in re.finditer(r'https?://trello\.com/[^\s"\'&<>]+', resp.text):
                url = match.group(0).rstrip(".,;:!?")
                urls.add(url)
            return list(urls)[:30]
        except Exception:
            return []

    def _extract_sensitive(self, text: str) -> list[str]:
        snippets: list[str] = []
        patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "email"),
            (r'(?:password|passwd|pwd)[\s:=]+["\']?([^\s"\']{4,})', "password"),
            (r'(?:api[_-]?key|apikey|secret|token)[\s:=]+["\']?([^\s"\']{8,})', "api_key"),
            (r'https?://[^\s<>"{}|\\^`\[\]]+(?:\.env|\.config|/admin|/api)', "internal_url"),
        ]
        for pattern, label in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                snippets.append(f"[{label}] {match.group(0)}")
        return snippets[:15]

    async def _process_board(self, client: httpx.AsyncClient, board: dict) -> list[Finding]:
        results: list[Finding] = []
        board_name = board.get("name", "")
        board_url = board.get("url", "")

        if board_name and board_url:
            results.append(Finding(
                source=self.name,
                type="trello_board",
                value=board_url,
                context=f"Board: {board_name}",
                url_found_on="https://api.trello.com/1/search",
                severity="info",
                confidence=0.7,
                raw={"name": board_name, "url": board_url},
            ))

        cards = board.get("cards", [])
        for card in cards:
            card_name = card.get("name", "")
            card_desc = card.get("desc", "")
            card_url = card.get("url", "")
            card_id = card.get("id", "")

            if card_name and card_url:
                results.append(Finding(
                    source=self.name,
                    type="trello_board",
                    value=card_url,
                    context=f"Card: {card_name} (board: {board_name})",
                    url_found_on="https://api.trello.com/1/search",
                    severity="info",
                    confidence=0.65,
                    raw={"card_id": card_id, "name": card_name, "desc": card_desc[:500],
                         "url": card_url, "board": board_name},
                ))

            if card_desc:
                for snippet in self._extract_sensitive(card_desc):
                    results.append(Finding(
                        source=self.name,
                        type="trello_board",
                        value=snippet,
                        context=f"Extracted from Trello card '{card_name}' (board: {board_name})",
                        url_found_on=card_url,
                        severity="high",
                        confidence=0.6,
                        raw={"card_id": card_id, "type": "extracted", "snippet": snippet},
                    ))

        return results

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(45)) as client:
            if self.api_key and self.token:
                search_results = await self._trello_api_search(client, domain)

                for result in search_results:
                    boards = result.get("boards", [])
                    for board in boards:
                        board_findings = await self._process_board(client, board)
                        findings.extend(board_findings)

                    cards = result.get("cards", [])
                    for card in cards:
                        card_name = card.get("name", "")
                        card_desc = card.get("desc", "")
                        card_url = card.get("url", "")
                        card_id = card.get("id", "")
                        board_name = card.get("board", {}).get("name", "unknown")

                        if card_name and card_url:
                            findings.append(Finding(
                                source=self.name,
                                type="trello_board",
                                value=card_url,
                                context=f"Card: {card_name} (board: {board_name})",
                                url_found_on="https://api.trello.com/1/search",
                                severity="info",
                                confidence=0.65,
                                raw={"card_id": card_id, "name": card_name,
                                     "desc": card_desc[:500], "url": card_url},
                            ))

                        if card_desc:
                            for snippet in self._extract_sensitive(card_desc):
                                findings.append(Finding(
                                    source=self.name,
                                    type="trello_board",
                                    value=snippet,
                                    context=f"Extracted from Trello card '{card_name}'",
                                    url_found_on=card_url,
                                    severity="high",
                                    confidence=0.6,
                                    raw={"card_id": card_id, "type": "extracted", "snippet": snippet},
                                ))
            else:
                scraped_urls = await self._google_scrape(client, domain)
                for url in scraped_urls:
                    findings.append(Finding(
                        source=self.name,
                        type="trello_board",
                        value=url,
                        context="Trello URL found via Google dorking",
                        url_found_on=f"https://www.google.com/search?q=site:trello.com+{domain}",
                        severity="info",
                        confidence=0.4,
                        raw={"url": url, "method": "google_dork"},
                    ))

                await asyncio.sleep(self.rate_limit_delay)

        return findings


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="osint.trello_boards")
def run_trello_boards_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = TrelloBoardsModule()
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
