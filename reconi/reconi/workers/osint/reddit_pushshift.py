"""Reddit / Pushshift OSINT module — search Reddit for domain mentions."""

import asyncio
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class RedditPushshiftModule(ReconModule):
    name = "reddit_pushshift"
    category = "osint"
    description = "Search Reddit submissions and comments for domain mentions via Pushshift and Reddit APIs"
    requires_api_key = False
    rate_limit_delay = 1.2

    async def _pushshift_submissions(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = "https://api.pushshift.io/reddit/search/submission/"
        params = {"q": domain, "size": 100, "sort": "desc", "sort_type": "created_utc"}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", [])
        except Exception:
            return []

    async def _pushshift_comments(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = "https://api.pushshift.io/reddit/search/comment/"
        params = {"q": domain, "size": 100, "sort": "desc", "sort_type": "created_utc"}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", [])
        except Exception:
            return []

    async def _reddit_search(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = "https://www.reddit.com/search.json"
        params = {"q": domain, "limit": 100, "sort": "relevance"}
        headers = {"User-Agent": "Reconi/1.0 (OSINT bot; contact@example.com)"}
        try:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            children = data.get("data", {}).get("children", [])
            return [c.get("data", {}) for c in children]
        except Exception:
            return []

    def _extract_interesting(self, text: str) -> list[str]:
        snippets: list[str] = []
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        key_pattern = re.compile(r'(?:api[_-]?key|apikey|secret|token)[\s:=]+["\']?([^\s"\']{8,})', re.IGNORECASE)

        for match in url_pattern.finditer(text):
            url = match.group(0).rstrip(".,;:!?")
            if len(url) < 200:
                snippets.append(f"[url] {url}")
        for match in email_pattern.finditer(text):
            snippets.append(f"[email] {match.group(0)}")
        for match in key_pattern.finditer(text):
            snippets.append(f"[{match.group(0)}]")
        return snippets[:10]

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(45)) as client:
            submissions = await self._pushshift_submissions(client, domain)

            for post in submissions:
                title = post.get("title", "")
                selftext = post.get("selftext", "")
                author = post.get("author", "")
                subreddit = post.get("subreddit", "")
                permalink = post.get("permalink", "")
                created_utc = post.get("created_utc", 0)

                reddit_url = f"https://www.reddit.com{permalink}" if permalink else ""
                snippet = selftext[:300] if selftext else title[:300]

                findings.append(Finding(
                    source=self.name,
                    type="social_mention",
                    value=reddit_url,
                    context=f"r/{subreddit} by u/{author}: {snippet[:150]}",
                    url_found_on=f"https://api.pushshift.io/reddit/search/submission/?q={domain}",
                    severity="info",
                    confidence=0.65,
                    raw={
                        "title": title, "author": author, "subreddit": subreddit,
                        "permalink": reddit_url, "created_utc": created_utc,
                        "snippet": snippet,
                    },
                ))

                for extracted in self._extract_interesting(title + " " + selftext):
                    findings.append(Finding(
                        source=self.name,
                        type="social_mention",
                        value=extracted,
                        context=f"Extracted from r/{subreddit} post by u/{author}",
                        url_found_on=reddit_url,
                        severity="low",
                        confidence=0.5,
                        raw={"type": "extracted", "post_url": reddit_url},
                    ))

            await asyncio.sleep(self.rate_limit_delay)

            comments = await self._pushshift_comments(client, domain)

            for comment in comments:
                body = comment.get("body", "")
                author = comment.get("author", "")
                subreddit = comment.get("subreddit", "")
                permalink = comment.get("permalink", "")
                created_utc = comment.get("created_utc", 0)

                reddit_url = f"https://www.reddit.com{permalink}" if permalink else ""

                findings.append(Finding(
                    source=self.name,
                    type="social_mention",
                    value=reddit_url,
                    context=f"r/{subreddit} comment by u/{author}: {body[:150]}",
                    url_found_on=f"https://api.pushshift.io/reddit/search/comment/?q={domain}",
                    severity="info",
                    confidence=0.6,
                    raw={
                        "author": author, "subreddit": subreddit,
                        "permalink": reddit_url, "created_utc": created_utc,
                        "snippet": body[:300],
                    },
                ))

                for extracted in self._extract_interesting(body):
                    findings.append(Finding(
                        source=self.name,
                        type="social_mention",
                        value=extracted,
                        context=f"Extracted from r/{subreddit} comment by u/{author}",
                        url_found_on=reddit_url,
                        severity="low",
                        confidence=0.5,
                        raw={"type": "extracted", "comment_url": reddit_url},
                    ))

            await asyncio.sleep(self.rate_limit_delay)

            reddit_results = await self._reddit_search(client, domain)

            for post in reddit_results:
                title = post.get("title", "")
                selftext = post.get("selftext", "")
                author = post.get("author", "")
                subreddit = post.get("subreddit", "")
                permalink = post.get("permalink", "")
                created_utc = post.get("created_utc", 0)
                url_link = post.get("url", "")

                reddit_url = f"https://www.reddit.com{permalink}" if permalink else ""
                snippet = selftext[:300] if selftext else title[:300]

                findings.append(Finding(
                    source=self.name,
                    type="social_mention",
                    value=url_link if url_link and url_link != reddit_url else reddit_url,
                    context=f"r/{subreddit} by u/{author}: {snippet[:150]}",
                    url_found_on=f"https://www.reddit.com/search.json?q={domain}",
                    severity="info",
                    confidence=0.65,
                    raw={
                        "title": title, "author": author, "subreddit": subreddit,
                        "permalink": reddit_url, "created_utc": created_utc,
                        "snippet": snippet, "external_url": url_link,
                    },
                ))

        return findings


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="osint.reddit_pushshift")
def run_reddit_pushshift_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = RedditPushshiftModule()
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
