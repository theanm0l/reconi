"""GitHub repository search — scan repos for secrets and sensitive files."""
import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

_SECRET_PATTERNS = [
    (re.compile(r'([a-zA-Z0-9_-]{20,60})', re.IGNORECASE), "possible_api_key"),
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|token|apikey|api_key|auth)\s*[:=]\s*["\']?([^\s"\'<>]{8,})'), "credential"),
    (re.compile(r'(?i)sk-[a-zA-Z0-9]{32,}'), "openai_key"),
    (re.compile(r'(?i)AKIA[0-9A-Z]{16}'), "aws_access_key"),
    (re.compile(r'(?i)ghp_[0-9a-zA-Z]{36}'), "github_pat"),
    (re.compile(r'(?i)gho_[0-9a-zA-Z]{36}'), "github_oauth"),
    (re.compile(r'(?i)github_pat_[0-9a-zA-Z_]{22,}'), "github_pat_v2"),
    (re.compile(r'(?i)xox[baprs]-[0-9a-zA-Z-]{10,}'), "slack_token"),
    (re.compile(r'(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s<>"\'{}|\\^`\[\]]+'), "db_connection_string"),
    (re.compile(r'(?i)-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE\s?KEY(?: BLOCK)?-----'), "private_key"),
    (re.compile(r'(?i)(?:api|app|auth|client|secret|token|key)_?(?:key|token|secret)?\s*[:=]\s*["\']?([^\s"\'<>]{16,})'), "named_secret"),
]

_SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.development",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "config.json", "config.yml", "config.yaml", "credentials.json",
    "secrets.yml", "secrets.json", "settings.py", "settings.ini",
    ".npmrc", ".pypirc", ".htpasswd", "id_rsa", "id_ed25519",
]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


def _scan_content(content: str) -> list[dict]:
    hits = []
    for pattern, label in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            hits.append({"type": label, "value": match.group(0) if match.groups() else match.group(0), "match": match.group(0)})
    return hits


class GithubReposModule(ReconModule):
    name = "github_repos"
    category = "code_mining"
    description = "Search GitHub repos for a domain and scan for secrets in sensitive files and commits"
    requires_api_key = True
    rate_limit_delay = 0.75

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        token = os.getenv("GITHUB_TOKEN", "")
        if not token:
            findings.append(Finding(source=self.name, type="error", value="GITHUB_TOKEN not set", severity="info", confidence=0.0))
            return findings

        domain = _extract_domain(target)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60), headers=headers) as client:
                search_url = f"https://api.github.com/search/repositories?q={domain}&per_page=100"
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()
                repos = data.get("items", [])

            for repo in repos[:30]:
                await asyncio.sleep(0.5)
                owner = repo["owner"]["login"]
                repo_name = repo["name"]
                repo_url = repo["html_url"]

                findings.append(Finding(
                    source=self.name,
                    type="repo",
                    value=repo_url,
                    context=repo.get("description", ""),
                    url_found_on=search_url,
                    severity="info",
                    confidence=0.6,
                    raw={"owner": owner, "repo": repo_name, "stars": repo.get("stargazers_count", 0)},
                ))

                try:
                    async with httpx.AsyncClient(timeout=httpx.Timeout(60), headers=headers) as client:
                        contents_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo_name}/contents/")
                        if contents_resp.status_code == 200:
                            contents = contents_resp.json()
                            for item in contents[:50]:
                                if item.get("name") in _SENSITIVE_FILES:
                                    findings.append(Finding(
                                        source=self.name,
                                        type="secret_in_repo",
                                        value=item["html_url"],
                                        context=f"Sensitive file: {item['name']}",
                                        url_found_on=repo_url,
                                        severity="medium",
                                        confidence=0.8,
                                        raw={"file": item["name"], "repo": repo_name, "size": item.get("size", 0)},
                                    ))
                except httpx.HTTPStatusError:
                    pass
                except Exception:
                    pass

                try:
                    async with httpx.AsyncClient(timeout=httpx.Timeout(60), headers=headers) as client:
                        commits_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo_name}/commits?per_page=20")
                        if commits_resp.status_code == 200:
                            commits = commits_resp.json()
                            for commit in commits[:20]:
                                message = commit.get("commit", {}).get("message", "")
                                hits = _scan_content(message)
                                for hit in hits:
                                    findings.append(Finding(
                                        source=self.name,
                                        type="secret_in_repo",
                                        value=commit.get("html_url", ""),
                                        context=f"Commit message match: {hit['type']}",
                                        url_found_on=repo_url,
                                        severity="high",
                                        confidence=0.7,
                                        raw={"commit_message": message[:200], "detected": hit["type"]},
                                    ))
                except httpx.HTTPStatusError:
                    pass
                except Exception:
                    pass

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.github_repos")
def run_github_repos_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GithubReposModule()
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
