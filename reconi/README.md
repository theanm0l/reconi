# Reconi — Automated Reconnaissance & OSINT for Web Apps

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/your-username/reconi/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/reconi/actions)

**62 reconnaissance sources across 8 categories, powered by AI for triage, classification, and false-positive reduction.**

```
reconi scan example.com
```

---

## Features

- **62 Recon Sources** — Wayback Machine, GAU, CommonCrawl, Google Dorks, GitHub, GitLab, Pastebin, Postman, SwaggerHub, Shodan, Censys, Dehashed, HaveIBeenPwned, and 47 more
- **AI-Powered Pipeline** — OpenCode Go (DeepSeek V4) for triage, classification, validation, correlation, and reporting. Local Ollama fallback included.
- **Secret Detection** — 27 regex patterns with entropy filtering: AWS, GitHub, Stripe, Slack, Discord, OpenAI, JWT, private keys, database URLs, and more
- **Live API Validation** — Tests found keys against real endpoints (GitHub, Stripe, AWS STS, Slack, etc.)
- **Confidence Scoring** — Weighted 0-100 scoring with deduplication via SimHash
- **CLI-First** — Rich terminal UI, JSON/CSV/HTML export
- **Docker** — Single-command setup with PostgreSQL, Redis, and Celery workers
- **Async Architecture** — FastAPI + Celery workers, PostgreSQL + Redis

## Quick Start

### Install

```bash
pip install reconi
reconi init                    # Creates reconi.yaml with defaults
```

### Scan a Target

```bash
# Full scan (all 62 modules)
reconi scan example.com

# Selective scan
reconi scan example.com --modules "wayback,gau,google,github_code,pastebin"

# With AI analysis (requires OpenCode Go API key)
export OPENCODE_GO_API_KEY="sk-..."
reconi scan example.com
```

### View Results

```bash
# List findings
reconi findings --severity critical --limit 20

# Export report
reconi report --format html --output report.html
reconi report --format json --output findings.json
```

## Docker Setup

```bash
# Start PostgreSQL + Redis + Worker
docker-compose up -d

# Run scan
docker-compose run --rm worker reconi scan example.com

# Monitor workers
open http://localhost:5555   # Flower dashboard
```

## AI Configuration

Reconi uses a **cascading AI pipeline** to filter noise, classify findings, validate context, and generate reports.

### Option 1: OpenCode Go ($10/month)

```yaml
# reconi.yaml
ai:
  provider: opencode-go
  base_url: https://opencode.ai/zen/go/v1
  triage_model: deepseek-v4-flash
  analysis_model: deepseek-v4-pro
```

```bash
export OPENCODE_GO_API_KEY="your-key"
```

### Option 2: Local Ollama (free)

```bash
ollama pull llama3.1:8b
# reconi.yaml
ai:
  provider: ollama
  fallback_model: llama3.1:8b
```

### AI Pipeline Stages

| Stage | Model | Purpose |
|-------|-------|---------|
| **Triage** | deepseek-v4-flash | Filters 90% noise instantly (2ms/finding) |
| **Classify** | deepseek-v4-pro | Type, service, severity, CWE mapping |
| **Validate** | deepseek-v4-pro | Context-aware verification |
| **Correlate** | deepseek-v4-pro | Links findings across sources |
| **Report** | deepseek-v4-pro | Executive summary + remediation |

## Recon Modules (62 Total)

### URL & Subdomain Discovery (15)
`wayback` `waybackurls` `gau` `gauplus` `commoncrawl` `urlscan` `alienvault` `virustotal` `crtsh` `certspotter` `hackertarget` `dnsdumpster` `securitytrails` `shodan` `censys`

### Search Engine Dorking (10)
`google` `bing` `duckduckgo` `github_code` `github_gists` `gitlab` `shodan_query` `publicwww` `nerdydata` `dnslytics`

### Code Repository Mining (10)
`github_repos` `github_commits` `github_issues` `pastebin` `pastebin_archive` `ghostbin` `giters` `gitmemory` `searchcode` `bitbucket`

### API & Documentation Discovery (8)
`postman_api` `postman_explore` `swaggerhub` `apis_guru` `graphql_introspect` `wsdl_discover` `rapidapi` `programmableweb`

### JS & Client-Side Analysis (7)
`endpoints` `sourcemaps` `webpack` `firebase` `s3_buckets` `config_files` `cloud_urls`

### DNS & Infrastructure (5)
`whois` `reverse_ip` `asn_enum` `spf_dmarc` `cname_analysis`

### Leaked Credential Search (5)
`dehashed` `intelx` `leakcheck` `haveibeenpwned` `snusbase`

### OSINT & Social (2)
`reddit_pushshift` `trello_boards`

## Architecture

```
CLI (Typer)
    │
    ▼
FastAPI ──► Celery Workers (62 modules in parallel)
    │              │
    ▼              ▼
PostgreSQL    Raw Findings
    │              │
    ▼              ▼
Redis Cache   ┌─────────────────────────────┐
              │   AI ANALYSIS PIPELINE       │
              │  Triage → Classify → Validate│
              │  → Correlate → Score → Report│
              │   (OpenCode Go / Ollama)     │
              └──────────┬──────────────────┘
                         ▼
                Final Findings (scored, deduplicated)
```

## Configuration

```yaml
# reconi.yaml
targets:
  - example.com

modules:
  url_discovery: [wayback, gau, crtsh, shodan, censys, ...]
  dorking: [google, github_code, gitlab, ...]
  code_mining: [pastebin, searchcode, ...]
  api_discovery: [postman_api, swaggerhub, ...]
  js_analysis: [endpoints, sourcemaps, firebase, ...]
  dns_infra: [whois, cname_analysis, ...]
  leaks: [dehashed, haveibeenpwned, ...]
  osint: [reddit_pushshift, trello_boards]

ai:
  provider: opencode-go
  triage_model: deepseek-v4-flash
  analysis_model: deepseek-v4-pro

proxies:
  enabled: false
  pool: free
  rotate_interval: 10

validation:
  live_api_test: true
  risky_apis: []

output:
  format: json
  report_dir: ./reports
```

## Environment Variables

| Variable | Required For |
|----------|-------------|
| `OPENCODE_GO_API_KEY` | AI analysis pipeline |
| `GITHUB_TOKEN` | GitHub code/commit/issue search |
| `SHODAN_API_KEY` | Shodan host/dork search |
| `CENSYS_API_KEY` / `CENSYS_SECRET` | Censys certificate search |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain report |
| `SECURITYTRAILS_API_KEY` | SecurityTrails subdomains |
| `DEHASHED_API_KEY` / `DEHASHED_EMAIL` | Dehashed breach search |
| `INTELX_API_KEY` | Intelligence X search |
| `HIBP_API_KEY` | HaveIBeenPwned breach search |

## Development

```bash
pip install -e ".[dev]"
pre-commit install
pytest
```

## Disclaimer

**For authorized security testing only.** Always obtain written permission before scanning any domain you do not own. The authors assume no liability for misuse of this tool.

## License

MIT — See [LICENSE](LICENSE) for details.
