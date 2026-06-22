"""Configuration system using Pydantic settings and YAML."""

from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIConfig(BaseModel):
    provider: str = "opencode-go"
    base_url: str = "https://opencode.ai/zen/go/v1"
    api_key: str = ""
    triage_model: str = "deepseek-v4-flash"
    analysis_model: str = "deepseek-v4-pro"
    fallback_provider: str = "ollama"
    fallback_model: str = "llama3.1:8b"


class ProxyConfig(BaseModel):
    enabled: bool = False
    pool: str = "free"
    rotate_interval: int = 10
    proxies: list[str] = Field(default_factory=list)


class ValidationConfig(BaseModel):
    live_api_test: bool = True
    risky_apis: list[str] = Field(default_factory=list)
    max_validation_timeout: int = 10


class OutputConfig(BaseModel):
    format: str = "json"
    report_dir: str = "./reports"


class ModulesConfig(BaseModel):
    url_discovery: list[str] = Field(default_factory=list)
    dorking: list[str] = Field(default_factory=list)
    code_mining: list[str] = Field(default_factory=list)
    api_discovery: list[str] = Field(default_factory=list)
    js_analysis: list[str] = Field(default_factory=list)
    dns_infra: list[str] = Field(default_factory=list)
    leaks: list[str] = Field(default_factory=list)
    osint: list[str] = Field(default_factory=list)


class AppConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    proxies: ProxyConfig = Field(default_factory=ProxyConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RECONI_",
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore",
    )

    config_path: str = "reconi.yaml"
    database_url: str = "postgresql://reconi:reconi@localhost:5432/reconi"
    redis_url: str = "redis://localhost:6379/0"
    opencode_go_api_key: str = ""
    ollama_host: str = "http://localhost:11434"

    @property
    def config(self) -> AppConfig:
        return load_config(self.config_path)


_DEFAULT_CONFIG = {
    "modules": {
        "url_discovery": [
            "wayback", "waybackurls", "gau", "gauplus", "commoncrawl",
            "urlscan", "alienvault", "virustotal", "crtsh", "certspotter",
            "hackertarget", "dnsdumpster", "securitytrails", "shodan", "censys",
        ],
        "dorking": [
            "google", "bing", "duckduckgo", "github_code", "github_gists",
            "gitlab", "shodan_query", "publicwww", "nerdydata", "dnslytics",
        ],
        "code_mining": [
            "github_repos", "github_commits", "github_issues", "pastebin",
            "pastebin_archive", "ghostbin", "giters", "gitmemory", "searchcode",
            "bitbucket",
        ],
        "api_discovery": [
            "postman_api", "postman_explore", "swaggerhub", "apis_guru",
            "graphql_introspect", "wsdl_discover", "rapidapi", "programmableweb",
        ],
        "js_analysis": [
            "endpoints", "sourcemaps", "webpack", "firebase", "s3_buckets",
            "config_files", "cloud_urls",
        ],
        "dns_infra": ["whois", "reverse_ip", "asn_enum", "spf_dmarc", "cname_analysis"],
        "leaks": ["dehashed", "intelx", "leakcheck", "haveibeenpwned", "snusbase"],
        "osint": ["reddit_pushshift", "trello_boards"],
    },
    "ai": {
        "provider": "opencode-go",
        "base_url": "https://opencode.ai/zen/go/v1",
        "triage_model": "deepseek-v4-flash",
        "analysis_model": "deepseek-v4-pro",
        "fallback_provider": "ollama",
        "fallback_model": "llama3.1:8b",
    },
    "proxies": {
        "enabled": False,
        "pool": "free",
        "rotate_interval": 10,
    },
    "validation": {
        "live_api_test": True,
        "risky_apis": [],
        "max_validation_timeout": 10,
    },
    "output": {
        "format": "json",
        "report_dir": "./reports",
    },
}


def create_default_config(path: str) -> AppConfig:
    """Write default config to path and return it."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        yaml.dump(_DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
    return AppConfig(**_DEFAULT_CONFIG)


def load_config(path: str) -> AppConfig:
    """Load config from YAML file, falling back to defaults."""
    p = Path(path)
    if not p.exists():
        return AppConfig(**_DEFAULT_CONFIG)
    with open(p) as f:
        data = yaml.safe_load(f) or {}
    merged = _deep_merge(_DEFAULT_CONFIG, data)
    return AppConfig(**merged)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = {**base}
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


settings = Settings()
