# src/tic/infra/config.py
"""Typed, validated configuration loader."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ParserLimits(BaseModel):
    max_file_size_bytes: int = Field(default=1_073_741_824, ge=1024, le=10_737_418_240)
    max_json_depth: int = Field(default=64, ge=4, le=256)
    max_string_length: int = Field(default=8192, ge=64, le=65536)
    max_iocs_per_feed: int = Field(default=10_000_000, ge=1, le=100_000_000)
    max_archive_ratio: int = Field(default=100, ge=2, le=1000)


class HttpClientConfig(BaseModel):
    connect_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
    read_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    total_timeout_seconds: float = Field(default=30.0, ge=5.0, le=300.0)
    max_retries: int = Field(default=3, ge=0, le=10)
    user_agent: str = Field(default="tic/0.1 (+defensive-cli)")
    verify_tls: bool = Field(default=True)
    follow_redirects: bool = Field(default=False)


class ProviderConfig(BaseModel):
    """Per-provider configuration.

    allowed_hosts: explicit hostname allowlist for the SSRF guard.
    Use ONLY for trusted internal targets (e.g., on-prem MISP on RFC1918).
    Each entry is a deliberate security exception — review during audits.

    verify_tls: opt-in disable of TLS certificate verification for THIS
    provider only. Default True. Setting False is a deliberate security
    exception meant for local lab MISP instances using self-signed certs
    and must NEVER be used against production targets. Global verify_tls
    in HttpClientConfig is unaffected.
    """
    enabled: bool = True
    concurrency: int = Field(default=4, ge=1, le=32)
    cache_ttl_seconds: int = Field(default=3600, ge=60, le=2_592_000)
    keyring_service: str
    keyring_user: str
    endpoint: str | None = Field(default=None, max_length=2048)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=16)
    verify_tls: bool = True

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_allowed_hosts(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for host in v:
            if not isinstance(host, str) or not host:
                raise ValueError("allowed_hosts entries must be non-empty strings")
            if len(host) > 253:
                raise ValueError("allowed_hosts entry exceeds 253 chars")
            if "/" in host or "://" in host or " " in host:
                raise ValueError(
                    "allowed_hosts entries must be bare hostnames "
                    "(no scheme, no path, no whitespace)"
                )
            out.append(host.lower())
        return out

    @field_validator("endpoint")
    @classmethod
    def _validate_endpoint(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.startswith("https://"):
            raise ValueError("provider endpoint must use https")
        return v


class AIConfig(BaseModel):
    """AI narration configuration.

    AI narration is opt-in (`enabled: false` by default). When enabled, it
    produces an advisory summary alongside each Finding — it never changes
    score, severity, provider results, correlation, above_threshold, or
    exit_code. See `docs/THREAT_MODEL.md` (threat #7) for the full
    invariant set.

    Phase C additions (`language`, `narration_level`,
    `max_findings_per_sweep`) are backward-compatible defaults — existing
    deployments do not need to touch their config.
    """

    enabled: bool = False
    # Adapter selection. Default preserves prior behaviour (OpenAI-compatible
    # chat-completions). Setting `gemini` routes through the Gemini-native
    # generateContent endpoint with `response_mime_type=application/json` so
    # strict-JSON parsing is guaranteed even when the OpenAI compatibility
    # surface returns truncated/malformed JSON. The set is closed so a typo
    # at load time fails loudly rather than silently falling back.
    provider: Literal["openai_compat", "gemini"] = "openai_compat"
    endpoint_allowlist: list[str] = Field(default_factory=list)
    model: str = Field(default="")
    max_output_tokens: int = Field(default=512, ge=16, le=4096)
    max_input_chars: int = Field(default=8000, ge=256, le=32000)
    request_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)
    keyring_service: str = "tic-ai"
    keyring_user: str = "default"

    # --- Phase C: language and narration-level hints (advisory only) ---
    #
    # `language` controls the natural-language portions of the AI response
    # (the summary and the suggested_actions). Technical terms (IOC types,
    # provider names, severity values, schema keys) remain English.
    language: Literal["en", "tr"] = "tr"
    narration_level: Literal["concise", "detailed"] = "concise"

    # --- Phase C: bounded AI execution ---
    #
    # AI is invoked for at most this many findings per sweep. Findings
    # outside the cap still appear in the sweep result; only the
    # `ai_narrative` field stays null. Selection is deterministic — see
    # SweepOrchestrator._select_for_ai for the ordering.
    max_findings_per_sweep: int = Field(default=25, ge=1, le=100)

    @field_validator("endpoint_allowlist")
    @classmethod
    def _validate_endpoints(cls, v: list[str]) -> list[str]:
        for ep in v:
            if not ep.startswith("https://"):
                raise ValueError(f"AI endpoint must use https: {ep}")
        return v


class PathsConfig(BaseModel):
    working_dir: Path
    cache_dir: Path
    audit_log_path: Path

    @field_validator("working_dir", "cache_dir", "audit_log_path")
    @classmethod
    def _must_be_absolute(cls, v: Path) -> Path:
        if not v.is_absolute():
            raise ValueError(f"path must be absolute: {v}")
        return v


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TIC_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
    )

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    no_color: bool = False

    paths: PathsConfig
    parser_limits: ParserLimits = ParserLimits()
    http: HttpClientConfig = HttpClientConfig()
    ai: AIConfig = AIConfig()

    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    scoring_profile_path: Path | None = None
    redaction_hmac_keyring_service: str = "tic-redaction-hmac"
    redaction_hmac_keyring_user: str = "default"


def _xdg_default_paths() -> "PathsConfig | None":
    """XDG-compliant path defaults. Used ONLY when no explicit paths configured."""
    import os
    home = Path.home()
    xdg_cache = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    xdg_state = Path(os.environ.get("XDG_STATE_HOME", home / ".local" / "state"))
    try:
        return PathsConfig(
            working_dir=Path.cwd(),
            cache_dir=xdg_cache / "tic",
            audit_log_path=xdg_state / "tic" / "audit.log",
        )
    except Exception:
        return None


def load_settings(config_file: Path | None = None) -> Settings:
    """Load settings.

    Priority (highest first):
      1. TIC_PATHS__* environment variables
      2. paths: section in YAML config file
      3. XDG-based smart defaults

    The XDG defaults are injected at the LOWEST priority so they never
    override an explicit YAML value — fixing the previous bug where init_kwargs
    silently overrode user-provided YAML paths.
    """
    import os

    if config_file is None:
        env_path = os.environ.get("TIC_CONFIG_FILE")
        if env_path:
            config_file = Path(env_path)
        else:
            candidate = Path("configs/default.yaml")
            if candidate.exists():
                config_file = candidate

    has_paths_env = any(k in os.environ for k in {
        "TIC_PATHS__WORKING_DIR", "TIC_PATHS__CACHE_DIR", "TIC_PATHS__AUDIT_LOG_PATH"
    })

    yaml_has_paths = False
    if config_file is not None and Path(config_file).exists():
        try:
            import yaml as _yaml
            with open(config_file, encoding="utf-8") as _f:
                _doc = _yaml.safe_load(_f) or {}
            yaml_has_paths = "paths" in _doc
        except Exception:
            pass

    class _Settings(Settings):
        @classmethod
        def settings_customise_sources(cls, settings_cls, **kwargs):  # type: ignore[override]
            sources = super().settings_customise_sources(settings_cls, **kwargs)
            if config_file is not None and Path(config_file).exists():
                try:
                    from pydantic_settings import YamlConfigSettingsSource
                    yaml_src = YamlConfigSettingsSource(settings_cls, yaml_file=config_file)
                    return (kwargs["init_settings"], kwargs["env_settings"], yaml_src)
                except Exception:
                    pass
            return sources

    # Only inject XDG defaults if neither env vars NOR YAML provide paths.
    init_kwargs: dict = {}
    if not has_paths_env and not yaml_has_paths:
        dp = _xdg_default_paths()
        if dp is not None:
            init_kwargs["paths"] = dp

    try:
        return _Settings(**init_kwargs)  # type: ignore[call-arg]
    except Exception as exc:
        from tic.domain.errors import ConfigError
        raise ConfigError(
            f"settings validation failed: {exc}",
            user_message=(
                "Configuration is incomplete. Set required env vars:\n"
                "  TIC_PATHS__WORKING_DIR=/path/to/workdir\n"
                "  TIC_PATHS__CACHE_DIR=~/.cache/tic\n"
                "  TIC_PATHS__AUDIT_LOG_PATH=~/.local/state/tic/audit.log\n"
                "Or set TIC_CONFIG_FILE to a YAML file with a paths: section."
            ),
        ) from exc
