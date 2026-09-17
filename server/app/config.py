# Drishti v0.1 — env-driven configuration loader | 11-Jul-2026
"""Application settings. All secrets and tunables come from the environment."""
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# app_env values allowed to boot with the default/empty jwt_secret.
# Anything NOT in this set (including an unset / empty APP_ENV — see the ""
# default below) is treated as a non-dev deployment and must set a real
# JWT_SECRET or refuse to start (see Settings.validate_jwt_secret).
# "docker" and "production" are deliberately excluded.
_INSECURE_JWT_SECRET_ALLOWED_ENVS = {"local", "dev", "test"}

# jwt_secret values considered insecure defaults (must never boot a non-dev env).
_INSECURE_JWT_SECRETS = {"change-me", ""}

# per-provider default model, used when AI_MODEL is left blank
_DEFAULT_AI_MODELS = {
    "groq": "openai/gpt-oss-120b",
    "nvidia": "meta/llama-3.3-70b-instruct",
    "anthropic": "claude-sonnet-5",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore")

    # Default is intentionally EMPTY (not "local"): an unset APP_ENV must be
    # treated as a non-dev deployment so it fails closed on the default secret.
    # Only an APP_ENV explicitly set to local/dev/test may boot with "change-me".
    app_env: str = ""
    database_url: str = "sqlite:///./drishti.db"

    jwt_secret: str = "change-me"
    jwt_access_minutes: int = 15
    jwt_refresh_days: int = 7
    cors_origins: str = "http://localhost:5173"

    # AI provider: "groq", "nvidia", or "anthropic". The backend is the ONLY
    # caller of the LLM API; the frontend never holds a key (CLAUDE.md §6).
    ai_provider: str = "nvidia"
    anthropic_api_key: str = ""
    groq_api_key: str = ""
    nvidia_api_key: str = ""
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    # Default model tracks ai_provider (see resolved_ai_model). Set AI_MODEL to
    # override explicitly for either provider.
    ai_model: str = ""
    ai_mock: bool = False
    ai_max_tokens: int = 2500
    ai_timeout_seconds: float = 45.0

    # URL Trust Analyzer — optional reputation providers (free tiers). Absent
    # keys make the provider report configured:false and contribute NOTHING to
    # the score (never a fabricated value). See docs/URL_ANALYZER.md.
    google_safe_browsing_key: str = ""
    virustotal_key: str = ""
    # outbound network timeout for URL probes / provider calls (seconds)
    urltrust_timeout_seconds: float = 6.0

    # Deep Scan (Live Network Watch → consented device scan). CVE lookup uses the
    # free NVD REST API by default (works with NO key, but rate-limited: ~5 req /
    # 30s without a key, ~50 with one). VULNERS_KEY, if set, is used instead.
    # Absent keys are fine — a lookup that can't run reports available:false and
    # contributes NOTHING (never a fabricated CVE). Keys are optional.
    nvd_api_key: str = ""
    vulners_key: str = ""
    # nmap subprocess timeout (seconds) — a -sV top-1000 scan can take a while
    deepscan_timeout_seconds: float = 120.0
    # outbound timeout for a single NVD/Vulners CVE lookup (seconds)
    deepscan_cve_timeout_seconds: float = 12.0
    # Subnet (range) scan bounds — direct Nmap on the LOCAL subnet, no NAT.
    deepscan_max_hosts: int = 32  # hosts per nmap batch (one -sV run); we iterate
    deepscan_max_total_hosts: int = 256  # hard ceiling on total hosts across batches
    deepscan_discovery_timeout_seconds: float = 60.0  # `nmap -sn` sweep ceiling
    deepscan_range_timeout_seconds: float = 300.0  # per-batch -sV ceiling

    # Business-impact model: per-org breach overhead constant (regulatory,
    # notification, response costs). Transparent, tunable (BACKEND.md §7.1).
    breach_cost_base: float = 500_000.0

    ingest_max_bytes: int = 1_048_576  # reject payloads > 1 MB

    # On startup, create tables and seed the org identity if the DB is empty.
    auto_seed: bool = True
    # When False (default), bootstrap seeds identity only (org + user + agent) —
    # the attack map and live watch start empty and fill only with real devices
    # the agent discovers, so NO fabricated device ever shows. Set DEMO_SEED=1 to
    # boot with the Acme sample network for a canned demo.
    demo_seed: bool = False
    # Telegram Alert Bot — optional external notifications.
    # Leave blank to disable (default). See server/app/services/telegram_alerts.py.
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


    @model_validator(mode="after")
    def validate_jwt_secret(self) -> "Settings":
        if self.jwt_secret in _INSECURE_JWT_SECRETS and self.app_env not in _INSECURE_JWT_SECRET_ALLOWED_ENVS:
            raise ValueError(
                f"JWT_SECRET is still the default 'change-me' value for APP_ENV={self.app_env!r}. "
                "Refusing to start: this default is public in the repo and lets anyone forge auth "
                "tokens. Set a real JWT_SECRET env var, and set APP_ENV explicitly to one of "
                f"{sorted(_INSECURE_JWT_SECRET_ALLOWED_ENVS)} only for local development. "
                "An unset/empty APP_ENV is treated as a deployment and requires a real JWT_SECRET."
            )
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def resolved_ai_model(self) -> str:
        if self.ai_model:
            return self.ai_model
        return _DEFAULT_AI_MODELS.get(self.ai_provider, _DEFAULT_AI_MODELS["groq"])


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
