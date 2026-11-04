"""Application settings loaded from APIGUARD_* environment variables.

The signing key is the one secret the service holds. Outside ``environment="test"`` the
settings refuse to load when the key is short, low-variety or a known placeholder, so a
deployment that forgot to set it fails at startup instead of issuing forgeable tokens.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SIGNING_KEY_LENGTH = 32
MIN_SIGNING_KEY_DISTINCT_CHARS = 10

# Values that appear in tutorials, templates and this repository's own .env.example.
_PLACEHOLDER_FRAGMENTS = (
    "changeme",
    "change-me",
    "change_me",
    "replace-with",
    "replace_me",
    "secret",
    "example",
    "password",
    "default",
)


class WeakSigningKeyError(ValueError):
    """Raised when the configured JWT signing key is unsafe to use."""


def signing_key_problem(key: str) -> str | None:
    """Return a human-readable reason the key is weak, or None if it is acceptable."""
    if len(key) < MIN_SIGNING_KEY_LENGTH:
        return f"must be at least {MIN_SIGNING_KEY_LENGTH} characters"
    if len(set(key)) < MIN_SIGNING_KEY_DISTINCT_CHARS:
        return f"must contain at least {MIN_SIGNING_KEY_DISTINCT_CHARS} distinct characters"
    lowered = key.lower()
    for fragment in _PLACEHOLDER_FRAGMENTS:
        if fragment in lowered:
            return f"looks like a placeholder (contains {fragment!r})"
    return None


class Settings(BaseSettings):
    # hide_input_in_errors keeps a rejected signing key out of the startup error message.
    model_config = SettingsConfigDict(
        env_prefix="APIGUARD_", extra="ignore", hide_input_in_errors=True
    )

    environment: Literal["production", "development", "test"] = "production"
    database_url: str = "postgresql+psycopg://apiguard:apiguard@127.0.0.1:55431/apiguard"
    database_connect_timeout_seconds: int = Field(default=5, ge=1, le=60)

    jwt_signing_key: SecretStr = SecretStr("")
    jwt_issuer: str = "apiguard"
    jwt_audience: str = "apiguard-api"
    access_token_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    refresh_token_ttl_seconds: int = Field(default=14 * 24 * 3600, ge=60)
    refresh_family_max_age_seconds: int = Field(default=30 * 24 * 3600, ge=60)

    # Fixed-window rate limits. Each limit is "attempts per window".
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    login_limit_per_ip: int = Field(default=20, ge=1)
    login_limit_per_account: int = Field(default=5, ge=1)
    refresh_limit_per_ip: int = Field(default=30, ge=1)
    refresh_limit_per_account: int = Field(default=10, ge=1)
    register_limit_per_ip: int = Field(default=10, ge=1)

    # Comma-separated origins. Empty disables CORS entirely.
    cors_origins: str = ""
    enable_docs: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @model_validator(mode="after")
    def _reject_weak_signing_key(self) -> Settings:
        key = self.jwt_signing_key.get_secret_value()
        if self.environment == "test":
            if not key:
                raise WeakSigningKeyError("APIGUARD_JWT_SIGNING_KEY is empty")
            return self
        problem = signing_key_problem(key)
        if problem is not None:
            raise WeakSigningKeyError(
                f"APIGUARD_JWT_SIGNING_KEY {problem}; refusing to start in "
                f"{self.environment!r} mode"
            )
        return self
