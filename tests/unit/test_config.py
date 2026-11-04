"""Settings validation (apiguard.config)."""

from __future__ import annotations

import secrets

import pytest
from pydantic import ValidationError

from apiguard.config import Settings, signing_key_problem

STRONG = secrets.token_urlsafe(48)

WEAK_KEYS = [
    "",
    "short",
    "a" * 64,  # long but a single character
    "ab" * 20,  # long but two characters
    "replace-with-output-of-the-command-above",  # the .env.example placeholder
    "my-super-secret-jwt-key-for-production-1234",
    "changeme-changeme-changeme-0123456789",
]


def _settings(**values: object) -> Settings:
    return Settings.model_validate(values)


@pytest.mark.parametrize("environment", ["production", "development"])
@pytest.mark.parametrize("key", WEAK_KEYS)
def test_weak_keys_are_refused_outside_test_mode(environment: str, key: str) -> None:
    with pytest.raises(ValidationError, match="APIGUARD_JWT_SIGNING_KEY"):
        _settings(environment=environment, jwt_signing_key=key)


def test_default_settings_refuse_to_load_without_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APIGUARD_JWT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("APIGUARD_ENVIRONMENT", raising=False)
    with pytest.raises(ValidationError, match="refusing to start in 'production' mode"):
        Settings()


def test_strong_key_is_accepted_in_production() -> None:
    settings = _settings(environment="production", jwt_signing_key=STRONG)
    assert settings.jwt_signing_key.get_secret_value() == STRONG


def test_test_mode_accepts_a_weak_but_non_empty_key() -> None:
    _settings(environment="test", jwt_signing_key="short")
    with pytest.raises(ValidationError):
        _settings(environment="test", jwt_signing_key="")


def test_key_is_not_shown_in_repr() -> None:
    settings = _settings(environment="production", jwt_signing_key=STRONG)
    assert STRONG not in repr(settings)
    assert STRONG not in str(settings.model_dump())


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APIGUARD_JWT_SIGNING_KEY", STRONG)
    monkeypatch.setenv("APIGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("APIGUARD_CORS_ORIGINS", "https://a.example, https://b.example")
    settings = Settings()
    assert settings.environment == "development"
    assert settings.cors_origin_list == ["https://a.example", "https://b.example"]


def test_cors_is_off_by_default() -> None:
    assert _settings(environment="test", jwt_signing_key="k").cors_origin_list == []


def test_signing_key_problem_accepts_random_keys() -> None:
    for _ in range(20):
        assert signing_key_problem(secrets.token_urlsafe(48)) is None
