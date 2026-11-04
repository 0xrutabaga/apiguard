"""Access token issuing and validation (apiguard.tokens)."""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from apiguard.config import Settings
from apiguard.tokens import InvalidAccessToken, decode_access_token, issue_access_token


@pytest.fixture
def settings() -> Settings:
    return Settings.model_validate(
        {"environment": "test", "jwt_signing_key": secrets.token_urlsafe(48)}
    )


def _b64(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _claims(settings: Settings, **overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _sign(
    settings: Settings,
    claims: dict[str, object],
    *,
    key: str | None = None,
    algorithm: str = "HS256",
) -> str:
    return jwt.encode(
        claims, key or settings.jwt_signing_key.get_secret_value(), algorithm=algorithm
    )


def test_round_trip(settings: Settings) -> None:
    user_id = uuid.uuid4()
    claims = decode_access_token(settings, issue_access_token(settings, user_id))
    assert claims.user_id == user_id
    assert claims.expires_at > datetime.now(UTC)


def test_issued_token_lifetime_matches_settings(settings: Settings) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    token = issue_access_token(settings, uuid.uuid4(), now=now)
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] - payload["iat"] == settings.access_token_ttl_seconds


def test_alg_none_is_rejected(settings: Settings) -> None:
    token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(_claims(settings))}."
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


def test_algorithm_outside_allow_list_is_rejected(settings: Settings) -> None:
    token = _sign(settings, _claims(settings), algorithm="HS512")
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


def test_wrong_key_is_rejected(settings: Settings) -> None:
    token = _sign(settings, _claims(settings), key=secrets.token_urlsafe(48))
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


def test_expired_token_is_rejected(settings: Settings) -> None:
    past = datetime.now(UTC) - timedelta(hours=1)
    token = issue_access_token(settings, uuid.uuid4(), now=past)
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


def test_not_yet_valid_token_is_rejected(settings: Settings) -> None:
    future = datetime.now(UTC) + timedelta(hours=1)
    token = issue_access_token(settings, uuid.uuid4(), now=future)
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "some-other-api"},
        {"iss": "https://evil.example"},
        {"typ": "refresh"},
        {"typ": None},
        {"sub": "not-a-uuid"},
    ],
    ids=["wrong-audience", "wrong-issuer", "wrong-type", "missing-type", "malformed-sub"],
)
def test_wrong_claims_are_rejected(settings: Settings, override: dict[str, object]) -> None:
    token = _sign(settings, _claims(settings, **override))
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"])
def test_missing_required_claim_is_rejected(settings: Settings, claim: str) -> None:
    token = _sign(settings, _claims(settings, **{claim: None}))
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, token)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "Bearer x.y.z"])
def test_garbage_is_rejected(settings: Settings, garbage: str) -> None:
    with pytest.raises(InvalidAccessToken):
        decode_access_token(settings, garbage)
