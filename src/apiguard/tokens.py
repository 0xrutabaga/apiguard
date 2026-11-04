"""Short-lived access tokens (JWT, HS256) via PyJWT.

Decoding pins the algorithm allow-list to ``["HS256"]`` and requires ``exp``, ``iat``,
``nbf``, ``iss``, ``aud``, ``sub`` and ``jti``. Tokens carry identity only: roles are read
from the database on every request, so a role change or removal takes effect immediately
rather than when the token expires.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from apiguard.config import Settings

ALGORITHM = "HS256"
ALLOWED_ALGORITHMS = [ALGORITHM]
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]
TOKEN_TYPE = "access"  # noqa: S105 - claim value, not a secret


class InvalidAccessToken(Exception):
    """The presented access token is not acceptable. The reason is for logs, not clients."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    token_id: str
    expires_at: datetime


def issue_access_token(
    settings: Settings, user_id: uuid.UUID, *, now: datetime | None = None
) -> str:
    issued = now or datetime.now(UTC)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(user_id),
        "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()),
        "exp": int((issued + timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": TOKEN_TYPE,
    }
    return jwt.encode(payload, settings.jwt_signing_key.get_secret_value(), algorithm=ALGORITHM)


def decode_access_token(settings: Settings, token: str) -> AccessClaims:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_signing_key.get_secret_value(),
            algorithms=ALLOWED_ALGORITHMS,
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise InvalidAccessToken(type(exc).__name__) from exc

    if payload.get("typ") != TOKEN_TYPE:
        raise InvalidAccessToken("wrong token type")
    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except ValueError as exc:
        raise InvalidAccessToken("malformed subject") from exc
    return AccessClaims(
        user_id=user_id,
        token_id=str(payload["jti"]),
        expires_at=datetime.fromtimestamp(int(payload["exp"]), UTC),
    )
