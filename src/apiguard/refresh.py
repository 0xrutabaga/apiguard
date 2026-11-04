"""Opaque refresh tokens with rotation and reuse detection.

* A refresh token is 32 random bytes (``secrets.token_urlsafe``). Only its SHA-256 digest is
  stored; a fast hash is sufficient because the input has 256 bits of entropy and cannot be
  guessed, unlike a password.
* Every login starts a new *family*. Each successful refresh marks the presented token as used
  and issues a new token in the same family.
* Presenting a token that was already used means two parties hold the same token (the client
  and a thief). The whole family is revoked, which logs out both of them.
* The presented row is locked with ``SELECT ... FOR UPDATE``, so two concurrent refreshes with
  the same token are serialised: one rotates, the other is treated as reuse.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from apiguard.config import Settings
from apiguard.models import RefreshToken


class RefreshFailure(StrEnum):
    UNKNOWN = "unknown"
    EXPIRED = "expired"
    REVOKED = "revoked"
    REUSED = "reused"


class RefreshRejected(Exception):
    def __init__(
        self,
        reason: RefreshFailure,
        user_id: uuid.UUID | None = None,
        family_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.user_id = user_id
        self.family_id = family_id


@dataclass(frozen=True)
class IssuedRefreshToken:
    token: str
    user_id: uuid.UUID
    family_id: uuid.UUID
    expires_at: datetime


def hash_refresh_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _issue(
    session: Session,
    settings: Settings,
    user_id: uuid.UUID,
    family_id: uuid.UUID,
    family_expires_at: datetime,
    now: datetime,
) -> IssuedRefreshToken:
    token = secrets.token_urlsafe(32)
    expires_at = min(now + timedelta(seconds=settings.refresh_token_ttl_seconds), family_expires_at)
    session.add(
        RefreshToken(
            family_id=family_id,
            user_id=user_id,
            token_hash=hash_refresh_token(token),
            expires_at=expires_at,
            family_expires_at=family_expires_at,
        )
    )
    return IssuedRefreshToken(
        token=token, user_id=user_id, family_id=family_id, expires_at=expires_at
    )


def start_family(
    session: Session, settings: Settings, user_id: uuid.UUID, *, now: datetime | None = None
) -> IssuedRefreshToken:
    """Issue the first refresh token of a new family (called on login)."""
    now = now or datetime.now(UTC)
    family_expires_at = now + timedelta(seconds=settings.refresh_family_max_age_seconds)
    return _issue(session, settings, user_id, uuid.uuid4(), family_expires_at, now)


def revoke_family(session: Session, family_id: uuid.UUID, *, now: datetime | None = None) -> int:
    """Revoke every still-active token in a family. Returns the number of rows revoked."""
    now = now or datetime.now(UTC)
    result = session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    return int(result.rowcount)  # type: ignore[attr-defined]


def rotate(
    session: Session, settings: Settings, presented: str, *, now: datetime | None = None
) -> IssuedRefreshToken:
    """Exchange a refresh token for a new one in the same family.

    On reuse the family is revoked in ``session`` and RefreshRejected(REUSED) is raised; the
    caller must commit the session before turning the exception into an error response so
    the revocation is not rolled back.
    """
    now = now or datetime.now(UTC)
    row = session.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(presented))
        .with_for_update()
    ).scalar_one_or_none()

    if row is None:
        raise RefreshRejected(RefreshFailure.UNKNOWN)
    if row.used_at is not None:
        revoke_family(session, row.family_id, now=now)
        raise RefreshRejected(RefreshFailure.REUSED, row.user_id, row.family_id)
    if row.revoked_at is not None:
        raise RefreshRejected(RefreshFailure.REVOKED, row.user_id, row.family_id)
    if row.expires_at <= now:
        raise RefreshRejected(RefreshFailure.EXPIRED, row.user_id, row.family_id)

    row.used_at = now
    return _issue(session, settings, row.user_id, row.family_id, row.family_expires_at, now)


def family_of(session: Session, presented: str) -> RefreshToken | None:
    return session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(presented))
    ).scalar_one_or_none()
