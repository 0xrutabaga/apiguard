"""OWASP API2:2023 Broken Authentication.

Forged and stale access tokens, refresh token reuse, and user enumeration through login.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard import passwords, refresh
from apiguard.config import Settings
from apiguard.models import AuditEvent, RefreshToken, User
from apiguard.tokens import issue_access_token
from tests.support import TEST_PASSWORD, World


def _b64(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _claims(settings: Settings, user_id: uuid.UUID, **overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    claims.update(overrides)
    return claims


def _get_me(client: TestClient, token: str) -> int:
    return client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code


# --- forged / stale access tokens -------------------------------------------------------


def test_valid_token_is_accepted(client: TestClient, world: World) -> None:
    assert _get_me(client, issue_access_token(world.settings, world.uid("a_owner"))) == 200


def test_alg_none_token_is_rejected(client: TestClient, world: World) -> None:
    header = _b64({"alg": "none", "typ": "JWT"})
    payload = _b64(_claims(world.settings, world.uid("a_owner")))
    token = f"{header}.{payload}."
    assert _get_me(client, token) == 401


def test_token_signed_with_another_key_is_rejected(client: TestClient, world: World) -> None:
    token = jwt.encode(
        _claims(world.settings, world.uid("a_owner")), secrets.token_urlsafe(48), "HS256"
    )
    assert _get_me(client, token) == 401


def test_expired_token_is_rejected(client: TestClient, world: World) -> None:
    past = datetime.now(UTC) - timedelta(seconds=world.settings.access_token_ttl_seconds + 1)
    assert (
        _get_me(client, issue_access_token(world.settings, world.uid("a_owner"), now=past)) == 401
    )


@pytest.mark.parametrize(
    "override", [{"aud": "another-service"}, {"iss": "someone-else"}, {"typ": "id"}]
)
def test_token_for_another_audience_or_issuer_is_rejected(
    client: TestClient, world: World, override: dict[str, object]
) -> None:
    claims = _claims(world.settings, world.uid("a_owner"), **override)
    token = jwt.encode(claims, world.settings.jwt_signing_key.get_secret_value(), "HS256")
    assert _get_me(client, token) == 401


def test_token_of_deleted_user_is_rejected(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    token = issue_access_token(world.settings, world.uid("outsider"))
    with db.begin() as session:
        session.delete(session.get(User, world.uid("outsider")))
    assert _get_me(client, token) == 401


@pytest.mark.parametrize(
    "header", [None, "", "Bearer", "Basic dXNlcjpwYXNz", "Bearer not.a.jwt", "Token abc"]
)
def test_missing_or_malformed_authorization_header(client: TestClient, header: str | None) -> None:
    headers = {} if header is None else {"Authorization": header}
    response = client.get("/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


# --- refresh token reuse ----------------------------------------------------------------


def _login(client: TestClient, email: str) -> dict[str, str]:
    response = client.post("/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert response.status_code == 200, response.text
    body: dict[str, str] = response.json()
    return body


def test_refresh_token_reuse_revokes_the_whole_family(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    stolen = _login(client, "a_viewer@example.com")["refresh_token"]
    # The legitimate client rotates first...
    legit = client.post("/auth/refresh", json={"refresh_token": stolen}).json()["refresh_token"]
    # ...then the attacker replays the old token.
    replay = client.post("/auth/refresh", json={"refresh_token": stolen})
    assert replay.status_code == 401
    # The legitimate client's current token is now dead too: the family is revoked.
    assert client.post("/auth/refresh", json={"refresh_token": legit}).status_code == 401

    with db() as session:
        rows = session.execute(select(RefreshToken)).scalars().all()
        assert rows and all(row.revoked_at is not None for row in rows)
        events = session.execute(
            select(AuditEvent.event_type).where(AuditEvent.event_type == "refresh_token_reused")
        ).all()
    assert len(events) >= 1


def test_reuse_in_one_family_does_not_affect_other_sessions(
    client: TestClient, world: World
) -> None:
    laptop = _login(client, "a_viewer@example.com")["refresh_token"]
    phone = _login(client, "a_viewer@example.com")["refresh_token"]
    client.post("/auth/refresh", json={"refresh_token": laptop})
    assert client.post("/auth/refresh", json={"refresh_token": laptop}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": phone}).status_code == 200


def test_concurrent_refresh_with_the_same_token_revokes_the_family(
    world: World, db: sessionmaker[Session]
) -> None:
    """Two refreshes with one token: the row lock (SELECT ... FOR UPDATE) serialises them.

    The first rotates; the second sees a used token, which is the reuse signal, and revokes
    the family, including the token the first one just received. Two browser tabs refreshing
    at once therefore log the user out; that is the price of having no grace window.
    """
    with db.begin() as session:
        issued = refresh.start_family(session, world.settings, world.uid("a_viewer"))

    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        with db() as session:
            barrier.wait()
            try:
                refresh.rotate(session, world.settings, issued.token)
                session.commit()
                result = "rotated"
            except refresh.RefreshRejected as exc:
                session.commit()
                result = exc.reason.value
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(outcomes) == ["reused", "rotated"]
    with db() as session:
        rows = (
            session.execute(select(RefreshToken).where(RefreshToken.family_id == issued.family_id))
            .scalars()
            .all()
        )
    # Both the original and the token minted by the winner are revoked.
    assert len(rows) == 2
    assert all(row.revoked_at is not None for row in rows)


# --- user enumeration -------------------------------------------------------------------


def test_login_failure_is_identical_for_unknown_email_and_wrong_password(
    client: TestClient, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real_verify = passwords.verify_password

    def counting_verify(password_hash: str, password: str) -> bool:
        calls.append(password_hash)
        return real_verify(password_hash, password)

    monkeypatch.setattr(passwords, "verify_password", counting_verify)

    unknown = client.post(
        "/auth/login", json={"email": "nobody@example.com", "password": "wrong password!"}
    )
    calls_for_unknown = len(calls)
    wrong = client.post(
        "/auth/login", json={"email": "a_owner@example.com", "password": "wrong password!"}
    )
    calls_for_wrong = len(calls) - calls_for_unknown

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json() == {"detail": "invalid email or password"}
    ignored = {"x-request-id", "date"}
    assert {k: v for k, v in unknown.headers.items() if k not in ignored} == {
        k: v for k, v in wrong.headers.items() if k not in ignored
    }
    # Both paths run exactly one Argon2 verification, so their cost is the same.
    assert calls_for_unknown == calls_for_wrong == 1


def test_failed_login_is_audited_without_storing_the_password(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    client.post("/auth/login", json={"email": "a_owner@example.com", "password": "hunter2-guess"})
    with db() as session:
        event = session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "login_failed")
        ).scalar_one()
    assert event.actor_user_id == world.uid("a_owner")
    assert "hunter2-guess" not in json.dumps(event.detail)
