"""OWASP API4:2023 Unrestricted Resource Consumption.

Login, refresh and registration are throttled per client IP and per account, and request
sizes and page sizes are bounded.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import AuditEvent, RateLimitCounter
from apiguard.tokens import issue_access_token
from tests.support import TEST_PASSWORD, World


def _login(client: TestClient, email: str, password: str = "wrong password") -> int:
    return client.post("/auth/login", json={"email": email, "password": password}).status_code


def test_login_is_limited_per_account(
    app_factory: Callable[..., TestClient], world: World, db: sessionmaker[Session]
) -> None:
    client = app_factory(login_limit_per_account=3, login_limit_per_ip=100)
    statuses = [_login(client, "a_owner@example.com") for _ in range(3)]
    assert statuses == [401, 401, 401]

    blocked = client.post(
        "/auth/login", json={"email": "a_owner@example.com", "password": TEST_PASSWORD}
    )
    # Even the correct password is refused while the account is throttled.
    assert blocked.status_code == 429
    retry_after = int(blocked.headers["retry-after"])
    assert 1 <= retry_after <= 60
    # Other accounts from the same IP are unaffected.
    assert _login(client, "a_admin@example.com", TEST_PASSWORD) == 200

    with db() as session:
        events = (
            session.execute(select(AuditEvent).where(AuditEvent.event_type == "rate_limited"))
            .scalars()
            .all()
        )
    assert [e.detail["limit"] for e in events] == ["account"]


def test_account_key_is_case_insensitive(
    app_factory: Callable[..., TestClient], world: World
) -> None:
    client = app_factory(login_limit_per_account=2, login_limit_per_ip=100)
    _login(client, "a_owner@example.com")
    _login(client, "A_OWNER@example.com")
    assert _login(client, "A_Owner@Example.com") == 429


def test_login_is_limited_per_ip(app_factory: Callable[..., TestClient], world: World) -> None:
    client = app_factory(login_limit_per_ip=4, login_limit_per_account=100)
    # Spraying one password across many accounts trips the per-IP limit.
    statuses = [_login(client, f"user{i}@example.com") for i in range(5)]
    assert statuses == [401, 401, 401, 401, 429]


def test_refresh_is_limited_per_ip(app_factory: Callable[..., TestClient], world: World) -> None:
    client = app_factory(refresh_limit_per_ip=2)
    statuses = [
        client.post("/auth/refresh", json={"refresh_token": f"guess-{i}"}).status_code
        for i in range(3)
    ]
    assert statuses == [401, 401, 429]


def test_refresh_is_limited_per_account(
    app_factory: Callable[..., TestClient], world: World
) -> None:
    client = app_factory(refresh_limit_per_account=2, refresh_limit_per_ip=100)
    token = client.post(
        "/auth/login", json={"email": "a_viewer@example.com", "password": TEST_PASSWORD}
    ).json()["refresh_token"]
    for _ in range(2):
        response = client.post("/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 200
        token = response.json()["refresh_token"]
    assert client.post("/auth/refresh", json={"refresh_token": token}).status_code == 429


def test_registration_is_limited_per_ip(app_factory: Callable[..., TestClient]) -> None:
    client = app_factory(register_limit_per_ip=2)
    statuses = [
        client.post(
            "/auth/register",
            json={
                "email": f"r{i}@example.com",
                "password": "long enough password",
                "display_name": "R",
            },
        ).status_code
        for i in range(3)
    ]
    assert statuses == [201, 201, 429]


def test_counters_do_not_store_emails(
    app_factory: Callable[..., TestClient], db: sessionmaker[Session]
) -> None:
    client = app_factory()
    _login(client, "private.person@example.com")
    with db() as session:
        keys = session.execute(select(RateLimitCounter.key)).scalars().all()
    assert keys
    assert not any("private.person" in key for key in keys)


def test_page_size_is_bounded(client: TestClient, world: World) -> None:
    url = f"/orgs/{world.org_a}/projects?limit=1000"
    assert client.get(url, headers=world.auth("a_owner")).status_code == 422


def test_oversized_fields_are_rejected(client: TestClient, world: World) -> None:
    url = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    headers = world.auth("a_editor")
    assert client.post(url, json={"title": "x" * 201}, headers=headers).status_code == 422
    assert (
        client.post(url, json={"title": "ok", "body": "x" * 100_001}, headers=headers).status_code
        == 422
    )


def test_oversized_password_is_rejected_before_hashing(client: TestClient) -> None:
    response = client.post("/auth/login", json={"email": "a@example.com", "password": "x" * 10_000})
    assert response.status_code == 422


def test_invitations_are_limited_per_actor(
    app_factory: Callable[..., TestClient], world: World
) -> None:
    client = app_factory(invite_limit_per_actor=3)
    token = issue_access_token(client.app.state.settings, world.uid("outsider"))
    headers = {"Authorization": f"Bearer {token}"}
    org = client.post("/orgs", json={"name": "probe"}, headers=headers).json()
    statuses = [
        client.post(
            f"/orgs/{org['id']}/invitations",
            json={"email": f"probe{i}@example.com", "role": "viewer"},
            headers=headers,
        ).status_code
        for i in range(4)
    ]
    assert statuses == [202, 202, 202, 429]


def test_a_flood_of_rejected_requests_writes_one_audit_row_per_window(
    app_factory: Callable[..., TestClient], db: sessionmaker[Session]
) -> None:
    client = app_factory(login_limit_per_ip=2, login_limit_per_account=1000)
    statuses = [_login(client, f"flood{i}@example.com") for i in range(30)]
    assert statuses.count(429) == 28
    with db() as session:
        events = (
            session.execute(select(AuditEvent).where(AuditEvent.event_type == "rate_limited"))
            .scalars()
            .all()
        )
    assert len(events) == 1
