"""Registration, login, refresh rotation and logout over HTTP against PostgreSQL."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import RefreshToken, User
from apiguard.refresh import hash_refresh_token

PASSWORD = "a sufficiently long password"


def register(client: TestClient, email: str = "alice@example.com") -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "display_name": "Alice"},
    )
    assert response.status_code == 201, response.text
    body: dict[str, str] = response.json()
    return body


def login(client: TestClient, email: str = "alice@example.com") -> dict[str, str]:
    response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    body: dict[str, str] = response.json()
    return body


def bearer(tokens: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_register_login_me(client: TestClient) -> None:
    user = register(client)
    assert set(user) == {"id", "email", "display_name"}
    tokens = login(client)
    assert tokens["token_type"] == "bearer"
    me = client.get("/me", headers=bearer(tokens))
    assert me.status_code == 200
    assert me.json()["id"] == user["id"]


def test_email_is_case_insensitive(client: TestClient) -> None:
    register(client, "Bob@Example.COM")
    login(client, "bob@example.com")
    duplicate = client.post(
        "/auth/register",
        json={"email": "BOB@example.com", "password": PASSWORD, "display_name": "B"},
    )
    assert duplicate.status_code == 409


def test_password_policy(client: TestClient) -> None:
    for password in ["short", "x" * 129]:
        response = client.post(
            "/auth/register",
            json={"email": "c@example.com", "password": password, "display_name": "C"},
        )
        assert response.status_code == 422


def test_password_is_stored_as_argon2id(client: TestClient, db: sessionmaker[Session]) -> None:
    register(client)
    with db() as session:
        stored = session.execute(select(User.password_hash)).scalar_one()
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_refresh_rotates_and_old_token_stops_working(
    client: TestClient, db: sessionmaker[Session]
) -> None:
    register(client)
    first = login(client)
    second = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    rotated = second.json()
    assert rotated["refresh_token"] != first["refresh_token"]
    assert client.get("/me", headers=bearer(rotated)).status_code == 200

    with db() as session:
        rows = session.execute(select(RefreshToken)).scalars().all()
    assert len(rows) == 2
    assert len({row.family_id for row in rows}) == 1
    # Only hashes are stored.
    stored = {row.token_hash for row in rows}
    assert hash_refresh_token(first["refresh_token"]) in stored
    assert all(first["refresh_token"].encode() != h for h in stored)


def test_refresh_chain(client: TestClient) -> None:
    register(client)
    token = login(client)["refresh_token"]
    for _ in range(5):
        response = client.post("/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 200
        token = response.json()["refresh_token"]


def test_logout_revokes_the_family(client: TestClient) -> None:
    register(client)
    tokens = login(client)
    rotated = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
    response = client.post(
        "/auth/logout", json={"refresh_token": rotated["refresh_token"]}, headers=bearer(rotated)
    )
    assert response.status_code == 204
    after = client.post("/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
    assert after.status_code == 401


def test_logout_needs_matching_user(client: TestClient) -> None:
    register(client, "a@example.com")
    register(client, "b@example.com")
    a = login(client, "a@example.com")
    b = login(client, "b@example.com")
    response = client.post(
        "/auth/logout", json={"refresh_token": a["refresh_token"]}, headers=bearer(b)
    )
    assert response.status_code == 401
    # A's session is untouched.
    assert (
        client.post("/auth/refresh", json={"refresh_token": a["refresh_token"]}).status_code == 200
    )


def test_unknown_refresh_token(client: TestClient) -> None:
    response = client.post("/auth/refresh", json={"refresh_token": "not-a-token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid refresh token"}


def test_expired_refresh_token(client: TestClient, db: sessionmaker[Session]) -> None:
    register(client)
    tokens = login(client)
    with db.begin() as session:
        row = session.execute(select(RefreshToken)).scalar_one()
        # Expiry is compared with the application clock, so set it from that clock.
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    response = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 401


def test_password_whitespace_is_significant(client: TestClient) -> None:
    padded = "  padded password with spaces  "
    response = client.post(
        "/auth/register",
        json={"email": "pad@example.com", "password": padded, "display_name": "  Pad  "},
    )
    assert response.status_code == 201
    assert response.json()["display_name"] == "Pad"  # names are trimmed

    def status(password: str) -> int:
        return client.post(
            "/auth/login", json={"email": " pad@example.com ", "password": password}
        ).status_code

    assert status(padded) == 200
    assert status(padded.strip()) == 401


def test_blank_names_are_rejected_after_trimming(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"email": "blank@example.com", "password": PASSWORD, "display_name": "   "},
    )
    assert response.status_code == 422
