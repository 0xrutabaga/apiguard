"""OWASP API3:2023 Broken Object Property Level Authorization.

Two halves: clients cannot write properties they should not control (mass assignment), and
responses do not expose properties clients should not see (excessive data exposure).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import Document, Membership, User
from tests.support import World


@pytest.mark.parametrize(
    "extra",
    [
        {"org_id": "00000000-0000-0000-0000-000000000000"},
        {"owner_id": "00000000-0000-0000-0000-000000000000"},
        {"project_id": "00000000-0000-0000-0000-000000000000"},
        {"id": "00000000-0000-0000-0000-000000000000"},
    ],
    ids=lambda d: next(iter(d)),
)
def test_document_create_rejects_server_controlled_fields(
    client: TestClient, world: World, db: sessionmaker[Session], extra: dict[str, str]
) -> None:
    url = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    response = client.post(url, json={"title": "t", **extra}, headers=world.auth("a_editor"))
    assert response.status_code == 422
    with db() as session:
        assert session.execute(select(Document).where(Document.title == "t")).first() is None


@pytest.mark.parametrize(
    "extra",
    [
        {"owner_id": "self"},
        {"org_id": "self"},
        {"project_id": "self"},
        {"created_at": "2000-01-01T00:00:00Z"},
    ],
    ids=lambda d: next(iter(d)),
)
def test_document_update_rejects_server_controlled_fields(
    client: TestClient, world: World, db: sessionmaker[Session], extra: dict[str, str]
) -> None:
    replacements = {
        "owner_id": world.uid("a_editor2"),
        "org_id": world.org_b,
        "project_id": world.proj_a2,
    }
    body = {k: str(replacements.get(k, v)) for k, v in extra.items()}
    response = client.patch(
        world.doc_a_url, json={"title": "renamed", **body}, headers=world.auth("a_editor")
    )
    assert response.status_code == 422
    with db() as session:
        document = session.get(Document, world.doc_a)
        assert document is not None
        assert document.title == "A plan"
        assert document.owner_id == world.uid("a_editor")
        assert document.org_id == world.org_a


def test_registration_cannot_set_role_or_hash(
    client: TestClient, db: sessionmaker[Session]
) -> None:
    for extra in ({"role": "owner"}, {"password_hash": "$argon2id$forged"}, {"id": "x"}):
        response = client.post(
            "/auth/register",
            json={
                "email": "mallory@example.com",
                "password": "long enough password",
                "display_name": "M",
                **extra,
            },
        )
        assert response.status_code == 422
    with db() as session:
        assert session.execute(select(User)).first() is None


def test_role_update_accepts_only_role(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    url = f"/orgs/{world.org_a}/members/{world.uid('a_viewer')}"
    response = client.patch(
        url, json={"role": "editor", "org_id": str(world.org_b)}, headers=world.auth("a_owner")
    )
    assert response.status_code == 422
    with db() as session:
        membership = session.get(Membership, (world.org_a, world.uid("a_viewer")))
        assert membership is not None and membership.role == "viewer"


def test_org_create_cannot_smuggle_membership(client: TestClient, world: World) -> None:
    response = client.post(
        "/orgs",
        json={"name": "x", "owner_id": str(world.uid("a_owner"))},
        headers=world.auth("outsider"),
    )
    assert response.status_code == 422


def test_owner_of_new_document_is_the_caller(client: TestClient, world: World) -> None:
    url = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    created = client.post(url, json={"title": "mine"}, headers=world.auth("a_editor2")).json()
    assert created["owner_id"] == str(world.uid("a_editor2"))
    assert created["org_id"] == str(world.org_a)


# --- excessive data exposure ------------------------------------------------------------

FORBIDDEN_KEYS = {"password_hash", "token_hash", "family_id"}


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for item in value.values():
            keys |= _all_keys(item)
        return keys
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value)) if value else set()
    return set()


def test_responses_never_contain_secrets(client: TestClient, world: World) -> None:
    owner = world.auth("a_owner")
    responses = [
        client.get("/me", headers=owner),
        client.get("/orgs", headers=owner),
        client.get(f"/orgs/{world.org_a}/members", headers=owner),
        client.get(world.doc_a_url, headers=owner),
        client.post(
            "/auth/register",
            json={
                "email": "new@example.com",
                "password": "long enough password",
                "display_name": "N",
            },
        ),
    ]
    for response in responses:
        assert response.status_code in (200, 201), response.text
        assert not (_all_keys(response.json()) & FORBIDDEN_KEYS), response.request.url
        assert "$argon2" not in response.text


def test_member_listing_shows_only_profile_fields(client: TestClient, world: World) -> None:
    members = client.get(f"/orgs/{world.org_a}/members", headers=world.auth("a_viewer")).json()
    assert members
    assert all(set(m) == {"user_id", "email", "display_name", "role"} for m in members)
