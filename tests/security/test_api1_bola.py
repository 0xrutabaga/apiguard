"""OWASP API1:2023 Broken Object Level Authorization.

Every test uses real ids of objects that exist. Protection must not depend on ids being hard
to guess, so the attacker in each test is assumed to know them.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import Document, DocumentShare
from tests.support import World

NOT_FOUND = {"detail": "not found"}


def _doc_body(db: sessionmaker[Session], world: World, doc: str) -> str:
    with db() as session:
        return session.execute(
            select(Document.body).where(Document.id == getattr(world, doc))
        ).scalar_one()


@pytest.mark.parametrize("attacker", ["b_owner", "outsider"])
def test_cross_tenant_document_read_is_404(client: TestClient, world: World, attacker: str) -> None:
    response = client.get(world.doc_a_url, headers=world.auth(attacker))
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


@pytest.mark.parametrize("attacker", ["b_owner", "outsider"])
def test_cross_tenant_document_update_and_delete_change_nothing(
    client: TestClient, world: World, db: sessionmaker[Session], attacker: str
) -> None:
    headers = world.auth(attacker)
    assert client.patch(world.doc_a_url, json={"body": "pwned"}, headers=headers).status_code == 404
    assert client.delete(world.doc_a_url, headers=headers).status_code == 404
    assert _doc_body(db, world, "doc_a") == "tenant A data"


def test_404_for_foreign_document_is_identical_to_404_for_missing_document(
    client: TestClient, world: World
) -> None:
    """The response must not reveal whether a foreign id exists."""
    headers = world.auth("b_owner")
    foreign = client.get(world.doc_a_url, headers=headers)
    missing = client.get(world.doc_url(world.org_a, world.proj_a, uuid.uuid4()), headers=headers)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_foreign_document_id_under_own_org_url_is_404(client: TestClient, world: World) -> None:
    """Org B's owner puts org A's document id under org B's own (authorised) URL."""
    url = world.doc_url(world.org_b, world.proj_b, world.doc_a)
    assert client.get(url, headers=world.auth("b_owner")).status_code == 404


def test_foreign_project_id_under_own_org_url_is_404(client: TestClient, world: World) -> None:
    url = world.doc_url(world.org_b, world.proj_a, world.doc_a)
    assert client.get(url, headers=world.auth("b_owner")).status_code == 404
    response = client.get(
        f"/orgs/{world.org_b}/projects/{world.proj_a}", headers=world.auth("b_owner")
    )
    assert response.status_code == 404


def test_document_under_wrong_project_of_same_org_is_404(client: TestClient, world: World) -> None:
    url = world.doc_url(world.org_a, world.proj_a2, world.doc_a)
    assert client.get(url, headers=world.auth("a_owner")).status_code == 404


def test_cross_tenant_listing_is_404(client: TestClient, world: World) -> None:
    headers = world.auth("b_owner")
    assert client.get(f"/orgs/{world.org_a}/projects", headers=headers).status_code == 404
    url = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    assert client.get(url, headers=headers).status_code == 404
    assert client.get(f"/orgs/{world.org_a}/members", headers=headers).status_code == 404


def test_cross_tenant_document_create_is_404(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    url = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    response = client.post(url, json={"title": "planted"}, headers=world.auth("b_owner"))
    assert response.status_code == 404
    with db() as session:
        assert session.execute(select(Document).where(Document.title == "planted")).first() is None


def test_creating_into_a_foreign_project_via_own_org_is_404(
    client: TestClient, world: World
) -> None:
    url = f"/orgs/{world.org_b}/projects/{world.proj_a}/documents"
    response = client.post(url, json={"title": "planted"}, headers=world.auth("b_owner"))
    assert response.status_code == 404


def test_intra_tenant_private_document_is_invisible_to_other_editor(
    client: TestClient, world: World
) -> None:
    """BOLA inside one tenant: a_editor2 is in the same org but has no share on doc_a."""
    headers = world.auth("a_editor2")
    assert client.get(world.doc_a_url, headers=headers).status_code == 404
    listing = client.get(
        f"/orgs/{world.org_a}/projects/{world.proj_a}/documents", headers=headers
    ).json()
    assert listing == []


def test_share_grants_read_and_revocation_removes_it(client: TestClient, world: World) -> None:
    share_url = f"{world.doc_a_url}/shares/{world.uid('a_editor2')}"
    owner = world.auth("a_editor")
    reader = world.auth("a_editor2")
    assert client.put(share_url, json={"permission": "read"}, headers=owner).status_code == 200
    assert client.get(world.doc_a_url, headers=reader).status_code == 200
    assert client.delete(share_url, headers=owner).status_code == 204
    assert client.get(world.doc_a_url, headers=reader).status_code == 404


def test_cannot_share_with_a_user_from_another_tenant(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    share_url = f"{world.doc_a_url}/shares/{world.uid('b_owner')}"
    response = client.put(share_url, json={"permission": "edit"}, headers=world.auth("a_owner"))
    assert response.status_code == 404
    assert client.get(world.doc_a_url, headers=world.auth("b_owner")).status_code == 404
    with db() as session:
        assert session.execute(select(DocumentShare)).first() is None


def test_database_rejects_cross_tenant_share_even_without_the_api(
    db: sessionmaker[Session], world: World
) -> None:
    """Defence in depth: the composite foreign key forbids the row itself."""
    with pytest.raises(IntegrityError), db.begin() as session:
        session.add(
            DocumentShare(
                document_id=world.doc_a,
                user_id=world.uid("b_owner"),
                org_id=world.org_a,
                permission="read",
            )
        )


def test_database_rejects_document_in_foreign_project(
    db: sessionmaker[Session], world: World
) -> None:
    with pytest.raises(IntegrityError), db.begin() as session:
        session.add(
            Document(
                org_id=world.org_a,
                project_id=world.proj_b,
                owner_id=world.uid("a_owner"),
                title="mismatched",
                body="",
            )
        )


def test_removed_member_loses_access_immediately(client: TestClient, world: World) -> None:
    editor = world.auth("a_editor")  # token issued before removal stays cryptographically valid
    assert client.get(world.doc_a_url, headers=editor).status_code == 200
    response = client.delete(
        f"/orgs/{world.org_a}/members/{world.uid('a_editor')}", headers=world.auth("a_owner")
    )
    assert response.status_code == 204
    assert client.get(world.doc_a_url, headers=editor).status_code == 404


def test_audit_trail_does_not_reveal_whether_an_invisible_document_exists(
    client: TestClient, world: World
) -> None:
    """The caller can read their own audit events, so those must not be an existence oracle.

    a_editor2 is a member of org A but cannot see doc_a. Probing doc_a and a random id must
    leave events that differ only in the id the caller supplied themselves.
    """
    headers = world.auth("a_editor2")
    missing_id = uuid.uuid4()
    for doc in (world.doc_a, missing_id):
        response = client.get(world.doc_url(world.org_a, world.proj_a, doc), headers=headers)
        assert response.status_code == 404
    events = client.get("/me/audit-events", headers=headers).json()
    denials = [e for e in reversed(events) if e["event_type"] == "permission_denied"]
    assert [e["detail"]["document_id"] for e in denials] == [str(world.doc_a), str(missing_id)]
    stripped = [{k: v for k, v in e["detail"].items() if k != "document_id"} for e in denials]
    assert (
        stripped[0]
        == stripped[1]
        == {
            "action": "document.read",
            "reason": "not found or not visible",
            "status": 404,
        }
    )
