"""Joining an organisation through an invitation the invitee accepts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import AuditEvent, Invitation, Membership
from tests.support import World


def _invite(
    client: TestClient, world: World, email: str, role: str = "viewer", inviter: str = "a_owner"
) -> dict[str, str]:
    response = client.post(
        f"/orgs/{world.org_a}/invitations",
        json={"email": email, "role": role},
        headers=world.auth(inviter),
    )
    assert response.status_code == 202, response.text
    body: dict[str, str] = response.json()
    return body


def _accept(client: TestClient, world: World, who: str, token: str) -> int:
    return client.post(
        "/invitations/accept", json={"token": token}, headers=world.auth(who)
    ).status_code


def test_invitation_does_not_grant_membership_until_accepted(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    invitation = _invite(client, world, "outsider@example.com")
    assert set(invitation) == {"id", "org_id", "email", "role", "expires_at", "token"}
    # Not a member yet: the org is still invisible to the invitee.
    assert client.get(f"/orgs/{world.org_a}", headers=world.auth("outsider")).status_code == 404

    accepted = client.post(
        "/invitations/accept",
        json={"token": invitation["token"]},
        headers=world.auth("outsider"),
    )
    assert accepted.status_code == 201
    assert accepted.json() == {"id": str(world.org_a), "name": "Org A", "role": "viewer"}
    assert client.get(f"/orgs/{world.org_a}", headers=world.auth("outsider")).status_code == 200
    with db() as session:
        assert session.execute(select(Invitation)).first() is None
        event = session.execute(
            select(AuditEvent).where(
                AuditEvent.event_type == "member_added", AuditEvent.org_id == world.org_a
            )
        ).scalar_one()
    assert event.detail["via"] == "invitation"
    assert event.detail["invited_by"] == str(world.uid("a_owner"))


def test_token_is_single_use(client: TestClient, world: World) -> None:
    token = _invite(client, world, "outsider@example.com")["token"]
    assert _accept(client, world, "outsider", token) == 201
    assert _accept(client, world, "outsider", token) == 404


def test_token_only_works_for_the_invited_email(client: TestClient, world: World) -> None:
    """A forwarded or leaked token is useless to an account with a different email."""
    token = _invite(client, world, "outsider@example.com")["token"]
    assert _accept(client, world, "b_owner", token) == 404
    assert _accept(client, world, "outsider", token) == 201


def test_unknown_expired_and_wrong_email_tokens_look_the_same(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    expired = _invite(client, world, "outsider@example.com")["token"]
    with db.begin() as session:
        invitation = session.execute(select(Invitation)).scalar_one()
        invitation.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    other = _invite(client, world, "someone.else@example.com")["token"]
    responses = [
        client.post("/invitations/accept", json={"token": t}, headers=world.auth("outsider"))
        for t in ("no-such-token", expired, other)
    ]
    assert {r.status_code for r in responses} == {404}
    assert {r.text for r in responses} == {'{"detail":"invalid or expired invitation"}'}


def test_reinvite_replaces_token_and_role(client: TestClient, world: World) -> None:
    first = _invite(client, world, "outsider@example.com", "viewer")
    second = _invite(client, world, "OUTSIDER@example.com", "editor")
    assert first["id"] == second["id"]
    assert _accept(client, world, "outsider", first["token"]) == 404
    assert _accept(client, world, "outsider", second["token"]) == 201
    roles = client.get("/orgs", headers=world.auth("outsider")).json()
    assert roles[0]["role"] == "editor"


def test_existing_member_accepting_gets_409(client: TestClient, world: World) -> None:
    token = _invite(client, world, "a_viewer@example.com", "editor")["token"]
    assert _accept(client, world, "a_viewer", token) == 409


def test_managers_list_and_revoke_invitations(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    invitation = _invite(client, world, "outsider@example.com")
    listed = client.get(f"/orgs/{world.org_a}/invitations", headers=world.auth("a_admin")).json()
    assert [i["id"] for i in listed] == [invitation["id"]]
    assert "token" not in listed[0]
    url = f"/orgs/{world.org_a}/invitations/{invitation['id']}"
    assert client.delete(url, headers=world.auth("a_admin")).status_code == 204
    assert _accept(client, world, "outsider", invitation["token"]) == 404
    with db() as session:
        assert session.get(Membership, (world.org_a, world.uid("outsider"))) is None


def test_admin_cannot_revoke_an_owner_invitation(client: TestClient, world: World) -> None:
    invitation = _invite(client, world, "outsider@example.com", "owner")
    url = f"/orgs/{world.org_a}/invitations/{invitation['id']}"
    assert client.delete(url, headers=world.auth("a_admin")).status_code == 403


def test_invitation_tokens_are_stored_hashed(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    token = _invite(client, world, "outsider@example.com")["token"]
    with db() as session:
        stored = session.execute(select(Invitation.token_hash)).scalar_one()
    assert token.encode() not in stored
    assert len(stored) == 32
