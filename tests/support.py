"""Test helpers shared by the integration and security suites."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import Session, sessionmaker

from apiguard import passwords
from apiguard.config import Settings
from apiguard.models import Document, Membership, Organization, Project, User
from apiguard.tokens import issue_access_token

TEST_PASSWORD = "correct horse battery staple"


def make_settings(database_url: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "database_url": database_url,
        "jwt_signing_key": secrets.token_urlsafe(48),
        # Generous limits so only the rate-limit tests hit them.
        "login_limit_per_ip": 1000,
        "login_limit_per_account": 1000,
        "refresh_limit_per_ip": 1000,
        "refresh_limit_per_account": 1000,
        "register_limit_per_ip": 1000,
    }
    values.update(overrides)
    return Settings.model_validate(values)


# --- a populated two-tenant world ---------------------------------------------------------


@dataclass
class World:
    """Two organisations with members of every role, one project and document in each.

    org_a: a_owner (owner), a_admin (admin), a_editor and a_editor2 (editor), a_viewer
    org_b: b_owner (owner)
    outsider: a user with no membership
    doc_a is owned by a_editor in proj_a; doc_b is owned by b_owner in proj_b.
    """

    settings: Settings
    users: dict[str, User] = field(default_factory=dict)
    org_a: uuid.UUID = field(default_factory=uuid.uuid4)
    org_b: uuid.UUID = field(default_factory=uuid.uuid4)
    proj_a: uuid.UUID = field(default_factory=uuid.uuid4)
    proj_a2: uuid.UUID = field(default_factory=uuid.uuid4)
    proj_b: uuid.UUID = field(default_factory=uuid.uuid4)
    doc_a: uuid.UUID = field(default_factory=uuid.uuid4)
    doc_b: uuid.UUID = field(default_factory=uuid.uuid4)

    def uid(self, name: str) -> uuid.UUID:
        return self.users[name].id

    def auth(self, name: str) -> dict[str, str]:
        token = issue_access_token(self.settings, self.users[name].id)
        return {"Authorization": f"Bearer {token}"}

    def doc_url(self, org: uuid.UUID, project: uuid.UUID, doc: uuid.UUID) -> str:
        return f"/orgs/{org}/projects/{project}/documents/{doc}"

    @property
    def doc_a_url(self) -> str:
        return self.doc_url(self.org_a, self.proj_a, self.doc_a)

    @property
    def doc_b_url(self) -> str:
        return self.doc_url(self.org_b, self.proj_b, self.doc_b)


def build_world(session_factory: sessionmaker[Session], settings: Settings) -> World:
    world = World(settings=settings)
    password_hash = passwords.hash_password(TEST_PASSWORD)
    members = {
        "a_owner": (world.org_a, "owner"),
        "a_admin": (world.org_a, "admin"),
        "a_editor": (world.org_a, "editor"),
        "a_editor2": (world.org_a, "editor"),
        "a_viewer": (world.org_a, "viewer"),
        "b_owner": (world.org_b, "owner"),
        "outsider": (None, None),
    }
    with session_factory.begin() as session:
        session.add_all(
            [Organization(id=world.org_a, name="Org A"), Organization(id=world.org_b, name="Org B")]
        )
        for name in members:
            user = User(email=f"{name}@example.com", display_name=name, password_hash=password_hash)
            session.add(user)
            world.users[name] = user
        session.flush()
        for name, (org, role) in members.items():
            if org is not None and role is not None:
                session.add(Membership(org_id=org, user_id=world.uid(name), role=role))
        session.add_all(
            [
                Project(id=world.proj_a, org_id=world.org_a, name="A project"),
                Project(id=world.proj_a2, org_id=world.org_a, name="A second project"),
                Project(id=world.proj_b, org_id=world.org_b, name="B project"),
            ]
        )
        session.flush()
        session.add_all(
            [
                Document(
                    id=world.doc_a,
                    org_id=world.org_a,
                    project_id=world.proj_a,
                    owner_id=world.uid("a_editor"),
                    title="A plan",
                    body="tenant A data",
                ),
                Document(
                    id=world.doc_b,
                    org_id=world.org_b,
                    project_id=world.proj_b,
                    owner_id=world.uid("b_owner"),
                    title="B plan",
                    body="tenant B data",
                ),
            ]
        )
    return world
