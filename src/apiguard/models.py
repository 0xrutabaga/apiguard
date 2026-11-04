"""SQLAlchemy 2 ORM models.

Tenant consistency is enforced by the schema, not only by application code:

* ``documents`` references ``projects`` through the composite key ``(project_id, org_id)``,
  so a document can never sit in a project that belongs to a different organisation.
* ``document_shares`` references ``memberships`` through ``(org_id, user_id)``, so a document
  can only be shared with a current member of the same organisation, and removing a member
  deletes that member's shares.
* ``audit_events`` has no foreign keys on purpose: security records must outlive the rows
  they describe. A trigger created in the migration rejects UPDATE and DELETE.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

ROLE_VALUES = ("owner", "admin", "editor", "viewer")
SHARE_VALUES = ("read", "edit")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _now_column() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = _now_column()


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = _now_column()


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        CheckConstraint(f"role IN {ROLE_VALUES!r}", name="role_valid"),
        Index("ix_memberships_user_id", "user_id"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = _now_column()


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        # Target of the composite foreign key from documents.
        UniqueConstraint("id", "org_id"),
        Index("ix_projects_org_id", "org_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = _now_column()


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["project_id", "org_id"],
            ["projects.id", "projects.org_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "org_id"),
        Index("ix_documents_org_id_project_id", "org_id", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = _now_column()
    # Set by the database on every UPDATE (database clock, like created_at).
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class DocumentShare(Base):
    __tablename__ = "document_shares"
    __table_args__ = (
        ForeignKeyConstraint(
            ["document_id", "org_id"],
            ["documents.id", "documents.org_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["org_id", "user_id"],
            ["memberships.org_id", "memberships.user_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"permission IN {SHARE_VALUES!r}", name="permission_valid"),
        Index("ix_document_shares_org_id_user_id", "org_id", "user_id"),
    )

    document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    org_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    permission: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[datetime] = _now_column()


class RefreshToken(Base):
    """One row per issued refresh token. Only the SHA-256 of the token is stored."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (Index("ix_refresh_tokens_family_id", "family_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    family_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    created_at: Mapped[datetime] = _now_column()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    family_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RateLimitCounter(Base):
    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_id_id", "org_id", "id"),
        Index("ix_audit_events_actor_user_id_id", "actor_user_id", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = _now_column()
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column()
    org_id: Mapped[uuid.UUID | None] = mapped_column()
    request_id: Mapped[str | None] = mapped_column(String(64))
    client_ip: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
