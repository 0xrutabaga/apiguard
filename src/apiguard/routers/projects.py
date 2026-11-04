"""Projects and the documents inside them."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from apiguard.authz import authorize_document, authorize_org, load_project, not_found
from apiguard.deps import ContextDep, CurrentUser, SessionDep, SessionFactoryDep
from apiguard.models import Document, DocumentShare, Membership, Project
from apiguard.policy import Action, visible_documents_clause
from apiguard.schemas import (
    DocumentCreate,
    DocumentOut,
    DocumentUpdate,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    ShareOut,
    ShareUpdate,
)

router = APIRouter(prefix="/orgs/{org_id}/projects", tags=["projects"])

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ProjectOut)
def create_project(
    org_id: uuid.UUID,
    body: ProjectCreate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> Project:
    authorize_org(session, user.id, org_id, Action.PROJECT_CREATE, session_factory=factory, ctx=ctx)
    project = Project(org_id=org_id, name=body.name)
    session.add(project)
    session.commit()
    return project


@router.get("", response_model=list[ProjectOut])
def list_projects(
    org_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[Project]:
    authorize_org(session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx)
    return list(
        session.execute(
            select(Project)
            .where(Project.org_id == org_id)
            .order_by(Project.created_at, Project.id)
            .limit(limit)
            .offset(offset)
        ).scalars()
    )


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> Project:
    authorize_org(session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx)
    return load_project(session, org_id, project_id)


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    body: ProjectUpdate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> Project:
    authorize_org(session, user.id, org_id, Action.PROJECT_UPDATE, session_factory=factory, ctx=ctx)
    project = load_project(session, org_id, project_id)
    project.name = body.name
    session.commit()
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> None:
    authorize_org(session, user.id, org_id, Action.PROJECT_DELETE, session_factory=factory, ctx=ctx)
    session.delete(load_project(session, org_id, project_id))
    session.commit()


# --- documents -------------------------------------------------------------------------


@router.post(
    "/{project_id}/documents", status_code=status.HTTP_201_CREATED, response_model=DocumentOut
)
def create_document(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    body: DocumentCreate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> Document:
    authorize_org(
        session, user.id, org_id, Action.DOCUMENT_CREATE, session_factory=factory, ctx=ctx
    )
    load_project(session, org_id, project_id)
    # org_id, project_id and owner_id come from the URL and the token, never from the body.
    document = Document(
        org_id=org_id, project_id=project_id, owner_id=user.id, title=body.title, body=body.body
    )
    session.add(document)
    session.commit()
    return document


@router.get("/{project_id}/documents", response_model=list[DocumentOut])
def list_documents(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[Document]:
    actor = authorize_org(
        session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx
    )
    load_project(session, org_id, project_id)
    return list(
        session.execute(
            select(Document)
            .where(Document.project_id == project_id, visible_documents_clause(actor))
            .order_by(Document.created_at, Document.id)
            .limit(limit)
            .offset(offset)
        ).scalars()
    )


@router.get("/{project_id}/documents/{document_id}", response_model=DocumentOut)
def get_document(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> Document:
    actor = authorize_org(
        session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx
    )
    document = authorize_document(
        session,
        actor,
        Action.DOCUMENT_READ,
        org_id,
        project_id,
        document_id,
        session_factory=factory,
        ctx=ctx,
    )
    return document


@router.patch("/{project_id}/documents/{document_id}", response_model=DocumentOut)
def update_document(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    body: DocumentUpdate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> Document:
    actor = authorize_org(
        session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx
    )
    document = authorize_document(
        session,
        actor,
        Action.DOCUMENT_UPDATE,
        org_id,
        project_id,
        document_id,
        session_factory=factory,
        ctx=ctx,
        for_update=True,
    )
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(422, "no fields to update")
    # Explicit allow-list: only these attributes can ever be written from a request.
    for field in ("title", "body"):
        if field in changes:
            setattr(document, field, changes[field])
    session.commit()
    return document


@router.delete("/{project_id}/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> None:
    actor = authorize_org(
        session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx
    )
    document = authorize_document(
        session,
        actor,
        Action.DOCUMENT_DELETE,
        org_id,
        project_id,
        document_id,
        session_factory=factory,
        ctx=ctx,
        for_update=True,
    )
    session.delete(document)
    session.commit()


@router.put("/{project_id}/documents/{document_id}/shares/{share_user_id}", response_model=ShareOut)
def share_document(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    share_user_id: uuid.UUID,
    body: ShareUpdate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> DocumentShare:
    actor = authorize_org(
        session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx
    )
    authorize_document(
        session,
        actor,
        Action.DOCUMENT_SHARE,
        org_id,
        project_id,
        document_id,
        session_factory=factory,
        ctx=ctx,
    )
    if session.get(Membership, (org_id, share_user_id)) is None:
        # Shares never cross the tenant boundary; the schema enforces this as well.
        raise not_found()
    share = session.get(DocumentShare, (document_id, share_user_id))
    if share is None:
        share = DocumentShare(
            document_id=document_id,
            user_id=share_user_id,
            org_id=org_id,
            permission=body.permission.value,
        )
        session.add(share)
    else:
        share.permission = body.permission.value
    session.commit()
    return share


@router.delete(
    "/{project_id}/documents/{document_id}/shares/{share_user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unshare_document(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    share_user_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> None:
    actor = authorize_org(
        session, user.id, org_id, Action.PROJECT_READ, session_factory=factory, ctx=ctx
    )
    authorize_document(
        session,
        actor,
        Action.DOCUMENT_SHARE,
        org_id,
        project_id,
        document_id,
        session_factory=factory,
        ctx=ctx,
    )
    share = session.get(DocumentShare, (document_id, share_user_id))
    if share is None:
        raise not_found()
    session.delete(share)
    session.commit()
