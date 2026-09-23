"""Protected document resources demonstrating RBAC + ownership rules.

Policy per action:

* an ``admin`` holder is granted globally (no resource constraint);
* every other holder must have the permission *and* satisfy the action's
  resource constraint (here: document ownership);
* callers who fail authentication/authorization see the same ``404`` as
  callers asking for a missing document, so existence is not disclosed.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.deps import client_source, get_principal, get_store
from app.errors import AuthError, AuthErrorCode
from app.logging_utils import audit
from app.models import Document, User
from app.permissions import Constraint, has_action, is_allowed
from app.store import DataStore

router = APIRouter(prefix="/documents", tags=["documents"])

GLOBAL_ROLES: frozenset[str] = frozenset({"admin"})


def _owns(user: User, resource: Document) -> bool:
    return resource.owner_id == user.id


# Resource-attribute constraints applied to non-global roles.
RESOURCE_CONSTRAINTS: dict[str, Constraint] = {
    "doc:read": _owns,
    "doc:write": _owns,
    # doc:delete has no ownership constraint: it is admin-only. Non-admins
    # never hold it, and admins satisfy the global-role rule.
}


class DocumentIn(BaseModel):
    id: str
    title: str
    content: str = ""


class DocumentOut(BaseModel):
    id: str
    owner_id: str
    title: str
    content: str


def can_access(user: User, action: str, doc: Document) -> bool:
    if not has_action(user, action):
        return False
    if GLOBAL_ROLES.intersection(user.roles):
        return True
    constraint = RESOURCE_CONSTRAINTS.get(action)
    if constraint is None:
        # Action granted only globally; non-global role cannot use it on a
        # specific resource.
        return False
    return is_allowed(
        user, action, doc,
        constraints={action: constraint},
        audit_log=False,
    )


def _load_or_uniform_404(document_id: str, store: DataStore) -> Document:
    doc = store.get_document(document_id)
    if doc is None:
        raise AuthError(AuthErrorCode.NOT_FOUND, status_code=404)
    return doc


def _deny_uniform(user: User, document_id: str, action: str, source: str) -> None:
    audit(
        "document_denied",
        inputs={"user_id": user.id, "document_id": document_id, "action": action,
                "source": source},
        decision="deny",
        basis="permission missing or resource constraint failed; uniform 404",
    )
    raise AuthError(AuthErrorCode.NOT_FOUND, status_code=404)


@router.get("", response_model=list[DocumentOut])
def list_documents(principal=Depends(get_principal), store: DataStore = Depends(get_store)):
    user, _, _ = principal
    if not has_action(user, "doc:read"):
        raise AuthError(AuthErrorCode.FORBIDDEN, status_code=403)
    if GLOBAL_ROLES.intersection(user.roles):
        docs = list(store.documents.values())
    else:
        docs = [d for d in store.documents.values() if d.owner_id == user.id]
    return [DocumentOut(**d.model_dump()) for d in docs]


@router.post("", response_model=DocumentOut, status_code=201)
def create_document(payload: DocumentIn, principal=Depends(get_principal),
                    store: DataStore = Depends(get_store)):
    user, _, _ = principal
    if not has_action(user, "doc:write"):
        raise AuthError(AuthErrorCode.FORBIDDEN, status_code=403)
    if store.get_document(payload.id) is not None:
        raise AuthError(AuthErrorCode.BAD_REQUEST, status_code=400)
    doc = Document(id=payload.id, owner_id=user.id, title=payload.title,
                   content=payload.content)
    store.add_document(doc)
    audit(
        "document_created",
        inputs={"user_id": user.id, "document_id": doc.id},
        decision="allow",
        basis="doc:write held",
    )
    return DocumentOut(**doc.model_dump())


@router.get("/{document_id}", response_model=DocumentOut)
def get_document(document_id: str, request: Request,
                 principal=Depends(get_principal), store: DataStore = Depends(get_store)):
    user, _, _ = principal
    doc = _load_or_uniform_404(document_id, store)
    if not can_access(user, "doc:read", doc):
        _deny_uniform(user, document_id, "doc:read", client_source(request))
    return DocumentOut(**doc.model_dump())


@router.put("/{document_id}", response_model=DocumentOut)
def update_document(document_id: str, payload: DocumentIn, request: Request,
                    principal=Depends(get_principal), store: DataStore = Depends(get_store)):
    user, _, _ = principal
    doc = _load_or_uniform_404(document_id, store)
    if not can_access(user, "doc:write", doc):
        _deny_uniform(user, document_id, "doc:write", client_source(request))
    doc.title = payload.title
    doc.content = payload.content
    return DocumentOut(**doc.model_dump())


@router.delete("/{document_id}", status_code=204)
def delete_document(document_id: str, request: Request,
                    principal=Depends(get_principal), store: DataStore = Depends(get_store)):
    user, _, _ = principal
    doc = _load_or_uniform_404(document_id, store)
    if not can_access(user, "doc:delete", doc):
        _deny_uniform(user, document_id, "doc:delete", client_source(request))
    store.delete_document(doc.id)
