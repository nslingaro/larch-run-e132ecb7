"""Applications and their documents (FR-06 to FR-15, FR-19).

Visibility, checked on every request, server side:
- an applicant sees only their own applications;
- an agent sees applications to their own branch's listings, an admin sees every
  branch's; neither ever sees a draft, nor one withdrawn before it was submitted.
Anything else is answered 404, exactly as if it did not exist.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import Select

from larch import models
from larch.db import utcnow
from larch.deps import AgentDep, AnyRoleDep, ApplicantDep, DbDep, Principal, ServicesDep, conflict, not_found
from larch.logs import security_event
from larch.models import ApplicationStatus as S
from larch.models import DocumentKind, ListingStatus, Role
from larch.schemas import (
    ApplicationIn,
    ApplicationOut,
    ApplicationPatch,
    ApplicationStaffOut,
    DecisionIn,
    DocumentOut,
    Page,
)
from larch.storage import StorageError
from larch.uploads import (
    MAX_DOCUMENT_BYTES,
    MAX_DOCUMENTS_PER_APPLICATION,
    MAX_FILENAME_LENGTH,
    UnsupportedFile,
    check_upload,
    clean_filename,
    content_disposition,
)

router = APIRouter(tags=["applications"])

A = models.Application
D = models.Document

ONLY_DRAFTS_CHANGE = "Only draft applications can be changed"
ONLY_FILE_TYPES = "Only PDF, JPEG or PNG files are accepted"
TOO_MANY_DOCUMENTS = "An application can hold at most 10 documents"
REQUIRED_DOCUMENTS = "Photo ID and proof of income are required"

STAFF_VISIBLE = or_(
    A.status.in_([S.SUBMITTED.value, S.APPROVED.value, S.REJECTED.value]),
    and_(A.status == S.WITHDRAWN.value, A.submitted_at.is_not(None)),
)


# --- helpers ---------------------------------------------------------------------


def scope_to_caller(stmt: Select[Any], principal: Principal) -> Select[Any]:
    """Restrict an applications query to what the caller may see."""
    if principal.role is Role.APPLICANT:
        return stmt.where(A.applicant_id == principal.user.id)
    if principal.role is Role.AGENT:
        return stmt.join(models.Listing, A.listing_id == models.Listing.id).where(
            models.Listing.branch_id == principal.user.branch_id, STAFF_VISIBLE
        )
    if principal.role is Role.ADMIN:
        return stmt.where(STAFF_VISIBLE)
    return stmt.where(False)  # fail closed for any unknown role


def load_application(db, principal: Principal, application_id: str, *, lock: bool = False) -> models.Application:
    stmt = scope_to_caller(select(A).where(A.id == application_id), principal)
    if lock:
        stmt = stmt.with_for_update(of=A)
    application = db.scalars(stmt).unique().one_or_none()
    if application is None:
        if db.scalar(select(A.id).where(A.id == application_id)) is not None:
            security_event("authorization_denied", "denied", actor_id=principal.user.id,
                           actor_role=principal.user.role, target_type="application",
                           target_id=application_id, reason="not_visible")
        raise not_found()
    return application


def application_out(application: models.Application, principal: Principal) -> dict[str, Any]:
    model = ApplicationOut if principal.role is Role.APPLICANT else ApplicationStaffOut
    return model.model_validate(application, from_attributes=True).model_dump(mode="json")


def document_out(document: models.Document) -> DocumentOut:
    return DocumentOut(
        id=document.id,
        application_id=document.application_id,
        kind=DocumentKind(document.kind),
        filename=document.original_filename,
        content_type=document.content_type,
        size_bytes=document.size_bytes,
        uploaded_at=document.uploaded_at,
    )


APPLICATION_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {"model": ApplicationStaffOut, "description": "decision_note is present for agents and admins only"}
}


# --- applications ----------------------------------------------------------------


@router.post(
    "/listings/{listing_id}/applications",
    status_code=status.HTTP_201_CREATED,
    response_model=ApplicationOut,
)
def start_application(listing_id: str, body: ApplicationIn, applicant: ApplicantDep, db: DbDep) -> dict[str, Any]:
    listing = db.get(models.Listing, listing_id)
    if listing is None or listing.status != ListingStatus.OPEN.value:
        raise not_found()
    already = select(A.id).where(A.listing_id == listing.id, A.applicant_id == applicant.user.id)
    if db.scalar(already) is not None:
        raise conflict("You have already applied for this listing")
    application = A(
        **body.model_dump(),
        listing_id=listing.id,
        applicant_id=applicant.user.id,
        status=S.DRAFT.value,
        created_at=utcnow(),
    )
    db.add(application)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("You have already applied for this listing") from None
    return application_out(application, applicant)


@router.get("/applications", response_model=Page[ApplicationStaffOut], response_model_exclude_unset=True)
def list_applications(
    principal: AnyRoleDep,
    db: DbDep,
    status_filter: Annotated[S | None, Query(alias="status")] = None,
    listing_id: Annotated[str | None, Query(max_length=36)] = None,
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Response:
    stmt = scope_to_caller(select(A), principal)
    if status_filter is not None:
        stmt = stmt.where(A.status == status_filter.value)
    if listing_id is not None:
        stmt = stmt.where(A.listing_id == listing_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(A.created_at.desc(), A.id.desc()).offset((page - 1) * page_size).limit(page_size)
    ).unique()
    payload = {
        "items": [application_out(a, principal) for a in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }
    # Built per role above; returned as-is so the applicant view cannot gain decision_note.
    return JSONResponse(payload)


@router.get("/applications/{application_id}", response_model=None, responses=APPLICATION_RESPONSES)
def get_application(application_id: str, principal: AnyRoleDep, db: DbDep) -> dict[str, Any]:
    return application_out(load_application(db, principal, application_id), principal)


@router.patch("/applications/{application_id}", response_model=ApplicationOut)
def update_application(
    application_id: str, body: ApplicationPatch, applicant: ApplicantDep, db: DbDep
) -> dict[str, Any]:
    application = load_application(db, applicant, application_id, lock=True)
    if application.status != S.DRAFT.value:
        raise conflict(ONLY_DRAFTS_CHANGE)
    for field, value in body.changes().items():
        setattr(application, field, value)
    db.commit()
    return application_out(application, applicant)


@router.post("/applications/{application_id}/submit", response_model=ApplicationOut)
def submit_application(application_id: str, applicant: ApplicantDep, db: DbDep) -> dict[str, Any]:
    application = load_application(db, applicant, application_id, lock=True)
    if application.status != S.DRAFT.value:
        raise conflict("Only draft applications can be submitted")
    if application.listing.status != ListingStatus.OPEN.value:
        raise conflict("Listing is closed")
    kinds = set(db.scalars(select(D.kind).where(D.application_id == application.id)))
    if not {DocumentKind.PHOTO_ID.value, DocumentKind.PROOF_OF_INCOME.value} <= kinds:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=REQUIRED_DOCUMENTS)
    application.status = S.SUBMITTED.value
    application.submitted_at = utcnow()
    db.commit()
    return application_out(application, applicant)


@router.post("/applications/{application_id}/withdraw", response_model=ApplicationOut)
def withdraw_application(application_id: str, applicant: ApplicantDep, db: DbDep) -> dict[str, Any]:
    application = load_application(db, applicant, application_id, lock=True)
    if application.status not in (S.DRAFT.value, S.SUBMITTED.value):
        raise conflict("Only draft or submitted applications can be withdrawn")
    application.status = S.WITHDRAWN.value
    application.withdrawn_at = utcnow()
    db.commit()
    return application_out(application, applicant)


@router.post("/applications/{application_id}/decision", response_model=ApplicationStaffOut)
def decide_application(application_id: str, body: DecisionIn, agent: AgentDep, db: DbDep) -> dict[str, Any]:
    application = load_application(db, agent, application_id, lock=True)
    if application.status != S.SUBMITTED.value:
        raise conflict("Only submitted applications can be decided")
    application.status = body.decision
    application.decision_note = body.note
    application.decided_by = agent.user.id
    application.decided_at = utcnow()
    db.commit()
    security_event("application_decided", "success", actor_id=agent.user.id, actor_role="agent",
                   target_type="application", target_id=application.id, reason=body.decision)
    return application_out(application, agent)


# --- documents ---------------------------------------------------------------------


@router.post(
    "/applications/{application_id}/documents",
    status_code=status.HTTP_201_CREATED,
    response_model=DocumentOut,
)
def upload_document(
    application_id: str,
    kind: Annotated[DocumentKind, Form()],
    file: Annotated[UploadFile, File()],
    applicant: ApplicantDep,
    db: DbDep,
    services: ServicesDep,
) -> DocumentOut:
    services.limiter.hit("upload_user", applicant.user.id)
    application = load_application(db, applicant, application_id, lock=True)
    if application.status != S.DRAFT.value:
        raise conflict(ONLY_DRAFTS_CHANGE)
    count = db.scalar(select(func.count()).select_from(D).where(D.application_id == application.id)) or 0
    if count >= MAX_DOCUMENTS_PER_APPLICATION:
        raise conflict(TOO_MANY_DOCUMENTS)

    data = file.file.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Documents can be at most 10 MB")
    filename = clean_filename(file.filename)
    if len(filename) > MAX_FILENAME_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="File name is longer than 255 characters"
        )
    try:
        content_type, filename = check_upload(data, file.content_type, filename)
    except UnsupportedFile as exc:
        security_event("document_rejected", "denied", actor_id=applicant.user.id, actor_role="applicant",
                       target_type="application", target_id=application.id, reason=str(exc))
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=ONLY_FILE_TYPES) from None
    # OPEN DECISION: malware scanning. LARCH_MALWARE_SCANNER is "none" until decided.

    storage_key = services.store.new_key()
    blob = services.cipher.encrypt(data, storage_key.encode())
    services.store.put(storage_key, blob.ciphertext)
    document = D(
        application_id=application.id,
        kind=kind.value,
        original_filename=filename,
        content_type=content_type,
        size_bytes=len(data),
        storage_key=storage_key,
        encryption_key_id=blob.key_id,
        wrapped_data_key=blob.wrapped_data_key,
        uploaded_at=utcnow(),
    )
    db.add(document)
    try:
        db.commit()
    except Exception:
        db.rollback()
        services.store.delete(storage_key)
        raise
    security_event("document_uploaded", "success", actor_id=applicant.user.id, actor_role="applicant",
                   target_type="document", target_id=document.id)
    return document_out(document)


@router.get("/applications/{application_id}/documents", response_model=list[DocumentOut])
def list_documents(application_id: str, principal: AnyRoleDep, db: DbDep) -> list[DocumentOut]:
    application = load_application(db, principal, application_id)
    documents = db.scalars(select(D).where(D.application_id == application.id).order_by(D.uploaded_at, D.id))
    return [document_out(d) for d in documents]


def _load_document(db, application: models.Application, document_id: str) -> models.Document:
    document = db.scalar(select(D).where(D.id == document_id, D.application_id == application.id))
    if document is None:
        raise not_found()
    return document


@router.get(
    "/applications/{application_id}/documents/{document_id}/content",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}, "image/jpeg": {}, "image/png": {}}}},
)
def download_document(
    application_id: str, document_id: str, principal: AnyRoleDep, db: DbDep, services: ServicesDep
) -> Response:
    services.limiter.hit("download_user", principal.user.id)
    application = load_application(db, principal, application_id)
    document = _load_document(db, application, document_id)
    ciphertext = services.store.get(document.storage_key)
    data = services.cipher.decrypt(
        document.encryption_key_id, document.wrapped_data_key, ciphertext, document.storage_key.encode()
    )
    security_event("document_downloaded", "success", actor_id=principal.user.id, actor_role=principal.user.role,
                   target_type="document", target_id=document.id)
    return Response(
        content=data,
        media_type=document.content_type,
        headers={
            "Content-Disposition": content_disposition(document.original_filename),
            # Never rendered as a page on the API's origin, even if opened directly.
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
        },
    )


@router.delete(
    "/applications/{application_id}/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def delete_document(
    application_id: str, document_id: str, applicant: ApplicantDep, db: DbDep, services: ServicesDep
) -> Response:
    application = load_application(db, applicant, application_id, lock=True)
    document = _load_document(db, application, document_id)
    if application.status != S.DRAFT.value:
        raise conflict(ONLY_DRAFTS_CHANGE)
    storage_key = document.storage_key
    db.delete(document)
    db.commit()
    # The wrapped data key went with the row, so the file is already unreadable; remove it too.
    try:
        services.store.delete(storage_key)
    except StorageError:
        security_event("document_file_delete_failed", "failure", target_type="document", target_id=document_id)
    security_event("document_deleted", "success", actor_id=applicant.user.id, actor_role="applicant",
                   target_type="document", target_id=document_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
