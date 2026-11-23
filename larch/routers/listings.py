"""Listings (FR-01, FR-02, FR-16)."""

from __future__ import annotations

from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import func, or_, select

from larch import models
from larch.db import utcnow
from larch.deps import AgentDep, DbDep, Principal, ServicesDep, _bearer, get_principal, not_found
from larch.logs import security_event
from larch.models import ListingStatus, Role
from larch.schemas import ListingIn, ListingOut, ListingPatch, ListingSort, Page

router = APIRouter(tags=["listings"])

L = models.Listing
# Sort keys come from this fixed mapping only; the id is a stable tie-breaker.
SORTS = {
    "-created_at": (L.created_at.desc(), L.id.desc()),
    "rent": (L.monthly_rent.asc(), L.created_at.desc(), L.id.desc()),
    "-rent": (L.monthly_rent.desc(), L.created_at.desc(), L.id.desc()),
    "available_from": (L.available_from.asc(), L.created_at.desc(), L.id.desc()),
    "-available_from": (L.available_from.desc(), L.created_at.desc(), L.id.desc()),
}


def listing_out(listing: models.Listing) -> ListingOut:
    return ListingOut.model_validate(listing, from_attributes=True)


def optional_principal(
    services: ServicesDep,
    db: DbDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal | None:
    """The caller if a valid token was sent; anonymous otherwise (stale tokens included)."""
    if credentials is None:
        return None
    try:
        return get_principal(services, db, credentials)
    except HTTPException:
        return None


def can_manage(principal: Principal | None, listing: models.Listing) -> bool:
    return (
        principal is not None
        and principal.role is Role.AGENT
        and principal.user.branch_id == listing.branch_id
    )


@router.get("/listings", response_model=Page[ListingOut])
def list_listings(
    db: DbDep,
    city: Annotated[str | None, Query(max_length=80)] = None,
    min_bedrooms: Annotated[int | None, Query(ge=0, le=10)] = None,
    max_rent: Annotated[int | None, Query(ge=0, le=20_000)] = None,
    available_by: date | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    sort: ListingSort = "-created_at",
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[ListingOut]:
    stmt = select(L).where(L.status == ListingStatus.OPEN.value)
    if city and city.strip():
        stmt = stmt.where(func.lower(L.city) == city.strip().lower())
    if min_bedrooms is not None:
        stmt = stmt.where(L.bedrooms >= min_bedrooms)
    if max_rent is not None:
        stmt = stmt.where(L.monthly_rent <= max_rent)
    if available_by is not None:
        stmt = stmt.where(L.available_from <= available_by)
    if q and q.strip():
        needle = q.strip().lower()
        stmt = stmt.where(
            or_(
                func.lower(L.title).contains(needle, autoescape=True),
                func.lower(L.description).contains(needle, autoescape=True),
            )
        )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(*SORTS[sort]).offset((page - 1) * page_size).limit(page_size))
    return Page[ListingOut](items=[listing_out(r) for r in rows], page=page, page_size=page_size, total=total)


@router.get("/listings/{listing_id}", response_model=ListingOut)
def get_listing(
    listing_id: str, db: DbDep, principal: Annotated[Principal | None, Depends(optional_principal)]
) -> ListingOut:
    listing = db.get(L, listing_id)
    if listing is None:
        raise not_found()
    if listing.status != ListingStatus.OPEN.value:
        allowed = can_manage(principal, listing) or (principal is not None and principal.role is Role.ADMIN)
        if not allowed:
            raise not_found()
    return listing_out(listing)


@router.post("/listings", status_code=status.HTTP_201_CREATED, response_model=ListingOut)
def create_listing(body: ListingIn, agent: AgentDep, db: DbDep) -> ListingOut:
    now = utcnow()
    listing = L(
        **body.model_dump(),
        branch_id=agent.user.branch_id,
        status=ListingStatus.OPEN.value,
        created_by=agent.user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(listing)
    db.commit()
    return listing_out(listing)


@router.patch("/listings/{listing_id}", response_model=ListingOut)
def update_listing(listing_id: str, body: ListingPatch, agent: AgentDep, db: DbDep) -> ListingOut:
    listing = db.get(L, listing_id)
    if listing is None or not can_manage(agent, listing):
        if listing is not None:
            security_event("authorization_denied", "denied", actor_id=agent.user.id, actor_role="agent",
                           target_type="listing", target_id=listing.id, reason="other_branch")
        raise not_found()
    changes = body.changes()
    if "status" in changes:
        changes["status"] = changes["status"].value
    for field, value in changes.items():
        setattr(listing, field, value)
    listing.updated_at = utcnow()
    db.commit()
    return listing_out(listing)
