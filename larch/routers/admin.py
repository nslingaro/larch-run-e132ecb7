"""Branches and agent accounts (FR-17, FR-18)."""

from __future__ import annotations

from fastapi import APIRouter, status
from fastapi.exceptions import RequestValidationError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from larch import models
from larch.db import utcnow
from larch.deps import AdminDep, DbDep, ServicesDep, conflict, not_found
from larch.logs import security_event
from larch.models import Role
from larch.routers.auth import user_out
from larch.schemas import AgentIn, AgentPatch, BranchIn, BranchOut, UserOut

router = APIRouter(tags=["branches and agents"])


def branch_out(branch: models.Branch) -> BranchOut:
    return BranchOut(id=branch.id, name=branch.name, city=branch.city)


@router.get("/branches", response_model=list[BranchOut])
def list_branches(db: DbDep) -> list[BranchOut]:
    branches = db.scalars(select(models.Branch).order_by(models.Branch.name_key))
    return [branch_out(b) for b in branches]


@router.post("/admin/branches", status_code=status.HTTP_201_CREATED, response_model=BranchOut)
def create_branch(body: BranchIn, admin: AdminDep, db: DbDep) -> BranchOut:
    name_key = body.name.lower()
    if db.scalar(select(models.Branch.id).where(models.Branch.name_key == name_key)):
        raise conflict("A branch with this name already exists")
    branch = models.Branch(name=body.name, name_key=name_key, city=body.city, created_at=utcnow())
    db.add(branch)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("A branch with this name already exists") from None
    security_event("branch_created", "success", actor_id=admin.user.id, actor_role="admin",
                   target_type="branch", target_id=branch.id)
    return branch_out(branch)


@router.get("/admin/agents", response_model=list[UserOut])
def list_agents(admin: AdminDep, db: DbDep) -> list[UserOut]:
    agents = db.scalars(
        select(models.User)
        .where(models.User.role == Role.AGENT.value)
        .order_by(models.User.created_at, models.User.id)
    )
    return [user_out(a) for a in agents]


@router.post("/admin/agents", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def create_agent(body: AgentIn, admin: AdminDep, db: DbDep, services: ServicesDep) -> UserOut:
    if db.get(models.Branch, body.branch_id) is None:
        raise RequestValidationError(
            [{"type": "value_error", "loc": ("body", "branch_id"), "msg": "Branch does not exist"}]
        )
    email_key = body.email.lower()
    if db.scalar(select(models.User.id).where(models.User.email_key == email_key)):
        raise conflict("An account with this email already exists")
    agent = models.User(
        email=body.email,
        email_key=email_key,
        password_hash=services.passwords.hash(body.initial_password),
        full_name=body.full_name,
        role=Role.AGENT.value,
        branch_id=body.branch_id,
        active=True,
        created_at=utcnow(),
    )
    db.add(agent)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("An account with this email already exists") from None
    security_event("agent_created", "success", actor_id=admin.user.id, actor_role="admin",
                   target_type="user", target_id=agent.id)
    return user_out(agent)


@router.patch("/admin/agents/{agent_id}", response_model=UserOut)
def update_agent(agent_id: str, body: AgentPatch, admin: AdminDep, db: DbDep) -> UserOut:
    agent = db.get(models.User, agent_id)
    if agent is None or agent.role != Role.AGENT.value:
        raise not_found()
    agent.active = body.active
    if not body.active:
        # Deactivation takes effect at once: every open session is revoked (FR-18).
        db.execute(
            update(models.Session)
            .where(models.Session.user_id == agent.id, models.Session.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
    db.commit()
    security_event("agent_activated" if body.active else "agent_deactivated", "success",
                   actor_id=admin.user.id, actor_role="admin", target_type="user", target_id=agent.id)
    return user_out(agent)
