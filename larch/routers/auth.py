"""Registration, sign-in, sign-out and the caller's own account (FR-03, FR-04, FR-05)."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from larch import models
from larch.db import new_id, utcnow
from larch.deps import DbDep, PrincipalDep, ServicesDep
from larch.logs import security_event
from larch.models import Role
from larch.schemas import LoginIn, PasswordChangeIn, RegisterIn, TokenOut, UserOut

router = APIRouter(tags=["accounts"])

INVALID_LOGIN = "Invalid email or password"


def user_out(user: models.User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=Role(user.role),
        branch_id=user.branch_id,
        active=user.active,
    )


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/auth/register", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def register(body: RegisterIn, request: Request, db: DbDep, services: ServicesDep) -> UserOut:
    services.limiter.hit("register_ip", _client_ip(request))
    email_key = body.email.lower()
    # Hash before looking the email up, so both outcomes take the same time.
    password_hash = services.passwords.hash(body.password)
    user = models.User(
        id=new_id(),
        email=body.email,
        email_key=email_key,
        password_hash=password_hash,
        full_name=body.full_name,
        role=Role.APPLICANT.value,
        active=True,
        created_at=utcnow(),
    )
    exists = db.scalar(select(models.User.id).where(models.User.email_key == email_key)) is not None
    if not exists:
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            exists = True
    if exists:
        # The contract forbids touching the existing account; forbids revealing that
        # it exists. Answer exactly as for a new account, and change nothing.
        security_event("registration", "denied", reason="email_in_use")
    else:
        security_event("registration", "success", actor_id=user.id, actor_role=user.role)
    return user_out(user)


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: DbDep, services: ServicesDep) -> TokenOut:
    email_key = body.email.lower()
    services.limiter.hit("login_ip", _client_ip(request))
    services.limiter.hit("login_account", email_key)
    user = db.scalar(select(models.User).where(models.User.email_key == email_key))
    password_ok = services.passwords.verify(user.password_hash if user else None, body.password)
    if user is None or not password_ok or not user.active:
        reason = "unknown_account" if user is None else ("bad_password" if not password_ok else "inactive")
        security_event("login", "denied", actor_id=user.id if user else None, reason=reason)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_LOGIN)

    if services.passwords.needs_rehash(user.password_hash):
        user.password_hash = services.passwords.hash(body.password)
    issued = services.tokens.issue(user.id, user.role)
    now = utcnow()
    db.execute(
        delete(models.Session).where(
            models.Session.user_id == user.id, models.Session.expires_at < now - timedelta(days=1)
        )
    )
    db.add(models.Session(id=issued.jti, user_id=user.id, created_at=now, expires_at=issued.expires_at))
    db.commit()
    security_event("login", "success", actor_id=user.id, actor_role=user.role)
    return TokenOut(access_token=issued.token)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def logout(principal: PrincipalDep, db: DbDep) -> Response:
    db.execute(
        update(models.Session)
        .where(models.Session.id == principal.session_id)
        .values(revoked_at=utcnow())
    )
    db.commit()
    security_event("logout", "success", actor_id=principal.user.id, actor_role=principal.user.role)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserOut)
def me(principal: PrincipalDep) -> UserOut:
    return user_out(principal.user)


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def change_password(body: PasswordChangeIn, principal: PrincipalDep, db: DbDep, services: ServicesDep) -> Response:
    user = principal.user
    services.limiter.hit("login_account", user.email_key)
    if not services.passwords.verify(user.password_hash, body.current_password):
        security_event("password_change", "denied", actor_id=user.id, actor_role=user.role, reason="bad_password")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    user.password_hash = services.passwords.hash(body.new_password)
    # Sign out every other session; the one making the change stays signed in.
    db.execute(
        update(models.Session)
        .where(
            models.Session.user_id == user.id,
            models.Session.id != principal.session_id,
            models.Session.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    db.commit()
    security_event("password_change", "success", actor_id=user.id, actor_role=user.role)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
