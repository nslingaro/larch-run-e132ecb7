"""Request dependencies: database session, authentication and role checks."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from larch import models
from larch.db import utcnow
from larch.logs import security_event
from larch.models import Role
from larch.security.tokens import InvalidToken
from larch.services import Services

_bearer = HTTPBearer(auto_error=False, description="Access token from POST /auth/login")


def get_services(request: Request) -> Services:
    return request.app.state.services


ServicesDep = Annotated[Services, Depends(get_services)]


def get_db(services: ServicesDep) -> Iterator[Session]:
    session = services.sessions()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


DbDep = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True)
class Principal:
    user: models.User
    session_id: str

    @property
    def role(self) -> Role:
        return Role(self.user.role)


def _unauthenticated(reason: str) -> HTTPException:
    security_event("authentication_failed", "denied", reason=reason)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_principal(
    services: ServicesDep,
    db: DbDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    # Tokens are read from the Authorization header only, never from the URL.
    if credentials is None:
        raise _unauthenticated("missing_token")
    try:
        claims = services.tokens.verify(credentials.credentials)
    except InvalidToken as exc:
        raise _unauthenticated(f"invalid_token:{exc}") from None
    session = db.get(models.Session, claims.jti)
    if session is None or session.user_id != claims.user_id:
        raise _unauthenticated("unknown_session")
    if session.revoked_at is not None:
        raise _unauthenticated("revoked_session")
    if session.expires_at <= utcnow():
        raise _unauthenticated("expired_session")
    user = db.get(models.User, claims.user_id)
    if user is None or not user.active or user.role != claims.role:
        raise _unauthenticated("inactive_or_changed_user")
    services.limiter.hit("user", user.id)
    return Principal(user=user, session_id=session.id)


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require_roles(*roles: Role) -> Callable[..., Principal]:
    allowed = frozenset(roles)

    def dependency(request: Request, principal: PrincipalDep) -> Principal:
        if principal.role not in allowed:
            route = getattr(request.scope.get("route"), "path", None)
            security_event(
                "authorization_denied",
                "denied",
                actor_id=principal.user.id,
                actor_role=principal.user.role,
                route=route,
                reason="role",
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return principal

    return dependency


ApplicantDep = Annotated[Principal, Depends(require_roles(Role.APPLICANT))]
AgentDep = Annotated[Principal, Depends(require_roles(Role.AGENT))]
AdminDep = Annotated[Principal, Depends(require_roles(Role.ADMIN))]
AnyRoleDep = Annotated[Principal, Depends(require_roles(Role.APPLICANT, Role.AGENT, Role.ADMIN))]


def not_found(what: str = "Not found") -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=what)


def conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
