"""ORM models. Field limits follow docs/design/data-model.md."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from larch.db import Base, new_id, utcnow


class Role(StrEnum):
    APPLICANT = "applicant"
    AGENT = "agent"
    ADMIN = "admin"


class ListingStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class ApplicationStatus(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    WITHDRAWN = "withdrawn"
    APPROVED = "approved"
    REJECTED = "rejected"


class EmploymentStatus(StrEnum):
    EMPLOYED = "employed"
    SELF_EMPLOYED = "self_employed"
    STUDENT = "student"
    UNEMPLOYED = "unemployed"
    RETIRED = "retired"


class DocumentKind(StrEnum):
    PHOTO_ID = "photo_id"
    PROOF_OF_INCOME = "proof_of_income"
    PROOF_OF_ADDRESS = "proof_of_address"
    OTHER = "other"


def _enum_check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{member.value}'" for member in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"ck_{column}_values")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        _enum_check("role", Role),
        CheckConstraint("(role = 'agent') = (branch_id IS NOT NULL)", name="ck_users_agent_branch"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254))
    # Lower-cased email; makes the case-insensitive uniqueness rule a database constraint.
    email_key: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(16))
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("branches.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    branch: Mapped[Branch | None] = relationship(lazy="raise")


class Session(Base):
    """Server-side record of each issued access token, so logout and deactivation revoke it."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # the token's jti
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(index=True)
    revoked_at: Mapped[datetime | None] = mapped_column()


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(80))
    name_key: Mapped[str] = mapped_column(String(80), unique=True)
    city: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Listing(Base):
    __tablename__ = "listings"
    __table_args__ = (
        _enum_check("status", ListingStatus),
        CheckConstraint("bedrooms BETWEEN 0 AND 10", name="ck_listings_bedrooms"),
        CheckConstraint("monthly_rent BETWEEN 1 AND 20000", name="ck_listings_rent"),
        Index("ix_listings_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    branch_id: Mapped[str] = mapped_column(ForeignKey("branches.id"), index=True)
    title: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    address_line: Mapped[str] = mapped_column(String(200))
    city: Mapped[str] = mapped_column(String(80))
    postcode: Mapped[str] = mapped_column(String(8))
    bedrooms: Mapped[int] = mapped_column(Integer)
    monthly_rent: Mapped[int] = mapped_column(Integer)
    available_from: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(8), default=ListingStatus.OPEN.value)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (
        UniqueConstraint("listing_id", "applicant_id", name="uq_applications_listing_applicant"),
        _enum_check("status", ApplicationStatus),
        _enum_check("employment_status", EmploymentStatus),
        Index("ix_applications_applicant_created", "applicant_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id"), index=True)
    applicant_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), default=ApplicationStatus.DRAFT.value)
    full_name: Mapped[str] = mapped_column(String(100))
    date_of_birth: Mapped[date] = mapped_column(Date)
    phone: Mapped[str] = mapped_column(String(20))
    contact_email: Mapped[str] = mapped_column(String(254))
    current_address: Mapped[str] = mapped_column(String(300))
    employment_status: Mapped[str] = mapped_column(String(16))
    employer_name: Mapped[str | None] = mapped_column(String(100))
    annual_income: Mapped[int] = mapped_column(Integer)
    move_in_date: Mapped[date] = mapped_column(Date)
    occupants: Mapped[int] = mapped_column(Integer)
    pets: Mapped[bool] = mapped_column(Boolean)
    notes: Mapped[str | None] = mapped_column(Text)
    decision_note: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    # Set by head office outside the API; the retention purge skips held applications.
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column()
    decided_at: Mapped[datetime | None] = mapped_column()
    withdrawn_at: Mapped[datetime | None] = mapped_column()

    listing: Mapped[Listing] = relationship(lazy="joined", innerjoin=True)


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = (_enum_check("kind", DocumentKind),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    original_filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(Integer)
    storage_key: Mapped[str] = mapped_column(String(64), unique=True)
    # Envelope encryption: the per-document data key, wrapped by the named key-encryption key.
    encryption_key_id: Mapped[str] = mapped_column(String(64))
    wrapped_data_key: Mapped[bytes] = mapped_column(LargeBinary(128))
    uploaded_at: Mapped[datetime] = mapped_column(default=utcnow)
