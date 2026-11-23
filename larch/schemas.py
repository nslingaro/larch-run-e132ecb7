"""Request and response models (docs/design/api.md).

Every request model forbids unknown fields, so ownership, status, role and audit
fields can never be set by a client (mass assignment). Integers and booleans are
strict: "2" or "true" strings are rejected rather than coerced.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, date, datetime
from typing import Annotated, Any, ClassVar, Generic, Literal, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    PlainSerializer,
    StringConstraints,
    model_validator,
)

from larch.models import ApplicationStatus, DocumentKind, EmploymentStatus, ListingStatus, Role

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MIN_APPLICANT_AGE = 18


def today_utc() -> date:
    return datetime.now(UTC).date()


# --- field types -------------------------------------------------------------------


def _single_line(value: str) -> str:
    if any(unicodedata.category(ch)[0] == "C" for ch in value):
        raise ValueError("must not contain control characters")
    return value


def _multi_line(value: str) -> str:
    if any(unicodedata.category(ch)[0] == "C" and ch not in "\n\r\t" for ch in value):
        raise ValueError("must not contain control characters")
    return value


def Line(min_length: int, max_length: int) -> Any:  # noqa: N802 - reads as a type
    return Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=min_length, max_length=max_length),
        AfterValidator(_single_line),
    ]


def Text(max_length: int) -> Any:  # noqa: N802
    return Annotated[
        str,
        StringConstraints(strip_whitespace=True, max_length=max_length),
        AfterValidator(_multi_line),
    ]


_POSTCODE = re.compile(r"^([A-Z]{1,2}[0-9][A-Z0-9]?)([0-9][A-Z]{2})$")


def _postcode(value: str) -> str:
    compact = re.sub(r"\s+", "", value).upper()
    match = _POSTCODE.fullmatch(compact)
    if not match:
        raise ValueError("must be a UK postcode")
    return f"{match.group(1)} {match.group(2)}"


_PHONE = re.compile(r"^\+?[0-9 ()\-]+$")


def _phone(value: str) -> str:
    if not _PHONE.fullmatch(value) or sum(ch.isdigit() for ch in value) < 6:
        raise ValueError("must be a phone number")
    return value


def _adult(value: date) -> date:
    today = today_utc()
    if value >= today:
        raise ValueError("must be in the past")
    age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))
    if age < MIN_APPLICANT_AGE:
        raise ValueError("Applicant must be 18 or over")
    if age > 120:
        raise ValueError("must be a real date of birth")
    return value


Name = Line(1, 100)
Email = Annotated[EmailStr, StringConstraints(max_length=254)]
Password = Annotated[str, StringConstraints(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)]
Postcode = Annotated[str, StringConstraints(max_length=10), AfterValidator(_postcode)]
Phone = Annotated[str, StringConstraints(strip_whitespace=True, min_length=6, max_length=20), AfterValidator(_phone)]
DateOfBirth = Annotated[date, AfterValidator(_adult)]
StrictInt = Annotated[int, Field(strict=True)]
StrictBool = Annotated[bool, Field(strict=True)]
Bedrooms = Annotated[int, Field(strict=True, ge=0, le=10)]
Rent = Annotated[int, Field(strict=True, ge=1, le=20_000)]
Income = Annotated[int, Field(strict=True, ge=0, le=10_000_000)]
Occupants = Annotated[int, Field(strict=True, ge=1, le=10)]
Timestamp = Annotated[
    datetime,
    PlainSerializer(lambda v: v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), return_type=str),
]


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PatchModel(RequestModel):
    """PATCH bodies: any subset of fields; ``null`` only where the field is optional."""

    nullable_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="after")
    def _no_null_for_required(self) -> PatchModel:
        for name in self.model_fields_set:
            if getattr(self, name) is None and name not in self.nullable_fields:
                raise ValueError(f"{name} cannot be null")
        return self

    def changes(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.model_fields_set}


# --- accounts ----------------------------------------------------------------------


class RegisterIn(RequestModel):
    email: Email
    password: Password
    full_name: Name


class LoginIn(RequestModel):
    email: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=254)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=MAX_PASSWORD_LENGTH)]


class PasswordChangeIn(RequestModel):
    current_password: Annotated[str, StringConstraints(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
    new_password: Password


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: Role
    branch_id: str | None
    active: bool


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"


# --- branches and agents -------------------------------------------------------------


class BranchIn(RequestModel):
    name: Line(1, 80)
    city: Line(1, 80)


class BranchOut(BaseModel):
    id: str
    name: str
    city: str


class AgentIn(RequestModel):
    email: Email
    full_name: Name
    branch_id: Annotated[str, StringConstraints(min_length=1, max_length=36)]
    initial_password: Password


class AgentPatch(RequestModel):
    active: StrictBool


# --- listings ------------------------------------------------------------------------


class ListingIn(RequestModel):
    title: Line(1, 120)
    description: Text(5000)
    address_line: Line(1, 200)
    city: Line(1, 80)
    postcode: Postcode
    bedrooms: Bedrooms
    monthly_rent: Rent
    available_from: date


class ListingPatch(PatchModel):
    title: Line(1, 120) | None = None
    description: Text(5000) | None = None
    address_line: Line(1, 200) | None = None
    city: Line(1, 80) | None = None
    postcode: Postcode | None = None
    bedrooms: Bedrooms | None = None
    monthly_rent: Rent | None = None
    available_from: date | None = None
    status: ListingStatus | None = None


class ListingOut(BaseModel):
    id: str
    branch_id: str
    title: str
    description: str
    address_line: str
    city: str
    postcode: str
    bedrooms: int
    monthly_rent: int
    available_from: date
    status: ListingStatus
    created_at: Timestamp
    updated_at: Timestamp


ListingSort = Literal["-created_at", "rent", "-rent", "available_from", "-available_from"]


# --- applications --------------------------------------------------------------------


class ApplicationIn(RequestModel):
    full_name: Name
    date_of_birth: DateOfBirth
    phone: Phone
    contact_email: Email
    current_address: Text(300)
    employment_status: EmploymentStatus
    employer_name: Line(1, 100) | None = None
    annual_income: Income
    move_in_date: date
    occupants: Occupants
    pets: StrictBool
    notes: Text(2000) | None = None


class ApplicationPatch(PatchModel):
    nullable_fields: ClassVar[frozenset[str]] = frozenset({"employer_name", "notes"})

    full_name: Name | None = None
    date_of_birth: DateOfBirth | None = None
    phone: Phone | None = None
    contact_email: Email | None = None
    current_address: Text(300) | None = None
    employment_status: EmploymentStatus | None = None
    employer_name: Line(1, 100) | None = None
    annual_income: Income | None = None
    move_in_date: date | None = None
    occupants: Occupants | None = None
    pets: StrictBool | None = None
    notes: Text(2000) | None = None


class DecisionIn(RequestModel):
    decision: Literal["approved", "rejected"]
    note: Text(2000) | None = None


class ApplicationOut(BaseModel):
    """The applicant's view. Never carries the agent's internal note (FR-12)."""

    id: str
    listing_id: str
    applicant_id: str
    status: ApplicationStatus
    full_name: str
    date_of_birth: date
    phone: str
    contact_email: str
    current_address: str
    employment_status: EmploymentStatus
    employer_name: str | None
    annual_income: int
    move_in_date: date
    occupants: int
    pets: bool
    notes: str | None
    created_at: Timestamp
    submitted_at: Timestamp | None
    decided_at: Timestamp | None
    withdrawn_at: Timestamp | None


class ApplicationStaffOut(ApplicationOut):
    decision_note: str | None


# --- documents -----------------------------------------------------------------------


class DocumentOut(BaseModel):
    id: str
    application_id: str
    kind: DocumentKind
    filename: str
    content_type: str
    size_bytes: int
    uploaded_at: Timestamp


# --- paging --------------------------------------------------------------------------

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    page: int
    page_size: int
    total: int


class Health(BaseModel):
    status: str
