from __future__ import annotations

import itertools
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient

from larch import models
from larch.app import create_app
from larch.config import Settings
from larch.db import utcnow
from larch.security.document_crypto import generate_key_b64
from larch.security.tokens import generate_signing_key_pem
from larch.services import Services

API = "/api/v1"
PASSWORD = "correct horse battery"
PDF = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64

SIGNING_KEY = generate_signing_key_pem()
DOCUMENT_KEY = generate_key_b64()

_counter = itertools.count(1)

HIGH = "100000/60"


def make_settings(tmp_path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "development",
        "database_url": f"sqlite:///{tmp_path}/larch.db",
        "documents_dir": str(tmp_path / "documents"),
        "token_signing_key": SIGNING_KEY,
        "document_encryption_keys": f"k1:{DOCUMENT_KEY}",
        "document_encryption_active_key_id": "k1",
        # Cheap Argon2id parameters keep the suite fast; production uses the defaults.
        "argon2_time_cost": 1,
        "argon2_memory_cost_kib": 64,
        "argon2_parallelism": 1,
        "cors_origins": ["https://apply.larch.example"],
        "rate_limit_login_per_ip": HIGH,
        "rate_limit_login_per_account": HIGH,
        "rate_limit_register_per_ip": HIGH,
        "rate_limit_upload_per_user": HIGH,
        "rate_limit_download_per_user": HIGH,
        "rate_limit_authenticated_per_user": HIGH,
        "rate_limit_per_ip": HIGH,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def services(app) -> Services:
    return app.state.services


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}{next(_counter)}@example.com"


def listing_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "title": "Two-bed flat near the station",
        "description": "Bright flat with a garden view.",
        "address_line": "4 Station Parade",
        "city": "Harrogate",
        "postcode": "HG1 1TE",
        "bedrooms": 2,
        "monthly_rent": 975,
        "available_from": "2026-12-01",
    }
    body.update(overrides)
    return body


def application_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "full_name": "Sam Carter",
        "date_of_birth": "1994-05-17",
        "phone": "07700 900123",
        "contact_email": "sam@example.com",
        "current_address": "12 Mill Lane, Leeds LS6 2AB",
        "employment_status": "employed",
        "employer_name": "Northfield Foods",
        "annual_income": 34000,
        "move_in_date": "2026-12-15",
        "occupants": 2,
        "pets": False,
        "notes": None,
    }
    body.update(overrides)
    return body


@dataclass
class Api:
    client: TestClient
    services: Services

    def create_admin(self, email: str | None = None) -> str:
        email = email or unique_email("admin")
        with self.services.sessions() as db:
            db.add(
                models.User(
                    email=email,
                    email_key=email.lower(),
                    password_hash=self.services.passwords.hash(PASSWORD),
                    full_name="Head Office",
                    role="admin",
                    active=True,
                    created_at=utcnow(),
                )
            )
            db.commit()
        return self.login(email)

    def login(self, email: str, password: str = PASSWORD) -> str:
        response = self.client.post(f"{API}/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    def applicant(self, email: str | None = None) -> tuple[str, str]:
        email = email or unique_email("applicant")
        response = self.client.post(
            f"{API}/auth/register", json={"email": email, "password": PASSWORD, "full_name": "Sam Carter"}
        )
        assert response.status_code == 201, response.text
        return self.login(email), response.json()["id"]

    def branch(self, admin: str, name: str | None = None, city: str = "Harrogate") -> dict[str, Any]:
        response = self.client.post(
            f"{API}/admin/branches", json={"name": name or f"Branch {next(_counter)}", "city": city},
            headers=bearer(admin),
        )
        assert response.status_code == 201, response.text
        return response.json()

    def agent(self, admin: str, branch_id: str, email: str | None = None) -> tuple[str, dict[str, Any]]:
        email = email or unique_email("agent")
        response = self.client.post(
            f"{API}/admin/agents",
            json={"email": email, "full_name": "Alex Agent", "branch_id": branch_id, "initial_password": PASSWORD},
            headers=bearer(admin),
        )
        assert response.status_code == 201, response.text
        return self.login(email), response.json()

    def listing(self, agent: str, **overrides: Any) -> dict[str, Any]:
        response = self.client.post(f"{API}/listings", json=listing_body(**overrides), headers=bearer(agent))
        assert response.status_code == 201, response.text
        return response.json()

    def application(self, applicant: str, listing_id: str, **overrides: Any) -> dict[str, Any]:
        response = self.client.post(
            f"{API}/listings/{listing_id}/applications", json=application_body(**overrides), headers=bearer(applicant)
        )
        assert response.status_code == 201, response.text
        return response.json()

    def upload(
        self,
        token: str,
        application_id: str,
        kind: str = "photo_id",
        content: bytes = PDF,
        filename: str = "passport.pdf",
        content_type: str = "application/pdf",
    ):
        return self.client.post(
            f"{API}/applications/{application_id}/documents",
            data={"kind": kind},
            files={"file": (filename, content, content_type)},
            headers=bearer(token),
        )

    def submitted_application(self, applicant: str, listing_id: str) -> dict[str, Any]:
        application = self.application(applicant, listing_id)
        assert self.upload(applicant, application["id"], "photo_id").status_code == 201
        assert self.upload(applicant, application["id"], "proof_of_income").status_code == 201
        response = self.client.post(f"{API}/applications/{application['id']}/submit", headers=bearer(applicant))
        assert response.status_code == 200, response.text
        return response.json()


@pytest.fixture
def api(client, services) -> Api:
    return Api(client, services)


@dataclass
class World:
    """Two branches, an agent in each, two applicants and an open listing per branch."""

    admin: str
    branch_a: dict[str, Any]
    branch_b: dict[str, Any]
    agent_a: str
    agent_a_user: dict[str, Any]
    agent_b: str
    alice: str
    alice_id: str
    bob: str
    bob_id: str
    listing_a: dict[str, Any]
    listing_b: dict[str, Any]


@pytest.fixture
def world(api) -> World:
    admin = api.create_admin()
    branch_a = api.branch(admin, "Harrogate")
    branch_b = api.branch(admin, "Leeds", city="Leeds")
    agent_a, agent_a_user = api.agent(admin, branch_a["id"])
    agent_b, _ = api.agent(admin, branch_b["id"])
    alice, alice_id = api.applicant()
    bob, bob_id = api.applicant()
    listing_a = api.listing(agent_a)
    listing_b = api.listing(agent_b, city="Leeds", postcode="LS6 2AB")
    return World(admin, branch_a, branch_b, agent_a, agent_a_user, agent_b, alice, alice_id, bob, bob_id,
                 listing_a, listing_b)
