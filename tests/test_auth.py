"""Registration, sign-in, sign-out, /me and password change (FR-03 to FR-05)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from datetime import timedelta

import jwt
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select

from larch import models
from larch.app import create_app
from larch.logs import JsonFormatter
from larch.security.tokens import TokenService, generate_signing_key_pem, public_key_pem
from tests.conftest import API, PASSWORD, SIGNING_KEY, bearer, make_settings, unique_email


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _user(services, email: str) -> models.User:
    with services.sessions() as db:
        return db.scalar(select(models.User).where(models.User.email_key == email.lower()))


# --- registration ------------------------------------------------------------------


def test_register_creates_an_applicant(client):
    response = client.post(
        f"{API}/auth/register", json={"email": "Sam@Example.com", "password": PASSWORD, "full_name": "Sam Carter"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "Sam@example.com"  # domain normalised by the validator
    assert body["full_name"] == "Sam Carter"
    assert body["role"] == "applicant"
    assert body["branch_id"] is None
    assert body["active"] is True
    assert set(body) == {"id", "email", "full_name", "role", "branch_id", "active"}


def test_register_existing_email_changes_nothing_and_reveals_nothing(client, services):
    email = unique_email()
    first = client.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD, "full_name": "First"})
    second = client.post(
        f"{API}/auth/register",
        json={"email": email.upper(), "password": "another password", "full_name": "Second"},
    )
    assert first.status_code == second.status_code == 201
    assert set(first.json()) == set(second.json())
    assert second.json()["id"] != first.json()["id"]
    with services.sessions() as db:
        users = db.scalars(select(models.User).where(models.User.email_key == email.lower())).all()
    assert len(users) == 1 and users[0].full_name == "First"
    assert client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    assert client.post(f"{API}/auth/login", json={"email": email, "password": "another password"}).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"email": "not-an-email", "password": PASSWORD, "full_name": "Sam"},
        {"email": "a@example.com", "password": "seven77", "full_name": "Sam"},
        {"email": "a@example.com", "password": "x" * 129, "full_name": "Sam"},
        {"email": "a@example.com", "password": PASSWORD, "full_name": ""},
        {"email": "a@example.com", "password": PASSWORD, "full_name": "x" * 101},
        {"email": "a@example.com", "password": PASSWORD, "full_name": "Sam\u0000Carter"},
        {"email": "a@example.com", "password": PASSWORD},
        {"email": "a@example.com", "password": PASSWORD, "full_name": "Sam", "role": "admin"},
    ],
)
def test_register_rejects_invalid_bodies(client, body):
    assert client.post(f"{API}/auth/register", json=body).status_code == 422


def test_register_accepts_exactly_eight_characters(client):
    body = {"email": unique_email(), "password": "12345678", "full_name": "Sam"}
    assert client.post(f"{API}/auth/register", json=body).status_code == 201


def test_passwords_are_stored_as_salted_argon2id(api, services):
    email_1, email_2 = unique_email(), unique_email()
    api.applicant(email_1)
    api.applicant(email_2)
    hash_1, hash_2 = _user(services, email_1).password_hash, _user(services, email_2).password_hash
    assert hash_1.startswith("$argon2id$") and hash_2.startswith("$argon2id$")
    assert hash_1 != hash_2  # same password, different salts
    assert PASSWORD not in hash_1


def test_outdated_password_hash_is_upgraded_on_login(api, services):
    email = unique_email()
    api.applicant(email)
    old_hash = PasswordHasher(time_cost=2, memory_cost=128, parallelism=1).hash(PASSWORD)
    with services.sessions() as db:
        user = db.scalar(select(models.User).where(models.User.email_key == email))
        user.password_hash = old_hash
        db.commit()
    api.login(email)
    new_hash = _user(services, email).password_hash
    assert new_hash != old_hash
    assert not services.passwords.needs_rehash(new_hash)


# --- login ------------------------------------------------------------------------


def test_login_returns_a_bearer_token(api, client):
    email = unique_email()
    api.applicant(email)
    response = client.post(f"{API}/auth/login", json={"email": email.upper(), "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert set(claims) >= {"iss", "aud", "sub", "jti", "iat", "exp", "role"}
    assert claims["role"] == "applicant"
    assert jwt.get_unverified_header(body["access_token"])["alg"] == "ES256"


def test_login_failures_share_one_generic_answer(api, client, world):
    email = unique_email()
    api.applicant(email)
    wrong_password = client.post(f"{API}/auth/login", json={"email": email, "password": "wrong password"})
    unknown = client.post(f"{API}/auth/login", json={"email": unique_email(), "password": PASSWORD})
    client.patch(f"{API}/admin/agents/{world.agent_a_user['id']}", json={"active": False}, headers=bearer(world.admin))
    inactive = client.post(f"{API}/auth/login", json={"email": world.agent_a_user["email"], "password": PASSWORD})
    for response in (wrong_password, unknown, inactive):
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid email or password"}


def test_login_is_rate_limited_per_account_without_revealing_existence(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_login_per_account="3/900"))
    with TestClient(app) as client:
        email = unique_email()
        client.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD, "full_name": "S"})
        for target in (email, unique_email()):
            statuses = [
                client.post(f"{API}/auth/login", json={"email": target, "password": "wrong guess"}).status_code
                for _ in range(4)
            ]
            assert statuses == [401, 401, 401, 429]
        # Another account is unaffected by the first one's limit.
        other = unique_email()
        client.post(f"{API}/auth/register", json={"email": other, "password": PASSWORD, "full_name": "S"})
        assert client.post(f"{API}/auth/login", json={"email": other, "password": PASSWORD}).status_code == 200


def test_login_is_rate_limited_per_address(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_login_per_ip="2/60"))
    with TestClient(app) as client:
        statuses = [
            client.post(f"{API}/auth/login", json={"email": unique_email(), "password": "x"}).status_code
            for _ in range(3)
        ]
    assert statuses == [401, 401, 429]


def test_registration_is_rate_limited_per_address(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_register_per_ip="1/3600"))
    with TestClient(app) as client:
        body = {"password": PASSWORD, "full_name": "S"}
        assert client.post(f"{API}/auth/register", json={**body, "email": unique_email()}).status_code == 201
        assert client.post(f"{API}/auth/register", json={**body, "email": unique_email()}).status_code == 429


# --- tokens and sessions -----------------------------------------------------------


def test_signed_in_endpoints_require_a_token(client):
    response = client.get(f"{API}/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert client.get(f"{API}/me", headers={"Authorization": "Basic dXNlcjpwYXNz"}).status_code == 401


def test_token_in_the_url_is_not_accepted(api, client):
    token, _ = api.applicant()
    assert client.get(f"{API}/me", params={"access_token": token}).status_code == 401
    assert client.get(f"{API}/me", params={"token": token}).status_code == 401


def _forged_tokens(valid: str, settings) -> dict[str, str]:
    header_b64, payload_b64, signature = valid.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    kid = jwt.get_unverified_header(valid)["kid"]

    escalated = _b64(json.dumps({**claims, "role": "admin"}).encode())
    none_header = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": kid}).encode())
    hs_header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    hs_signing_input = f"{hs_header}.{payload_b64}".encode()
    hs_signature = _b64(hmac.new(public_key_pem(SIGNING_KEY).encode(), hs_signing_input, hashlib.sha256).digest())

    def service(**overrides):
        args = {
            "signing_key_pem": SIGNING_KEY, "previous_public_keys_pem": None,
            "issuer": settings.token_issuer, "audience": settings.token_audience, "ttl": timedelta(minutes=5),
        }
        args.update(overrides)
        return TokenService(**args)

    return {
        "tampered_payload": f"{header_b64}.{escalated}.{signature}",
        "alg_none": f"{none_header}.{payload_b64}.",
        "hs256_confusion": f"{hs_header}.{payload_b64}.{hs_signature}",
        "other_key": service(signing_key_pem=generate_signing_key_pem()).issue(claims["sub"], "applicant").token,
        "wrong_audience": service(audience="https://evil.example").issue(claims["sub"], "applicant").token,
        "wrong_issuer": service(issuer="https://evil.example").issue(claims["sub"], "applicant").token,
        "expired": service(ttl=timedelta(minutes=-5)).issue(claims["sub"], "applicant").token,
        "unknown_session": service().issue(claims["sub"], "applicant").token,
        "garbage": "not.a.token",
        "oversized": "a" * 5000,
    }


@pytest.mark.parametrize(
    "kind",
    ["tampered_payload", "alg_none", "hs256_confusion", "other_key", "wrong_audience", "wrong_issuer",
     "expired", "unknown_session", "garbage", "oversized"],
)
def test_invalid_tokens_are_rejected(api, client, settings, kind):
    token, _ = api.applicant()
    forged = _forged_tokens(token, settings)[kind]
    assert client.get(f"{API}/me", headers=bearer(forged)).status_code == 401
    assert client.get(f"{API}/me", headers=bearer(token)).status_code == 200


def test_rotated_signing_key_still_accepts_tokens_from_the_previous_key(tmp_path):
    first = create_app(make_settings(tmp_path))
    with TestClient(first) as client:
        email = unique_email()
        client.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD, "full_name": "S"})
        old_token = client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]

    rotated = make_settings(
        tmp_path, token_signing_key=generate_signing_key_pem(), token_previous_public_keys=public_key_pem(SIGNING_KEY)
    )
    with TestClient(create_app(rotated)) as client:
        assert client.get(f"{API}/me", headers=bearer(old_token)).status_code == 200

    retired = make_settings(tmp_path, token_signing_key=generate_signing_key_pem())
    with TestClient(create_app(retired)) as client:
        assert client.get(f"{API}/me", headers=bearer(old_token)).status_code == 401


def test_logout_ends_the_session(api, client):
    email = unique_email()
    api.applicant(email)
    token, other = api.login(email), api.login(email)
    assert client.post(f"{API}/auth/logout", headers=bearer(token)).status_code == 204
    assert client.get(f"{API}/me", headers=bearer(token)).status_code == 401
    assert client.post(f"{API}/auth/logout", headers=bearer(token)).status_code == 401
    assert client.get(f"{API}/me", headers=bearer(other)).status_code == 200


def test_logout_requires_sign_in(client):
    assert client.post(f"{API}/auth/logout").status_code == 401


def test_per_user_rate_limit(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_authenticated_per_user="2/60"))
    with TestClient(app) as client:
        email = unique_email()
        client.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD, "full_name": "S"})
        token = client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
        statuses = [client.get(f"{API}/me", headers=bearer(token)).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]


# --- /me ----------------------------------------------------------------------------


def test_me_returns_the_callers_account(api, client, world):
    email = unique_email()
    token, user_id = api.applicant(email)
    body = client.get(f"{API}/me", headers=bearer(token)).json()
    assert body == {"id": user_id, "email": email, "full_name": "Sam Carter", "role": "applicant",
                    "branch_id": None, "active": True}
    agent = client.get(f"{API}/me", headers=bearer(world.agent_a)).json()
    assert agent["role"] == "agent" and agent["branch_id"] == world.branch_a["id"]
    assert client.get(f"{API}/me", headers=bearer(world.admin)).json()["role"] == "admin"


def test_change_password(api, client):
    email = unique_email()
    api.applicant(email)
    token, other_session = api.login(email), api.login(email)
    response = client.put(
        f"{API}/me/password", json={"current_password": PASSWORD, "new_password": "brand new secret"},
        headers=bearer(token),
    )
    assert response.status_code == 204
    assert client.get(f"{API}/me", headers=bearer(token)).status_code == 200
    assert client.get(f"{API}/me", headers=bearer(other_session)).status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": email, "password": "brand new secret"}).status_code == 200


def test_change_password_with_wrong_current_password(api, client):
    token, _ = api.applicant()
    response = client.put(
        f"{API}/me/password", json={"current_password": "not it at all", "new_password": "brand new secret"},
        headers=bearer(token),
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Current password is incorrect"}


def test_change_password_validation_and_auth(api, client, world):
    token, _ = api.applicant()
    short = client.put(f"{API}/me/password", json={"current_password": PASSWORD, "new_password": "short"},
                       headers=bearer(token))
    assert short.status_code == 422
    assert client.put(f"{API}/me/password", json={"current_password": PASSWORD, "new_password": "long enough"}
                      ).status_code == 401
    agent = client.put(f"{API}/me/password", json={"current_password": PASSWORD, "new_password": "agent new pw"},
                       headers=bearer(world.agent_a))
    assert agent.status_code == 204


# --- logging ------------------------------------------------------------------------


def test_logs_never_contain_passwords_tokens_or_emails(api, client, caplog):
    email = unique_email("private")
    with caplog.at_level(logging.INFO):
        token, _ = api.applicant(email)
        client.post(f"{API}/auth/login", json={"email": email, "password": "wrong secret value"})
        client.get(f"{API}/me", headers=bearer(token))
        client.get(f"{API}/me", headers=bearer(token + "x"))
        client.post(f"{API}/auth/logout", headers=bearer(token))
    output = "\n".join(JsonFormatter().format(record) for record in caplog.records)
    for secret in (PASSWORD, "wrong secret value", token, token.split(".")[2], email, "Sam Carter"):
        assert secret not in output
    events = [json.loads(line) for line in output.splitlines()]
    security = [e for e in events if e["logger"] == "larch.security"]
    assert {"login", "logout", "authentication_failed", "registration"} <= {e["event"] for e in security}
    assert all("request_id" in e and e.get("source_ip") for e in security)
    denied = next(e for e in security if e["event"] == "login" and e["outcome"] == "denied")
    assert denied["reason"] == "bad_password"
