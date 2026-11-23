"""Health check, headers, CORS, request limits, error handling and configuration."""

from __future__ import annotations

import json
import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from larch.app import create_app
from larch.config import Settings
from larch.logs import JsonFormatter
from tests.conftest import API, make_settings

ORIGIN = "https://apply.larch.example"


def test_health_returns_ok(client):
    response = client.get(f"{API}/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_reports_unavailable_database_without_details(client, services, monkeypatch):
    def broken_connect():
        raise RuntimeError("connection refused to db.internal:5432 password=hunter2")

    monkeypatch.setattr(services.engine, "connect", broken_connect)
    response = client.get(f"{API}/health")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_security_headers_on_every_response(client):
    for response in (client.get(f"{API}/health"), client.get(f"{API}/nope")):
        headers = response.headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["x-frame-options"] == "DENY"
        assert headers["strict-transport-security"] == "max-age=31536000"
        assert headers["cache-control"] == "no-store"
        csp = headers["content-security-policy"]
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
        assert "*" not in csp and "unsafe-eval" not in csp
        assert "camera=()" in headers["permissions-policy"]
        assert "server" not in headers


def test_request_id_generated_when_absent(client):
    response = client.get(f"{API}/health")
    assert uuid.UUID(response.headers["x-request-id"]).version == 4


def test_valid_request_id_is_echoed_and_invalid_one_replaced(client):
    assert client.get(f"{API}/health", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"] == "abc-123"
    replaced = client.get(f"{API}/health", headers={"X-Request-ID": "bad id\twith <script>"}).headers["x-request-id"]
    assert replaced != "bad id\twith <script>"
    uuid.UUID(replaced)


def test_unknown_route_is_404_and_wrong_method_405(client):
    assert client.get(f"{API}/does-not-exist").status_code == 404
    assert client.delete(f"{API}/health").status_code == 405


def test_cors_allows_only_the_configured_origin(client):
    preflight = client.options(
        f"{API}/listings",
        headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "authorization,content-type"},
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == ORIGIN
    assert "access-control-allow-credentials" not in preflight.headers

    simple = client.get(f"{API}/listings", headers={"Origin": ORIGIN})
    assert simple.headers["access-control-allow-origin"] == ORIGIN
    assert "Origin" in simple.headers["vary"]

    for origin in ("https://evil.example", "null"):
        denied = client.options(
            f"{API}/listings", headers={"Origin": origin, "Access-Control-Request-Method": "POST"}
        )
        assert denied.status_code == 400
        assert "access-control-allow-origin" not in denied.headers
        assert "access-control-allow-origin" not in client.get(f"{API}/listings", headers={"Origin": origin}).headers


def test_cors_rejects_unapproved_methods_and_headers(client):
    for headers in (
        {"Access-Control-Request-Method": "TRACE"},
        {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-evil"},
    ):
        response = client.options(f"{API}/listings", headers={"Origin": ORIGIN, **headers})
        assert response.status_code == 400


def test_json_endpoint_rejects_non_json_bodies(client):
    xml = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    response = client.post(f"{API}/auth/login", content=xml, headers={"Content-Type": "application/xml"})
    assert response.status_code == 415
    assert response.json() == {"detail": "Unsupported media type"}
    form = client.post(f"{API}/auth/login", data={"email": "a@example.com", "password": "x"})
    assert form.status_code == 415


def test_oversized_json_body_is_rejected(client):
    body = json.dumps({"email": "a@example.com", "password": "x" * 300_000})
    response = client.post(f"{API}/auth/login", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_malformed_and_deeply_nested_json_is_rejected_safely(client):
    response = client.post(f"{API}/auth/login", content=b"{not json", headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    nested = "[" * 100_000 + "]" * 100_000
    response = client.post(f"{API}/auth/login", content=nested, headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 413, 422, 500)
    assert "Traceback" not in response.text


def test_validation_errors_do_not_echo_submitted_values(client):
    secret = "pw-1"
    response = client.post(
        f"{API}/auth/register", json={"email": "x@example.com", "password": secret, "full_name": "X"}
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail[0]["loc"] == ["body", "password"]
    assert secret not in response.text
    assert all("input" not in item and "url" not in item for item in detail)


def test_unhandled_errors_return_generic_500_without_internals(tmp_path, caplog):
    app = create_app(make_settings(tmp_path))

    @app.get(f"{API}/boom")
    def boom():
        raise RuntimeError("SELECT * FROM users WHERE email='sam@example.com' at /srv/secret/path")

    with TestClient(app, raise_server_exceptions=False) as client, caplog.at_level(logging.ERROR):
        response = client.get(f"{API}/boom", headers={"X-Request-ID": "trace-1"})
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error", "request_id": "trace-1"}
    formatted = "\n".join(JsonFormatter().format(r) for r in caplog.records)
    assert "RuntimeError" in formatted and "trace-1" in formatted
    assert "sam@example.com" not in formatted and "/srv/secret/path" not in formatted


def test_api_docs_are_off_outside_development(tmp_path):
    app = create_app(make_settings(tmp_path, enable_api_docs=False))
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_api_docs_available_in_development(client):
    assert client.get("/openapi.json").status_code == 200
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "cdn.jsdelivr.net" in docs.headers["content-security-policy"]


CONTRACT = {
    ("get", "/health"), ("post", "/auth/register"), ("post", "/auth/login"), ("post", "/auth/logout"),
    ("get", "/me"), ("put", "/me/password"), ("get", "/branches"), ("post", "/admin/branches"),
    ("get", "/admin/agents"), ("post", "/admin/agents"), ("patch", "/admin/agents/{agent_id}"),
    ("get", "/listings"), ("get", "/listings/{listing_id}"), ("post", "/listings"),
    ("patch", "/listings/{listing_id}"), ("post", "/listings/{listing_id}/applications"),
    ("get", "/applications"), ("get", "/applications/{application_id}"),
    ("patch", "/applications/{application_id}"), ("post", "/applications/{application_id}/submit"),
    ("post", "/applications/{application_id}/withdraw"), ("post", "/applications/{application_id}/decision"),
    ("post", "/applications/{application_id}/documents"), ("get", "/applications/{application_id}/documents"),
    ("get", "/applications/{application_id}/documents/{document_id}/content"),
    ("delete", "/applications/{application_id}/documents/{document_id}"),
}


def test_exposed_routes_are_exactly_the_contract(app):
    """Exposed-interface inventory: nothing beyond docs/design/api.md."""
    exposed = {
        (method, path.removeprefix(API))
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    assert all(path.startswith(API) for path in app.openapi()["paths"])
    assert exposed == CONTRACT


@pytest.mark.parametrize("environment", ["test", "production"])
def test_deployed_environments_refuse_unsafe_configuration(environment):
    with pytest.raises(ValidationError) as excinfo:
        Settings(environment=environment, database_url="sqlite:///./var/larch.db")
    message = str(excinfo.value)
    assert "LARCH_TOKEN_SIGNING_KEY is required" in message
    assert "LARCH_DOCUMENT_ENCRYPTION_KEYS is required" in message
    assert "PostgreSQL" in message


def test_production_requires_tls_to_postgres(tmp_path):
    base = make_settings(tmp_path).model_dump()
    base.update(environment="production", database_url="postgresql+psycopg://larch@db/larch")
    with pytest.raises(ValidationError, match="sslmode"):
        Settings(**{k: (v.get_secret_value() if hasattr(v, "get_secret_value") else v) for k, v in base.items()})
    base["database_url"] += "?sslmode=verify-full"
    settings = Settings(**{k: (v.get_secret_value() if hasattr(v, "get_secret_value") else v) for k, v in base.items()})
    assert settings.environment.value == "production"
    assert not settings.api_docs_enabled


def test_production_is_the_default_environment(monkeypatch):
    monkeypatch.delenv("LARCH_ENVIRONMENT", raising=False)
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize("origin", ["*", "null", "apply.larch.example", "https://apply.larch.example/path"])
def test_cors_configuration_rejects_wildcards_and_non_origins(tmp_path, origin):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, cors_origins=[origin])


def test_cors_origins_parse_from_comma_separated_env(monkeypatch, tmp_path):
    monkeypatch.setenv("LARCH_CORS_ORIGINS", "https://apply.larch.example, http://localhost:5173")
    settings = Settings(environment="development")
    assert settings.cors_origins == ["https://apply.larch.example", "http://localhost:5173"]


def test_per_address_rate_limit(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_per_ip="3/60"))
    with TestClient(app) as client:
        statuses = [client.get(f"{API}/branches").status_code for _ in range(4)]
        assert statuses == [200, 200, 200, 429]
        limited = client.get(f"{API}/branches")
        assert int(limited.headers["retry-after"]) >= 1
        assert limited.json() == {"detail": "Too many requests"}
        assert client.get(f"{API}/health").status_code == 200  # health probe is exempt
