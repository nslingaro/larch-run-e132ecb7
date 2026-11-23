# Tenant Applications API: Architecture

Version 1.0, 3 November 2026. Implements the [product specification](../product-spec.md).

## 1. Context

```
Applicant or agent browser
        |  HTTPS
        v
larch-web (single-page app, https://apply.larch.example)  - separate repository
        |  HTTPS, JSON, cross-origin
        v
Tenant Applications API (https://api.larch.example)        - this repository
        |-- PostgreSQL: accounts, branches, listings, applications, document metadata
        `-- Document store: uploaded files, on an Azure Files share
```

## 2. Components

| Component | Choice |
|---|---|
| API service | Python 3.12, FastAPI, SQLAlchemy 2.x, Pydantic v2, served by Uvicorn |
| Database | PostgreSQL 16 in production. Code goes through SQLAlchemy only, so local development and tests run on SQLite. |
| Document store | Plain files under `LARCH_DOCUMENTS_DIR`. Production mounts an Azure Files share there. The database holds each document's metadata. |
| Admin command | `python -m larch create-admin <email> <full-name>`: prompts for the password twice, or reads it from standard input when that is not a terminal. Exits 0 when created, 1 when the email already has an account. |

The schema is created at startup in version 1. Migrations arrive with the first schema
change.

## 3. Sign-in

Every role signs in with an email address and password held by this API. `POST
/auth/login` returns a bearer access token, which the front end sends in the
`Authorization` header on every call. `POST /auth/logout` ends the session.

## 4. Deployment

- One container image, run on Azure App Service (Linux) in Larch's Azure subscription,
  UK South region.
- Two environments: test and production.
- TLS terminates at App Service.
- Logs go to standard output; App Service forwards them to Log Analytics.
- `GET /health` is App Service's health check.
- CI/CD: GitHub Actions, set up once the version 1 code is in place.

## 5. Configuration

Environment variables, all prefixed `LARCH_`.

| Variable | Purpose | Local default |
|---|---|---|
| `LARCH_DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./var/larch.db` |
| `LARCH_DOCUMENTS_DIR` | Folder documents are stored in | `./var/documents` |

Any other setting the service needs follows the same prefix.

## 6. Repository layout

```
larch/          application package; larch.main:app is the ASGI app
tests/          pytest suite
docs/           specification and design
Dockerfile
pyproject.toml
README.md
```

## 7. Conventions

- JSON bodies throughout, except document upload (multipart form) and download (the
  file itself). The contract is in [api.md](api.md).
- Errors use FastAPI's `{"detail": ...}` body.
- Every endpoint is covered by a pytest test.

## 8. Decisions

| # | Decision | Reason |
|---|---|---|
| 1 | One API service, no queues or workers | Volume is small; one deployable keeps operations simple |
| 2 | Documents on a file share, not Blob Storage | Simplest option for version 1; revisit in 1.1 |
| 3 | Accounts held by the API for every role, not Larch's Microsoft 365 sign-in | Applicants are the public; agents use the same sign-in for now so version 1 has one sign-in path |
