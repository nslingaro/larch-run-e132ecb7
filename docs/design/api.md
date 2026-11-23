# Tenant Applications API: API Contract

Version 1.0, 3 November 2026. The front end team builds against this contract.

## Conventions

- Base path: `/api/v1`. Every path below is relative to it.
- Signed-in endpoints need `Authorization: Bearer <access_token>`, the token
  `POST /auth/login` returns. Without a valid token they return 401.
- A signed-in caller whose role an endpoint does not allow gets 403.
- A record the caller has no access to returns 404, as if it did not exist.
- Errors: `{"detail": "<message>"}`. Invalid request bodies or parameters return 422 with
  FastAPI's default body.
- IDs are opaque to clients. Timestamps are ISO 8601 in UTC (`2026-11-03T09:30:00Z`);
  dates are `YYYY-MM-DD`.
- Paged lists return `{"items": [...], "page": 1, "page_size": 20, "total": 57}`.
  `page` starts at 1; `page_size` defaults to 20, maximum 100.

## Shapes

**User**

```json
{"id": "…", "email": "sam@example.com", "full_name": "Sam Carter",
 "role": "applicant", "branch_id": null, "active": true}
```

`role` is `applicant`, `agent` or `admin`. `branch_id` is set for agents only.

**Token**

```json
{"access_token": "…", "token_type": "bearer"}
```

**Branch**

```json
{"id": "…", "name": "Harrogate", "city": "Harrogate"}
```

**Listing**

```json
{"id": "…", "branch_id": "…", "title": "Two-bed flat near the station",
 "description": "…", "address_line": "4 Station Parade", "city": "Harrogate",
 "postcode": "HG1 1TE", "bedrooms": 2, "monthly_rent": 975,
 "available_from": "2026-12-01", "status": "open",
 "created_at": "…", "updated_at": "…"}
```

**Application**

```json
{"id": "…", "listing_id": "…", "applicant_id": "…", "status": "draft",
 "full_name": "Sam Carter", "date_of_birth": "1994-05-17", "phone": "07700 900123",
 "contact_email": "sam@example.com", "current_address": "12 Mill Lane, Leeds LS6 2AB",
 "employment_status": "employed", "employer_name": "Northfield Foods",
 "annual_income": 34000, "move_in_date": "2026-12-15", "occupants": 2, "pets": false,
 "notes": null, "decision_note": null, "created_at": "…", "submitted_at": null,
 "decided_at": null, "withdrawn_at": null}
```

`decision_note` appears only in responses to agents and admins.

**Document**

```json
{"id": "…", "application_id": "…", "kind": "photo_id", "filename": "passport.pdf",
 "content_type": "application/pdf", "size_bytes": 482113, "uploaded_at": "…"}
```

## Endpoints

"Owner" is the applicant who started the application. "Branch agents" are the agents of
the branch the application's listing belongs to.

| Method | Path | Who | Success |
|---|---|---|---|
| GET | `/health` | Anyone | 200 `{"status": "ok"}` |
| POST | `/auth/register` | Anyone | 201 User |
| POST | `/auth/login` | Anyone | 200 Token |
| POST | `/auth/logout` | Signed in | 204 |
| GET | `/me` | Signed in | 200 User |
| PUT | `/me/password` | Signed in | 204 |
| GET | `/branches` | Anyone | 200 list of Branch |
| POST | `/admin/branches` | Admin | 201 Branch |
| GET | `/admin/agents` | Admin | 200 list of User |
| POST | `/admin/agents` | Admin | 201 User |
| PATCH | `/admin/agents/{id}` | Admin | 200 User |
| GET | `/listings` | Anyone | 200 page of Listing |
| GET | `/listings/{id}` | Anyone; closed listings: branch agents and admins | 200 Listing |
| POST | `/listings` | Agent | 201 Listing |
| PATCH | `/listings/{id}` | Agents of the listing's branch | 200 Listing |
| POST | `/listings/{id}/applications` | Applicant | 201 Application |
| GET | `/applications` | Applicant, agent, admin | 200 page of Application |
| GET | `/applications/{id}` | Owner, branch agents, admins | 200 Application |
| PATCH | `/applications/{id}` | Owner | 200 Application |
| POST | `/applications/{id}/submit` | Owner | 200 Application |
| POST | `/applications/{id}/withdraw` | Owner | 200 Application |
| POST | `/applications/{id}/decision` | Branch agents | 200 Application |
| POST | `/applications/{id}/documents` | Owner | 201 Document |
| GET | `/applications/{id}/documents` | Owner, branch agents, admins | 200 list of Document |
| GET | `/applications/{id}/documents/{document_id}/content` | Owner, branch agents, admins | 200 the file |
| DELETE | `/applications/{id}/documents/{document_id}` | Owner | 204 |

Agents and admins never see draft applications, nor applications withdrawn before
submission: for them these return 404 and are left out of lists.

### Accounts

`POST /auth/register` takes `{"email", "password", "full_name"}` and creates an
applicant. `password` is at least 8 characters. Registering an email that already has an
account (compared case-insensitively) must not create a second account or change the
existing one.

`POST /auth/login` takes `{"email", "password"}`. A wrong email or password, or a
deactivated account, returns 401 `{"detail": "Invalid email or password"}`.

`POST /auth/logout` ends the session: the token stops working.

`PUT /me/password` takes `{"current_password", "new_password"}`. A wrong current
password returns 400 `{"detail": "Current password is incorrect"}`.

### Administration

`POST /admin/branches` takes `{"name", "city"}`. A name already in use returns 409.

`POST /admin/agents` takes `{"email", "full_name", "branch_id", "initial_password"}` and
creates an agent. An email that already has an account returns 409; a branch that does
not exist returns 422.

`PATCH /admin/agents/{id}` takes `{"active": false}` or `{"active": true}`.
Deactivating an agent ends their sessions at once.

### Listings

`GET /listings` returns open listings only, whoever calls. Query parameters, all
optional:

| Parameter | Meaning |
|---|---|
| `city` | City, case-insensitive exact match |
| `min_bedrooms` | At least this many bedrooms |
| `max_rent` | Monthly rent at most this |
| `available_by` | `available_from` on or before this date |
| `q` | Case-insensitive text in the title or description |
| `sort` | `-created_at` (default), `rent`, `-rent`, `available_from`, `-available_from` |
| `page`, `page_size` | Paging |

`POST /listings` takes `title`, `description`, `address_line`, `city`, `postcode`,
`bedrooms`, `monthly_rent` and `available_from`, with the limits in the
[data model](data-model.md). The listing belongs to the agent's branch and starts
`open`.

`PATCH /listings/{id}` takes any of those fields, plus `status` (`open` or `closed`).

### Applications

`POST /listings/{id}/applications` takes `full_name`, `date_of_birth`, `phone`,
`contact_email`, `current_address`, `employment_status`, `employer_name` (optional),
`annual_income`, `move_in_date`, `occupants`, `pets` and `notes` (optional), with the
limits in the [data model](data-model.md), and creates a draft.

- The listing does not exist or is closed: 404.
- The applicant already applied for it: 409
  `{"detail": "You have already applied for this listing"}`.
- The applicant is under 18 on the day: 422.

`GET /applications` returns, most recently created first: the caller's own applications
for an applicant; the applications to their branch's listings for an agent; every
branch's for an admin. Query parameters, all optional: `status`, `listing_id`, `page`,
`page_size`.

`PATCH /applications/{id}` takes any of the creation fields. An application that is not
a draft returns 409 `{"detail": "Only draft applications can be changed"}`.

`POST /applications/{id}/submit` takes no body.

- Not a draft: 409.
- Listing closed: 409 `{"detail": "Listing is closed"}`.
- No photo ID or no proof of income: 422
  `{"detail": "Photo ID and proof of income are required"}`.

`POST /applications/{id}/withdraw` takes no body. Allowed from `draft` or `submitted`;
otherwise 409.

`POST /applications/{id}/decision` takes `{"decision": "approved" | "rejected",
"note": "…"}`; `note` is optional, up to 2,000 characters. Allowed from `submitted` only;
otherwise 409.

### Documents

`POST /applications/{id}/documents` is a multipart form with fields `kind` (`photo_id`,
`proof_of_income`, `proof_of_address` or `other`) and `file`.

- Not PDF, JPEG or PNG: 415 `{"detail": "Only PDF, JPEG or PNG files are accepted"}`.
- Over 10 MB (10,485,760 bytes): 413.
- Application not a draft: 409.
- Application already holds 10 documents: 409
  `{"detail": "An application can hold at most 10 documents"}`.

`GET /applications/{id}/documents/{document_id}/content` returns the file as uploaded,
with the document's `content_type`. Browsers save it under its original file name.

`DELETE /applications/{id}/documents/{document_id}` is allowed on drafts only;
otherwise 409.
