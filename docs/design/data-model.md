# Tenant Applications API: Data Model

Version 1.0, 3 November 2026. Tables below are the minimum; the implementation may add
its own (for example, for sessions). "Personal" marks personal data under UK GDPR.

## users

| Field | Type | Notes | Personal |
|---|---|---|---|
| id | key | | |
| email | text, unique | Compared case-insensitively | Yes |
| password_hash | text | | |
| full_name | text, 1-100 | | Yes |
| role | `applicant`, `agent`, `admin` | | |
| branch_id | branches.id | Agents only | |
| active | boolean | Admins deactivate agents | |
| created_at | timestamp | | |

## branches

| Field | Type | Notes |
|---|---|---|
| id | key | |
| name | text, 1-80, unique | |
| city | text, 1-80 | |
| created_at | timestamp | |

## listings

| Field | Type | Notes |
|---|---|---|
| id | key | |
| branch_id | branches.id | The creating agent's branch |
| title | text, 1-120 | |
| description | text, up to 5,000 | |
| address_line | text, 1-200 | |
| city | text, 1-80 | |
| postcode | text | UK postcode |
| bedrooms | integer, 0-10 | 0 is a studio |
| monthly_rent | integer, 1-20,000 | Whole pounds |
| available_from | date | |
| status | `open`, `closed` | |
| created_by | users.id | |
| created_at, updated_at | timestamp | |

## applications

One row per applicant per listing (unique on `listing_id`, `applicant_id`).

| Field | Type | Notes | Personal |
|---|---|---|---|
| id | key | | |
| listing_id | listings.id | | |
| applicant_id | users.id | | |
| status | `draft`, `submitted`, `withdrawn`, `approved`, `rejected` | | |
| full_name | text, 1-100 | | Yes |
| date_of_birth | date | Applicant is 18 or over | Yes |
| phone | text, up to 20 | | Yes |
| contact_email | email | | Yes |
| current_address | text, up to 300 | | Yes |
| employment_status | `employed`, `self_employed`, `student`, `unemployed`, `retired` | | Yes |
| employer_name | text, up to 100, optional | | Yes |
| annual_income | integer, 0-10,000,000 | Whole pounds | Yes |
| move_in_date | date | | |
| occupants | integer, 1-10 | | |
| pets | boolean | | |
| notes | text, up to 2,000, optional | Free text from the applicant | Yes |
| decision_note | text, up to 2,000 | Internal; never shown to the applicant | Yes |
| decided_by | users.id | | |
| created_at, submitted_at, decided_at, withdrawn_at | timestamp | | |

## documents

Metadata only; the file itself is in the document store (see
[architecture](architecture.md), section 2).

| Field | Type | Notes | Personal |
|---|---|---|---|
| id | key | | |
| application_id | applications.id | | |
| kind | `photo_id`, `proof_of_income`, `proof_of_address`, `other` | | |
| original_filename | text, up to 255 | As uploaded | Yes |
| content_type | `application/pdf`, `image/jpeg`, `image/png` | | |
| size_bytes | integer, up to 10,485,760 | | |
| storage_key | text | Where the file sits under `LARCH_DOCUMENTS_DIR` | |
| uploaded_at | timestamp | | |

Document contents are personal data: passports, driving licences, payslips, bank
statements and utility bills.

## Retention

Not decided yet; see open question 1 in the [product specification](../product-spec.md).
