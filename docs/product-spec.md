# Tenant Applications API: Product Specification

| | |
|---|---|
| Client | Larch Lettings Ltd |
| Product owner | Head of Lettings Operations, Larch Lettings |
| Version | 1.0, approved 3 November 2026 |
| Design | [Architecture](design/architecture.md) · [Data model](design/data-model.md) · [API contract](design/api.md) |

## 1. Background

Larch Lettings is a letting agency with six branches in the north of England. Today a
prospective tenant applies by emailing a PDF form and attachments to a branch inbox.
Applications get lost, agents retype every form, and copies of passports and payslips
sit in shared mailboxes.

Version 1 replaces the email process with an online application. Larch's web team is
building the front end, a single-page app in its own repository (`larch-web`). This
repository is the backend API that front end calls.

Applications carry copies of photo ID and evidence of income, so a leak would directly
harm applicants and would be reportable under UK GDPR.

## 2. Goals

- Applicants apply for a property online and upload their documents in one place.
- Agents review complete applications for their branch without retyping anything.
- Head office manages branches and agent accounts itself.

Success: 80% of applications made online within three months of launch, and an average
of under three working days from submission to decision.

## 3. Users and roles

| Role | Who | Can |
|---|---|---|
| Visitor | Anyone, not signed in | Browse open listings and branches |
| Applicant | Member of the public; registers themselves | Everything a visitor can; start, edit, submit and withdraw their own applications; upload documents to them; see the decision |
| Agent | Branch staff; account created by an admin | Create and edit listings for their own branch; review submitted applications to those listings; download their documents; record decisions |
| Admin | Head office staff | Manage branches and agent accounts; view every listing, submitted application and document, read only |

Each user has one role. An agent belongs to exactly one branch.

## 4. User journeys

### 4.1 Apply for a property

1. A visitor browses open listings and filters them by city, bedrooms, rent and
   availability date.
2. They register with their email address, a password and their full name, then sign in.
3. They start an application for a listing and fill in their personal details.
4. They upload documents. Photo ID and proof of income are required; proof of address
   is optional.
5. They check the application and submit it. A submitted application can no longer be
   edited.
6. They follow its status: submitted, approved, rejected or withdrawn.
7. They can withdraw it at any time before a decision.

### 4.2 Review an application

1. An agent signs in and sees the submitted applications for their branch, newest first,
   filtered by listing or status if they wish.
2. They open an application, read the details and download the documents. Photo ID is
   collected so the branch can complete the Right to Rent check the Immigration Act 2014
   requires.
3. They record a decision, approved or rejected, with an internal note. The applicant
   sees the decision but not the note.

### 4.3 Manage listings

An agent creates a listing for their branch, edits it, and closes it once the property
is let. Closing a listing leaves its existing applications as they are.

### 4.4 Manage branches and agents

An admin creates branches and creates agent accounts with an initial password, which
they pass to the agent by phone. Agents can change their password at any time. When an
agent leaves, the admin deactivates the account, which removes their access immediately.

The first admin account is created with a command when the service is deployed.

## 5. Functional requirements

| ID | Requirement |
|---|---|
| FR-01 | Visitors can list open listings, filtered by city, minimum bedrooms, maximum rent, availability date and a free-text search of title and description, sorted by rent, availability date or newest, one page at a time. |
| FR-02 | Visitors can view an open listing. A closed listing is visible only to agents of its branch and to admins. |
| FR-03 | Anyone can register as an applicant with an email address, a password of at least 8 characters and their full name. One email address holds at most one account. |
| FR-04 | Users sign in with email and password, and can sign out. |
| FR-05 | Signed-in users can view their own account and change their password by giving the current one. |
| FR-06 | An applicant can start one application per listing, on open listings only. Applicants must be 18 or over. |
| FR-07 | An applicant can edit their application while it is a draft. |
| FR-08 | An applicant can upload documents to a draft: PDF, JPEG or PNG, up to 10 MB each and up to 10 per application, each marked with its kind. |
| FR-09 | An applicant can remove a document from a draft. |
| FR-10 | An applicant can submit a draft that holds at least one photo ID and one proof of income, while the listing is open. |
| FR-11 | An applicant can withdraw a draft or a submitted application. |
| FR-12 | An applicant sees their own applications and their status, including the decision, but never the agent's internal note. |
| FR-13 | An agent sees the applications to their branch's listings, filtered by listing and status. Agents never see drafts; an application withdrawn before it was submitted stays invisible to them. |
| FR-14 | An agent can download the documents of those applications, under their original file names. |
| FR-15 | An agent records a decision on a submitted application: approved or rejected, with an internal note. |
| FR-16 | An agent creates, edits, closes and reopens listings for their own branch. |
| FR-17 | An admin creates branches. |
| FR-18 | An admin creates agent accounts (email, name, branch, initial password), lists them and deactivates or reactivates them. Deactivation takes effect immediately. |
| FR-19 | An admin sees what agents see, across every branch, read only. |
| FR-20 | A command creates an admin account. |

## 6. Business rules

- Application status moves only as follows: draft to submitted; submitted to approved or
  rejected; draft or submitted to withdrawn.
- An applicant cannot start a second application for the same listing, even after
  withdrawing the first.
- Applicants cannot start or submit applications on a closed listing.
- Rent is in whole pounds per month.
- The API works in UTC; the front end shows UK time.

## 7. Non-functional requirements

- Volume: about 2,000 applications and 6,000 documents a month at peak; about 15 agents
  online at once.
- Performance: 95% of API calls answered within 500 ms, document uploads excepted.
- Availability: 07:00 to 22:00 UK time every day; maintenance overnight.
- Data location: United Kingdom.
- Security: access follows the roles in section 3. Standard security practices apply.

## 8. Out of scope for version 1

- Password reset (planned for 1.1).
- Email notifications (planned for 1.1).
- Account deletion by the applicant; head office handles requests by hand.
- Referencing and credit checks by third parties.
- Holding deposits and other payments.

## 9. Open questions

| # | Question | Owner | Due |
|---|---|---|---|
| 1 | How long do we keep applications and documents after a decision or a withdrawal? | Legal | 30 November 2026 |
| 2 | Do agents need to export applications to the CRM? | Lettings Operations | Release 1.1 |
