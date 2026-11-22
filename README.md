# CX Pulse UAE
**Bilingual Customer Experience & Administrative Operations Platform**

A portfolio-grade operations application demonstrating customer case management, administrative coordination, secure access, bilingual UX and operational reporting.

## Product status

- **Front end:** Responsive English/Arabic dashboard, case list/search, create case, status updates and CSV export.
- **API:** Cloudflare Worker endpoints for health, OTP authentication, sessions, cases and reports.
- **Database:** Cloudflare D1 schema and migration included.
- **Security:** Email allowlist, one-time codes, hashed OTPs and session tokens, HTTP-only secure cookies, same-origin mutation checks, request validation, rate limiting and audit events.
- **Tests:** Validation and allowlist unit tests.
- **Current deployment checkpoint (21 Nov 2026):** Cloudflare Worker is live; D1 binding is configured; the initial SQL migration has been applied; `/api/health` has returned `ok: true` and `databaseReachable: true`. Authentication is not yet enabled until the admin allowlist, OTP pepper, and Resend email settings are configured and tested.

## Demo and production behavior

When not signed in, the website remains in clearly labelled demo mode with illustrative sample figures and browser-session-only sample records. No real customer records are included. Once backend configuration is complete, authorised staff can sign in and use D1-backed records.

**Never enter real customer, banking, identity or confidential data into the public demo.** For a real deployment, use an approved privacy notice, retention policy, access review and incident process.

## Architecture

- Cloudflare Workers: API and static asset delivery.
- Cloudflare D1: users, OTP records, sessions, cases, rate limits and audit events.
- Resend: email delivery for six-digit OTP codes.
- GitHub: source control and CI tests.

## Setup

### 1. Install and test

Requires Node.js 22+.

```bash
npm install
npm test
```

### 2. D1 database (already provisioned for the current deployment)

The production database `cx-pulse-uae-db` is already created, bound as `DB`, and the `migrations/0001_initial.sql` schema has been applied. The live health endpoint has confirmed database connectivity. Do not recreate the database or rerun the initial SQL migration on this deployment.

### 3. Configure email delivery and access

The administrator login and the Resend account owner are separate addresses in this setup. Keep the administrator address only in `ADMIN_EMAILS`. The Resend account owner's address may be placed temporarily in `AGENT_EMAILS` for a limited OTP delivery test. Resend's shared testing sender `onboarding@resend.dev` can send only to the Resend account owner's own email address; to deliver OTPs to the administrator or other staff, verify a domain you own in Resend and use a sender on that verified domain. Configure the following in Cloudflare Worker settings; do not commit secrets to GitHub:

**Worker secrets**
- `RESEND_API_KEY`: Resend API key.
- `OTP_PEPPER`: long, random secret used to hash one-time codes.

**Worker variables**
- `FROM_EMAIL`: `CX Pulse <onboarding@resend.dev>` only while testing delivery to the Resend account owner; for administrator/staff delivery, use a sender on your verified domain.
- `ADMIN_EMAILS`: the exact administrator login email only.
- `AGENT_EMAILS`: approved staff emails; the Resend account owner email may be included temporarily as an agent for the sandbox OTP test.

Only allowlisted addresses can sign in. Admins can view all cases; agents can view cases they created or are assigned to. Keep the allowlists short and reviewed.

### 4. Deploy

After adding or changing variables/secrets in Cloudflare Dashboard, select Deploy so the new Worker version receives them. Code deployments from the connected GitHub repository continue through the configured deployment integration.

The deployment uses the static assets in `public/` and routes `/api/*` through the Worker.

### 5. Verify

- `GET /api/health` should return `ok: true` and `databaseConfigured: true`.
- Request an OTP with an allowlisted address.
- Verify the code and confirm the secure session cookie is set.
- Create a case, update its status, reload and confirm it persists.
- Confirm a non-allowlisted address cannot sign in.
- Confirm an agent cannot view or modify another agent's case.
- Confirm the audit log records case creation and status updates.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health |
| POST | `/api/auth/request-otp` | Send six-digit code |
| POST | `/api/auth/verify-otp` | Verify code and create session |
| POST | `/api/auth/logout` | Revoke current session |
| GET | `/api/auth/me` | Current signed-in user |
| GET | `/api/cases` | List permitted cases |
| POST | `/api/cases` | Create case |
| PATCH | `/api/cases/:id` | Update case status |
| GET | `/api/reports/summary` | Database-backed summary |

## Security and privacy notes

- OTP values and session tokens are never stored in plaintext.
- OTPs expire after 10 minutes and are limited to five verification attempts.
- Sign-in requests are rate-limited by hashed IP and email identifiers.
- Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict` and the `__Host-` prefix.
- Mutating API requests reject cross-origin browser requests.
- The API does not expose customer contact details.
- This is a portfolio implementation, not a certified banking or regulated case-management product. Complete a security review and privacy assessment before handling real customer data.

## Roadmap

1. Complete Cloudflare D1 provisioning and production secrets.
2. Add assignment management and richer audit history.
3. Add configurable SLA rules and scheduled reminders.
4. Add optional AI-assisted categorisation with human review and data minimisation.
5. Add accessibility review, security testing and operational documentation.

## Portfolio positioning

CX Pulse UAE showcases skills relevant to administration, customer service, operations coordination, reporting, process improvement and bilingual digital product design. It is an independent portfolio project and is not affiliated with a bank, government entity or other institution.
