# CertManMon

A self-hosted certificate management and monitoring platform. Track SSL/TLS certificates, monitor expiry dates, manage responsible persons, and receive automated email alerts — all from a clean web interface running in Docker.

![Dashboard](https://img.shields.io/badge/status-active-brightgreen) ![Docker](https://img.shields.io/badge/docker-ready-blue) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Features

### Certificate Management
- Add, edit and delete certificates with name, FQDN, expiry date and password
- Upload certificate files (`.pem`, `.crt`, `.cer`, `.pfx`, `.p12`) with automatic expiry date extraction
- Download stored certificates as PEM files
- Add multiple host resources per certificate with responsible persons
- Notes field for additional context
- Auto-suggest responsible persons from the user list

### Monitoring & Dashboard
- Color-coded status badges: Valid / Warning (<30d) / Critical (<14d) / Expired
- Summary stats bar showing totals per status
- Search and filter by name, FQDN, host, or status
- Certificate visibility groups — control which users see which certificates

### Email Notifications
- Configurable SMTP server (host, port, credentials, TLS)
- Three independent warning thresholds (e.g. 30, 14, 7 days before expiry)
- Automatic daily check at 08:00
- Sends to admin email list and/or responsible persons (matched via user accounts)
- Renewal notifications when a certificate's expiry date is extended
- Welcome email to new users with their login credentials
- "Run Check Now" and "Send Test Email" buttons in the UI
- Link to the platform included in notification emails

### User Management
- Local username/password authentication
- Microsoft Entra ID (Azure AD) SSO via OAuth2/OIDC
- Three roles: **Admin** (full access), **Editor** (certificate CRUD), **Viewer** (read-only)
- Display name field shown in header and user list
- Enable/disable individual accounts
- Welcome email sent automatically on user creation

### Groups & Access Control
- Create named groups with descriptions
- Assign users and certificates to groups
- Certificates with no group assigned are visible to admins only
- Group membership manageable from both the user modal and the group side panel

### API
- REST API under `/api/v1/` with API key authentication
- Two permission levels: **Read** and **Read/Write**
- Create and manage API keys from the Settings panel
- Keys shown only once on creation (SHA-256 hashed in database)
- All API activity logged in the audit log

| Method | Endpoint | Permission |
|--------|----------|------------|
| GET | `/api/v1/certificates` | Read |
| GET | `/api/v1/certificates/:id` | Read |
| POST | `/api/v1/certificates` | Read/Write |
| PUT | `/api/v1/certificates/:id` | Read/Write |
| DELETE | `/api/v1/certificates/:id` | Read/Write |
| GET | `/api/v1/groups` | Read |

### Audit Log
- Full event history for all actions
- Covers logins, logouts, certificate and user changes, settings updates, notification sends, API key usage
- Searchable and filterable by action category
- Paginated (50 entries per page)
- Clear all logs button

---

## Getting Started

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/)

### Quick Start

```bash
git clone https://github.com/whobat/CertManMon.git
cd CertManMon
docker compose up -d
```

Open **http://localhost:3000** and log in with the default credentials:

| Username | Password |
|----------|----------|
| `admin` | `changeme` |

> **Change the default password immediately** via Settings → Users.

---

## Configuration

All settings can be configured via the Settings UI. Alternatively, set environment variables in `docker-compose.yml` to pre-seed settings on first boot (existing DB values are never overwritten).

### `docker-compose.yml` environment variables

```yaml
environment:
  # Required
  - AUTH_USERNAME=admin
  - AUTH_PASSWORD=changeme
  - SESSION_SECRET=SuperSecretSecureString   # change this!

  # Optional: Entra ID SSO
  # - ENTRA_TENANT_ID=your-tenant-id
  # - ENTRA_CLIENT_ID=your-client-id
  # - ENTRA_CLIENT_SECRET=your-client-secret
  # - ENTRA_REDIRECT_URI=http://localhost:3000/api/auth/entra/callback

  # Optional: SMTP / Notifications
  # - SMTP_HOST=smtp.example.com
  # - SMTP_PORT=587
  # - SMTP_USER=user@example.com
  # - SMTP_PASS=your-smtp-password
  # - SMTP_FROM=certmanmon@example.com
  # - SMTP_TLS=true
  # - NOTIFICATIONS_ENABLED=false
  # - NOTIFY_RESPONSIBLE=true
  # - NOTIFY_RENEWAL=false
  # - THRESHOLD_1=30
  # - THRESHOLD_2=14
  # - THRESHOLD_3=7
  # - ADMIN_EMAILS=admin@example.com
  # - APP_URL=http://localhost:3000
```

### SESSION_SECRET
Set this to a long random string in production:
```bash
openssl rand -hex 32
```

---

## API Usage

Authenticate by passing your API key in the request header:

```bash
X-API-Key: cmm_your_key_here
# or
Authorization: Bearer cmm_your_key_here
```

**Examples:**

```bash
# List all certificates
curl -H "X-API-Key: cmm_your_key" http://localhost:3000/api/v1/certificates

# Get a single certificate
curl -H "X-API-Key: cmm_your_key" http://localhost:3000/api/v1/certificates/1

# Create a certificate (read/write key required)
curl -X POST \
  -H "X-API-Key: cmm_rw_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "wildcard.example.com",
    "fqdn": "*.example.com",
    "expiration_date": "2026-12-31",
    "note": "Renewed via API"
  }' \
  http://localhost:3000/api/v1/certificates

# Update a certificate
curl -X PUT \
  -H "X-API-Key: cmm_rw_key" \
  -H "Content-Type: application/json" \
  -d '{"name": "wildcard.example.com", "fqdn": "*.example.com", "expiration_date": "2027-06-01"}' \
  http://localhost:3000/api/v1/certificates/1

# Delete a certificate
curl -X DELETE \
  -H "X-API-Key: cmm_rw_key" \
  http://localhost:3000/api/v1/certificates/1
```

API keys are managed under **Settings → API Keys**.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Node.js + Express |
| Database | SQLite via `better-sqlite3` |
| Auth | `express-session`, `bcryptjs`, `@azure/msal-node` |
| Email | `nodemailer` |
| Scheduler | `node-cron` |
| Certificate parsing | `node-forge` |
| File uploads | `multer` |
| Frontend | Vanilla HTML/CSS/JS (no framework) |
| Container | Docker + Docker Compose |

---

## Data Persistence

Certificate data, users, groups, settings, and logs are stored in a SQLite database at `/data/certs.db` inside the container, mounted as a named Docker volume (`certmanmon_data`).

```bash
# Backup the database
docker cp certmanmon:/data/certs.db ./certs-backup.db
```

---

## Microsoft Entra ID Setup

1. Register an application in the [Azure Portal](https://portal.azure.com)
2. Set the redirect URI to `https://your-domain/api/auth/entra/callback`
3. Create a client secret under **Certificates & secrets**
4. In CertManMon → Settings → Authentication, enter:
   - Tenant ID
   - Client ID (Application ID)
   - Client Secret
   - Redirect URI
5. Enable the toggle and save

Users who sign in via Entra ID for the first time are automatically created with the **Viewer** role. Promote them in Settings → Users as needed.

---

## Updating

```bash
git pull
docker compose up -d --build
```

The database schema is updated automatically via migrations on startup — no manual steps required.
