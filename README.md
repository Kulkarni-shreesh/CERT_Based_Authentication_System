# Current Project State: Certificate-Based Authentication / PKI Portal

This README describes the current state of the project for summarization, handoff, or further planning.

## Project Purpose

This is a self-learning and CV showcase project for certificate-based authentication. It demonstrates:

- OpenSSL-based PKI setup
- Root CA and Intermediate CA
- Browser-importable `.p12` client certificates
- Nginx mutual TLS authentication
- Backend certificate identity mapping
- Certificate revocation using CRL
- A small PKI lifecycle portal with role-based login
- Employee, manager, and admin workflows

It is not intended to be an enterprise production deployment. The design is intentionally local, understandable, and demo-friendly.

## Technology Stack

- OpenSSL for CA, certificate, CSR, `.p12`, and CRL operations
- Nginx for HTTPS and mTLS enforcement
- Python standard-library HTTP server for backend and portal
- SQLite for users, employees, certificate requests, certificates, audit logs, notifications, and sessions
- Browser for mTLS client certificate demo
- PowerShell for local run commands

No Flask or external Python web framework is currently used.

## Main Files And Folders

```text
app/app.py
app/cert_auth.db
nginx/nginx-mtls.conf
nginx/mime.types
pki/
pki/certs/
pki/private/
pki/csr/
pki/crl/
pki/intermediate-ca-db/
pki/root-ca-db/
tools/nginx-1.30.1/
www/index.html
evidence/
README_CURRENT_STATE.md
COMPREHENSIVE_PROJECT_REPORT.md
LEVEL_UP_FEATURES.md
FLASK_ROUTE_DESIGN_CORRECTED.md
```

## PKI State

The project has a working local CA hierarchy:

```text
Root CA          -> ca.crt
Intermediate CA  -> intermediate.crt
CA chain         -> pki/certs/ca-chain.crt
```

Important client bundles:

```text
client.p12          password: clientpass
alice-client.p12    password: alicepass
expired-client.p12  password: expiredpass
revoked-client.p12  password: revokedpass
```

Portal-issued certificates use:

```text
password: portalpass
```

## Nginx mTLS

Nginx is configured in:

```text
nginx/nginx-mtls.conf
```

Important directives:

```nginx
ssl_client_certificate ".../pki/certs/ca-chain.crt";
ssl_crl ".../pki/crl/ca-chain.crl";
ssl_verify_client on;
ssl_verify_depth 2;
```

Nginx verifies the client certificate during TLS handshake. If verification succeeds, it proxies requests to the backend and passes:

```text
X-SSL-Client-Verify
X-SSL-Client-DN
X-SSL-Client-Issuer-DN
```

Backend service:

```text
http://127.0.0.1:8081
```

Nginx HTTPS service:

```text
https://localhost
```

## Backend And Portal

The backend is a single Python file:

```text
app/app.py
```

It handles:

- login/logout
- role-based sessions
- employee portal
- manager approval queue
- admin dashboard
- user management
- certificate list
- certificate revocation
- audit log
- `.p12` downloads
- mTLS login result page

## Authentication Model

The project currently uses username/password login for the portal.

Login URL:

```text
http://127.0.0.1:8081/login
```

Seeded demo accounts:

```text
Employee:
john@company.com
password123

Manager:
bob@company.com
password123

Admin:
charlie@company.com
password123
```

Passwords are stored in SQLite as salted PBKDF2 hashes, not plaintext.

The portal uses session cookies:

```text
pki_session
```

## Role-Based Access

The portal is segregated by role:

```text
employee -> employee portal only
manager  -> manager approval portal
admin    -> admin dashboard, users, certs, revocation, audit
```

Verified behavior:

```text
john@company.com trying /app/admin       -> 403 Forbidden
bob@company.com opening /app/manager     -> allowed
charlie@company.com opening /app/admin   -> allowed
```

## Main Routes

Public/login:

```text
GET  /login
POST /login
POST /logout
GET  /health
```

mTLS protected identity demo:

```text
GET /app
```

Employee portal:

```text
GET  /app/portal
POST /app/portal/request
GET  /app/request?id=<request_db_id>
GET  /app/certificate?id=<cert_id>
GET  /app/download?id=<cert_id>
```

Manager portal:

```text
GET  /app/manager
POST /app/manager/decision
```

Admin portal:

```text
GET  /app/admin
GET  /app/admin/users
GET  /app/admin/users/new
POST /app/admin/users/new
GET  /app/admin/certificates
GET  /app/admin/revoke?id=<cert_id>
POST /app/admin/revoke
POST /app/admin/sign
GET  /app/audit
```

## Employee Workflow

1. Admin adds employee through UI:

```text
/app/admin/users/new
```

2. Employee logs in.
3. Employee opens:

```text
/app/portal
```

4. Employee clicks:

```text
Generate & Submit Certificate Request
```

5. Request is stored in SQLite as:

```text
PENDING_MANAGER
```

6. Manager is notified in the demo notification table.

## Manager Workflow

1. Manager logs in as:

```text
bob@company.com / password123
```

2. Manager opens:

```text
/app/manager
```

3. Manager approves or rejects pending requests.

If approved, request status becomes:

```text
MANAGER_APPROVED
```

## Admin Workflow

1. Admin logs in as:

```text
charlie@company.com / password123
```

2. Admin opens:

```text
/app/admin
```

3. Admin can:

- view statistics
- view pending manager-approved requests
- sign certificates
- manage users
- view all certificates
- revoke certificates
- view audit logs

## Certificate Signing Flow

When admin signs an approved request:

1. Backend generates private key using OpenSSL.
2. Backend generates CSR.
3. Backend signs certificate with Intermediate CA.
4. Backend creates browser-importable `.p12`.
5. Backend stores certificate metadata in SQLite.
6. Backend adds mTLS CN-to-user mapping.
7. Backend logs audit event.
8. Backend creates notification for employee.

Portal-issued cert CN is the employee email:

```text
CN=employee@company.com
```

Portal-issued `.p12` password:

```text
portalpass
```

## Revocation Flow

Admin opens:

```text
/app/admin/certificates
```

Then clicks revoke on an active certificate.

Backend does:

1. Marks certificate as `REVOKED` in SQLite.
2. Calls OpenSSL to revoke the certificate.
3. Regenerates Intermediate CA CRL.
4. Rebuilds combined CRL:

```text
pki/crl/ca-chain.crl
```

5. Reloads Nginx.
6. Logs audit event.
7. Creates employee notification.

Nginx then rejects that certificate during mTLS:

```text
FAILED:certificate revoked
```

## Current Frontend State

The frontend is server-rendered HTML generated from `app/app.py`.

Recent visual improvements:

- cleaner header
- sticky navigation
- role-aware navigation
- improved login page
- polished cards
- better dashboard metric cards
- improved tables
- status badges
- better forms and buttons
- better focus states
- subtle shadows and spacing
- cleaner warning/error panels

The frontend is still simple and dependency-free. It does not use React, Bootstrap, Tailwind, Flask templates, or static CSS files yet.

## How To Run

Open VS Code in:

```text
C:\Users\kulka\OneDrive\Desktop\cert-based authentication
```

Terminal 1: start backend:

```powershell
python app\app.py
```

Expected output:

```text
PKI portal listening on http://127.0.0.1:8081
```

Terminal 2: start Nginx:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf"
```

If Nginx is already running:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf" -s reload
```

Stop Nginx:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf" -s stop
```

## URLs To Open

Portal login:

```text
http://127.0.0.1:8081/login
```

Admin dashboard:

```text
http://127.0.0.1:8081/app/admin
```

Admin users:

```text
http://127.0.0.1:8081/app/admin/users
```

All certificates:

```text
http://127.0.0.1:8081/app/admin/certificates
```

Manager approval:

```text
http://127.0.0.1:8081/app/manager
```

Employee portal:

```text
http://127.0.0.1:8081/app/portal
```

mTLS demo through Nginx:

```text
https://localhost/app
```

## Important mTLS Note

This route:

```text
http://127.0.0.1:8081/app
```

will show access denied because it bypasses Nginx. The backend expects Nginx to provide mTLS headers.

Use this for real mTLS:

```text
https://localhost/app
```

## Common Troubleshooting

If a new route gives 404 after code changes, old Python servers may still be running. Stop them:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*app.py*' -and $_.Name -like 'python*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

Then restart:

```powershell
python app\app.py
```

If mTLS gives `400 Bad Request` and logs say:

```text
FAILED:CRL has expired
```

regenerate CRLs and restart Nginx.

## Current Limitations

- This is still a learning/demo project.
- The backend is a single Python file.
- The UI is server-rendered and dependency-free.
- There is no real email notification; notifications are stored in SQLite.
- There is no true browser-side CSR generation yet; the portal models the CSR workflow, while OpenSSL does server-side key/CSR/cert generation for demo practicality.
- There is no production-grade secret management.
- There is no enterprise IAM/SSO.
- There is no OCSP.
- There is no HTTPS on the backend directly; Nginx is the HTTPS/mTLS gateway.

## Good Next Improvements

Possible next upgrades:

1. Move from single-file Python HTTP server to Flask.
2. Split code into:

```text
models.py
routes/auth.py
routes/portal.py
routes/manager.py
routes/admin.py
templates/
static/
```

3. Move CSS into a static file.
4. Add client-side CSR generation using WebCrypto or a JS PKI library.
5. Add real email simulation page or SMTP integration.
6. Add better audit log filtering/export.
7. Add charts to admin dashboard.
8. Add automated test scripts.
9. Add a cleaner README for GitHub.
10. Add screenshots for CV/project documentation.

## Short CV Description

Built a local certificate-based authentication and PKI lifecycle portal using OpenSSL, Nginx mTLS, Python, and SQLite. Implemented Root/Intermediate CA setup, browser-importable client certificates, role-based employee/manager/admin portals, certificate request and approval workflow, IT admin signing, `.p12` downloads, CRL-based revocation, audit logs, notifications, and mTLS access testing for valid, expired, revoked, and missing certificates.
