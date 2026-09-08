# Level-Up Features: PKI Portal, Revocation UI, Admin Dashboard

This upgrade turns the original mTLS lab into a small PKI operations portal. It is still a self-learning/CV showcase project, but now it demonstrates workflow, approval, signing, revocation, notifications, audit logging, and dashboard visibility.

## New Routes

Run the backend and open these pages:

```text
http://127.0.0.1:8081/app/portal
http://127.0.0.1:8081/app/manager
http://127.0.0.1:8081/app/admin
http://127.0.0.1:8081/app/admin/certificates
```

Through Nginx, use:

```text
https://localhost/app/portal
https://localhost/app/manager
https://localhost/app/admin
https://localhost/app/admin/certificates
```

## Feature 1: PKI Certificate Portal

Employee demo user:

```text
John Smith
john@company.com
Engineering
Software Engineer
Manager: Bob Johnson
```

Employee flow implemented:

1. Employee opens the portal.
2. Employee clicks `Generate & Submit Certificate Request`.
3. The request is stored in SQLite as `PENDING_MANAGER`.
4. Manager notification is created.
5. Manager approves from `/app/manager`.
6. Request becomes `MANAGER_APPROVED`.
7. IT admin signs from `/app/admin`.
8. OpenSSL creates a key, CSR, certificate, and `.p12` bundle.
9. Certificate is recorded in the database as `ACTIVE`.
10. Employee can download the `.p12`.

Demo note: the UI explains the browser-local CSR concept. For this local learning project, the final `.p12` is generated server-side so the demo remains easy to run without adding a heavy JavaScript PKI library.

Portal-issued `.p12` import password:

```text
portalpass
```

## Feature 2: Revocation Management UI

Admin revocation page:

```text
/app/admin/certificates
```

Implemented workflow:

1. Admin views certificates.
2. Admin clicks `Revoke`.
3. Admin selects a reason and optional notes.
4. Backend marks the certificate as `REVOKED`.
5. Backend calls OpenSSL to revoke the certificate.
6. Backend regenerates the Intermediate CA CRL.
7. Backend rebuilds `pki/crl/ca-chain.crl`.
8. Backend reloads Nginx.
9. Audit log entry is created.
10. Employee notification is created.

After revocation, Nginx denies that certificate during mTLS because the serial number is present in the CRL.

## Feature 3: Admin Dashboard

Admin dashboard:

```text
/app/admin
```

Dashboard sections implemented:

- statistics cards
- requests ready for signing
- pending manager approvals
- alerts
- certificates by department
- recent audit activity
- quick actions

## Database Tables

The upgraded app uses these SQLite tables:

```text
users
employees
certificate_requests
certificates
audit_log
notifications
```

Database file:

```text
app/cert_auth.db
```

## Important Files

```text
app/app.py
nginx/nginx-mtls.conf
pki/intermediate-ca-db/intermediate-ca.cnf
pki/crl/ca-chain.crl
```

## How To Demo

1. Start backend:

```powershell
python app\app.py
```

2. Start or reload Nginx:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf"
```

3. Open employee portal:

```text
https://localhost/app/portal
```

4. Submit a certificate request.

5. Open manager queue:

```text
https://localhost/app/manager
```

6. Approve the request.

7. Open admin dashboard:

```text
https://localhost/app/admin
```

8. Sign the approved request.

9. Open revocation management:

```text
https://localhost/app/admin/certificates
```

10. Revoke a demo certificate and explain that Nginx checks the regenerated CRL immediately.

## CV Upgrade Description

Extended the mTLS authentication lab into a PKI certificate lifecycle portal with employee certificate requests, manager approval workflow, IT admin signing, downloadable `.p12` bundles, admin dashboard metrics, certificate revocation UI, CRL regeneration, Nginx reload automation, notifications, and audit logging.
