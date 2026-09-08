# Certificate-Based Authentication Using OpenSSL, Nginx mTLS, Python, and SQLite

## 1. Project Overview

This project is a self-learning and CV showcase project that demonstrates certificate-based authentication using mutual TLS, also called mTLS. The system uses a private Public Key Infrastructure, Nginx as the TLS gateway, a Python backend application, and SQLite for simple user mapping.

The main idea is that users do not log in with a username and password. Instead, the browser presents a client certificate during the TLS handshake. Nginx verifies the certificate cryptographically. If the certificate is valid, trusted, not expired, and not revoked, Nginx forwards the request to the backend along with identity-related headers. The backend reads those headers and maps the certificate Common Name to a user record.

This project is not designed as an enterprise production deployment. It is intentionally built as a clear local lab that demonstrates the core security concepts in a simple and explainable way.

## 2. Objectives

The objectives of the project are:

- Create a local Root CA and Intermediate CA using OpenSSL.
- Generate browser-importable client certificates in `.p12` format.
- Configure Nginx to enforce mutual TLS.
- Reject users who do not present a valid client certificate.
- Pass verified certificate identity details from Nginx to the backend.
- Map a certificate Common Name to a user in a database.
- Demonstrate certificate revocation using a Certificate Revocation List.
- Test and record four important scenarios:
  - valid certificate
  - expired certificate
  - revoked certificate
  - no certificate

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| OpenSSL | Generate CA certificates, client certificates, server certificates, PKCS#12 bundles, and CRLs |
| Nginx | HTTPS server and mTLS verification gateway |
| Python | Backend application |
| SQLite | Simple local user database |
| Browser | Client certificate authentication demo |
| VS Code | Project editing and demo environment |
| PowerShell | Running OpenSSL, Nginx, and test commands |

## 4. High-Level Architecture

```text
Browser / OpenSSL Client
        |
        | HTTPS request with optional client certificate
        v
Nginx mTLS Gateway
        |
        | If certificate is valid:
        | passes X-SSL-Client-* headers
        v
Python Backend
        |
        | Looks up certificate CN
        v
SQLite User Database
```

Nginx is responsible for cryptographic certificate verification. The backend does not validate certificates directly. This is important because certificate validation belongs at the TLS layer. The backend only trusts the headers passed by Nginx because the backend is bound locally on `127.0.0.1:8081`.

## 5. Project Folder Structure

```text
cert-based authentication/
|
|-- app/
|   |-- app.py
|   |-- cert_auth.db
|
|-- evidence/
|   |-- 01-valid-client.txt
|   |-- 02-expired-client.txt
|   |-- 03-revoked-client.txt
|   |-- 04-no-client-cert.txt
|   |-- mtls-access.log
|   |-- mtls-error.log
|
|-- logs/
|   |-- mtls-access.log
|   |-- mtls-error.log
|
|-- nginx/
|   |-- nginx-mtls.conf
|   |-- mime.types
|
|-- pki/
|   |-- certs/
|   |-- crl/
|   |-- csr/
|   |-- private/
|   |-- intermediate-ca-db/
|   |-- root-ca-db/
|
|-- tools/
|   |-- nginx-1.30.1/
|
|-- www/
|   |-- index.html
|
|-- ca.crt
|-- intermediate.crt
|-- client.p12
|-- alice-client.p12
|-- expired-client.p12
|-- revoked-client.p12
|-- PHASE2_NGINX_MTLS.md
|-- PHASE3_BACKEND.md
|-- PHASE4_CRL.md
|-- PHASE5_TESTING_AND_REPORT.md
|-- PROJECT_REPORT.md
|-- COMPREHENSIVE_PROJECT_REPORT.md
```

## 6. Phase 1: PKI Setup

The first phase created the local certificate authority hierarchy.

### 6.1 Root CA

The Root CA is the trust anchor of the project. It signs the Intermediate CA certificate.

Important output:

```text
ca.crt
pki/private/ca.key
```

The browser must trust `ca.crt` so that it trusts certificates issued under this local CA chain.

### 6.2 Intermediate CA

The Intermediate CA is used to issue server and client certificates. This is better than issuing everything directly from the Root CA because it follows the common PKI design pattern where the Root CA stays at the top and the Intermediate CA performs day-to-day certificate issuance.

Important output:

```text
intermediate.crt
pki/private/intermediate.key
```

### 6.3 CA Chain

The CA chain file contains:

```text
intermediate.crt
ca.crt
```

Project file:

```text
pki/certs/ca-chain.crt
```

Nginx uses this file to verify client certificates.

### 6.4 Client Certificate

The first valid client certificate was created with:

```text
CN=phase1-client
```

Important files:

```text
pki/certs/client.crt
pki/private/client.key
client.p12
```

The `.p12` file is useful because browsers can import it as a personal certificate.

Password:

```text
clientpass
```

## 7. Phase 2: Nginx mTLS

Nginx was configured to require client certificates during the TLS handshake.

Important config file:

```text
nginx/nginx-mtls.conf
```

Key directives:

```nginx
ssl_client_certificate "C:/Users/kulka/OneDrive/Desktop/cert-based authentication/pki/certs/ca-chain.crt";
ssl_verify_client on;
ssl_verify_depth 2;
```

### 7.1 Meaning of Important Directives

`ssl_client_certificate` tells Nginx which CA certificates it should trust when verifying browser client certificates.

`ssl_verify_client on` forces the client to present a certificate. If the browser does not provide a certificate, Nginx rejects the request before it reaches the backend.

`ssl_verify_depth 2` allows Nginx to verify a certificate chain that includes a client certificate, an intermediate CA, and a root CA.

### 7.2 Server Certificate

Nginx also needs a server certificate for HTTPS. This project generated a localhost server certificate signed by the Intermediate CA.

Important files:

```text
pki/certs/server.crt
pki/certs/server-fullchain.crt
pki/private/server.key
```

The server certificate includes Subject Alternative Names for:

```text
localhost
127.0.0.1
::1
cert-auth.local
```

## 8. Phase 3: Backend Logic

The backend is a Python standard-library application.

Important file:

```text
app/app.py
```

The backend listens on:

```text
127.0.0.1:8081
```

Nginx proxies `/app` to the backend.

### 8.1 Headers Passed by Nginx

Nginx forwards verified certificate information using headers:

```nginx
proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
proxy_set_header X-SSL-Client-Issuer-DN $ssl_client_i_dn;
```

These become HTTP headers available to the backend:

```text
X-SSL-Client-Verify
X-SSL-Client-DN
X-SSL-Client-Issuer-DN
```

### 8.2 Backend Identity Mapping

The backend extracts the Common Name from the subject DN.

Example subject DN:

```text
CN=phase1-client,OU=Phase 1,O=Cert Based Auth Lab,L=Bengaluru,ST=Karnataka,C=IN
```

Extracted CN:

```text
phase1-client
```

The backend then searches SQLite for that CN.

Database file:

```text
app/cert_auth.db
```

User table:

```sql
create table users (
    id integer primary key autoincrement,
    cn text not null unique,
    username text not null,
    display_name text not null,
    role text not null
);
```

Seeded users include:

| CN | Display Name | Purpose |
|---|---|---|
| `phase1-client` | Phase 1 Client | Original valid client |
| `alice-client` | Alice Client | Extra valid demo client |

## 9. Phase 4: Certificate Revocation List

Phase 4 demonstrates how a compromised certificate can be disabled without deleting the certificate file.

The revoked demo certificate is:

```text
revoked-client
```

Important files:

```text
pki/certs/revoked-client.crt
pki/private/revoked-client.key
revoked-client.p12
```

Password:

```text
revokedpass
```

### 9.1 How Revocation Works

Revocation does not modify the certificate itself. The certificate remains the same file. Instead, OpenSSL adds the certificate serial number to a CRL.

Nginx then checks the CRL during mTLS verification. If the client certificate serial number appears in the CRL, Nginx rejects the certificate.

### 9.2 CRL Files

Important CRL files:

```text
pki/crl/intermediate.crl
pki/crl/root.crl
pki/crl/ca-chain.crl
```

The Intermediate CA CRL contains the revoked client certificate.

The Root CA CRL is included because Nginx performs full-chain CRL checking and expects CRL information for the chain.

The combined CRL loaded by Nginx is:

```text
pki/crl/ca-chain.crl
```

Nginx directive:

```nginx
ssl_crl "C:/Users/kulka/OneDrive/Desktop/cert-based authentication/pki/crl/ca-chain.crl";
```

## 10. Phase 5: Testing

Four test scenarios were executed and saved as evidence.

Evidence folder:

```text
evidence/
```

### 10.1 Valid Certificate Test

Certificate:

```text
phase1-client
```

Evidence:

```text
evidence/01-valid-client.txt
```

Result:

```text
HTTP/1.1 200 OK
X-SSL-Client-Verify: SUCCESS
```

The backend mapped the certificate to:

```text
Phase 1 Client
```

### 10.2 Expired Certificate Test

Certificate:

```text
expired-client
```

Evidence:

```text
evidence/02-expired-client.txt
```

Result:

```text
HTTP/1.1 400 Bad Request
X-SSL-Client-Verify: FAILED:certificate has expired
```

This proves Nginx rejects certificates outside their validity period.

### 10.3 Revoked Certificate Test

Certificate:

```text
revoked-client
```

Evidence:

```text
evidence/03-revoked-client.txt
```

Result:

```text
HTTP/1.1 400 Bad Request
X-SSL-Client-Verify: FAILED:certificate revoked
```

This proves Nginx checks the CRL and blocks revoked certificates.

### 10.4 No Certificate Test

Certificate:

```text
none
```

Evidence:

```text
evidence/04-no-client-cert.txt
```

Result:

```text
HTTP/1.1 400 Bad Request
X-SSL-Client-Verify: NONE
No required SSL certificate was sent
```

This proves `ssl_verify_client on` is working.

## 11. Browser Demo Notes

The browser certificate picker only shows certificates installed in the current user certificate store and considered usable by the browser.

Installed demo certificates:

| Certificate | Purpose | Browser Behavior |
|---|---|---|
| `phase1-client` | Valid original client | Should appear and authenticate successfully |
| `alice-client` | Extra valid client | Should appear and authenticate successfully |
| `revoked-client` | Revoked client | May appear, but Nginx rejects it |
| `expired-client` | Expired client | Browser may hide it because it is expired |

This is expected behavior. For the expired certificate case, the OpenSSL evidence file is the best showcase proof because browsers often filter expired client certificates before showing the picker.

## 12. How To Revoke A Client Certificate

Example: revoking `alice-client`.

Step 1: Revoke the certificate with the Intermediate CA database.

```powershell
& "C:\Program Files\Git\usr\bin\openssl.exe" ca -batch `
  -config pki\intermediate-ca-db\intermediate-ca.cnf `
  -revoke pki\certs\alice-client.crt
```

Step 2: Regenerate the Intermediate CA CRL.

```powershell
& "C:\Program Files\Git\usr\bin\openssl.exe" ca -batch `
  -config pki\intermediate-ca-db\intermediate-ca.cnf `
  -gencrl `
  -crlexts crl_ext `
  -out pki\crl\intermediate.crl
```

Step 3: Rebuild the combined CRL file.

```powershell
Get-Content pki\crl\intermediate.crl, pki\crl\root.crl |
  Set-Content pki\crl\ca-chain.crl
```

Step 4: Reload Nginx.

```powershell
.\tools\nginx-1.30.1\nginx.exe `
  -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" `
  -c "nginx\nginx-mtls.conf" `
  -s reload
```

After this, `alice-client` would fail with:

```text
FAILED:certificate revoked
```

## 13. Security Concepts Demonstrated

### 13.1 Public Key Infrastructure

The project shows how a Root CA and Intermediate CA form a certificate chain. The Root CA is trusted by the system or browser. The Intermediate CA issues operational certificates.

### 13.2 Mutual TLS

Normal HTTPS authenticates the server to the client. mTLS authenticates both sides:

- client verifies the server certificate
- server verifies the client certificate

### 13.3 Certificate-Based Identity

The certificate subject contains identity information. This project uses the Common Name as a simple identity key.

### 13.4 Backend Trust Boundary

The backend trusts only Nginx because Nginx is the local gateway that performs TLS verification. The backend should not be directly exposed in this project design.

### 13.5 Revocation

CRL support demonstrates how a certificate can be disabled before its expiry date. This is useful for compromised or retired identities.

## 14. Limitations

This project is intentionally simple. It does not include:

- enterprise-grade certificate lifecycle management
- OCSP
- hardware security modules
- centralized identity providers
- role-based access control beyond a simple SQLite field
- production secret management
- automated certificate renewal
- high availability
- container orchestration

These are outside the scope because the goal is learning and demonstration, not enterprise deployment.

## 15. What To Say In A CV Or Interview

Short CV version:

```text
Built a local certificate-based authentication lab using OpenSSL, Nginx mTLS, Python, and SQLite. Implemented a private CA chain, browser-importable client certificates, Nginx client certificate enforcement, backend CN-to-user mapping, CRL-based revocation, and evidence for valid, expired, revoked, and missing certificate scenarios.
```

Interview explanation:

```text
I built a local mTLS authentication system. OpenSSL creates a Root CA, Intermediate CA, server certificate, and client certificates. Nginx handles the TLS handshake and rejects missing, expired, or revoked certificates. If verification succeeds, Nginx forwards trusted certificate details to a Python backend, which maps the certificate CN to a SQLite user record. I also created test evidence for valid, expired, revoked, and no-certificate cases.
```

## 16. Steps To Run The Project In VS Code

### Step 1: Open The Project Folder

Open VS Code and choose:

```text
File -> Open Folder
```

Select:

```text
C:\Users\kulka\OneDrive\Desktop\cert-based authentication
```

Open a VS Code terminal:

```text
Terminal -> New Terminal
```

Move into the project folder if needed:

```powershell
cd "C:\Users\kulka\OneDrive\Desktop\cert-based authentication"
```

### Step 2: Start The Python Backend

In the first VS Code terminal, run:

```powershell
python app\app.py
```

Expected output:

```text
Backend listening on http://127.0.0.1:8081
```

Keep this terminal open.

### Step 3: Start Nginx

Open a second VS Code terminal and run:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf"
```

If Nginx is already running and you only changed config, reload it:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf" -s reload
```

To stop Nginx:

```powershell
.\tools\nginx-1.30.1\nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf" -s stop
```

### Step 4: Open The Browser Demo

Open:

```text
https://localhost/app
```

When the browser asks for a certificate, choose:

```text
phase1-client
```

or:

```text
alice-client
```

Expected result:

```text
Certificate login successful
```

The page should show the mapped user details.

### Step 5: Show The Nginx Config

In VS Code, open:

```text
nginx/nginx-mtls.conf
```

Show these important lines:

```nginx
ssl_client_certificate ".../pki/certs/ca-chain.crt";
ssl_crl ".../pki/crl/ca-chain.crl";
ssl_verify_client on;
```

Also show the backend proxy headers:

```nginx
proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
proxy_set_header X-SSL-Client-Issuer-DN $ssl_client_i_dn;
```

### Step 6: Show The Backend Code

Open:

```text
app/app.py
```

Explain:

- the backend reads `X-SSL-Client-Verify`
- extracts `CN` from `X-SSL-Client-DN`
- searches SQLite for a matching user
- returns the user details only if the certificate was verified by Nginx

### Step 7: Show The Test Evidence

Open these files:

```text
evidence/01-valid-client.txt
evidence/02-expired-client.txt
evidence/03-revoked-client.txt
evidence/04-no-client-cert.txt
```

Explain:

```text
Valid cert     -> allowed
Expired cert   -> blocked
Revoked cert   -> blocked by CRL
No cert        -> blocked by mTLS
```

### Step 8: Optional Command-Line Retest

Valid cert:

```powershell
$req = "GET /app HTTP/1.1`r`nHost: localhost`r`nAccept: application/json`r`nConnection: close`r`n`r`n"
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\client.crt" -key "pki\private\client.key" -quiet
```

Revoked cert:

```powershell
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\revoked-client.crt" -key "pki\private\revoked-client.key" -quiet
```

Expired cert:

```powershell
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\expired-client.crt" -key "pki\private\expired-client.key" -quiet
```

No cert:

```powershell
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -quiet
```

## 17. Final Conclusion

This project demonstrates the complete local flow of certificate-based authentication:

```text
PKI creation -> mTLS enforcement -> backend identity mapping -> revocation -> testing evidence
```

It is a strong learning project because it shows not only a successful authentication case, but also important failure cases. The valid, expired, revoked, and missing certificate tests prove that the authentication system behaves correctly under different certificate conditions.
