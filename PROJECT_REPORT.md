# Certificate-Based Authentication with Nginx mTLS

## Project Type

This is a self-learning and CV showcase project. It demonstrates the core concepts behind certificate-based authentication using a local PKI, Nginx mutual TLS, certificate revocation, and simple backend identity mapping. It is not intended to be an enterprise deployment.

## Objective

The goal was to build a working local system where:

- A private Root CA and Intermediate CA issue certificates.
- Nginx requires client certificates using mutual TLS.
- The backend receives only verified identity details from Nginx.
- A certificate CN is mapped to a user record.
- Revoked, expired, missing, and valid certificates produce different outcomes.

## Architecture

```text
Browser / OpenSSL client
        |
        | HTTPS with client certificate
        v
Nginx mTLS gateway
        |
        | X-SSL-Client-* headers after verification
        v
Python backend + SQLite user table
```

## Components

### PKI

OpenSSL was used to create:

- Root CA: `ca.crt`
- Intermediate CA: `intermediate.crt`
- Valid client bundle: `client.p12`
- Expired demo client: `expired-client.p12`
- Revoked demo client: `revoked-client.p12`

### Nginx mTLS

Nginx was configured with:

```nginx
ssl_client_certificate ".../pki/certs/ca-chain.crt";
ssl_crl ".../pki/crl/ca-chain.crl";
ssl_verify_client on;
ssl_verify_depth 2;
```

This forces clients to present a trusted, valid, non-revoked certificate before reaching the backend.

### Backend

The backend is a small Python standard-library app using SQLite. It reads these Nginx headers:

```text
X-SSL-Client-Verify
X-SSL-Client-DN
X-SSL-Client-Issuer-DN
```

It extracts the CN from the subject DN and maps `phase1-client` to a local user record.

## Test Results

| Test Case | Result |
|---|---|
| Valid certificate | Accepted, mapped to `Phase 1 Client` |
| Expired certificate | Rejected with `FAILED:certificate has expired` |
| Revoked certificate | Rejected with `FAILED:certificate revoked` |
| No certificate | Rejected with `No required SSL certificate was sent` |

Detailed evidence is saved in `PHASE5_TESTING_AND_REPORT.md` and the `evidence/` folder.

## What I Learned

- How a Root CA and Intermediate CA chain works.
- How browser-importable `.p12` client certificates are built.
- How Nginx enforces mTLS during the TLS handshake.
- Why the backend should not perform cryptographic certificate validation itself when Nginx is already doing it.
- How CRLs can disable compromised certificates.
- How to design repeatable test cases for authentication behavior.

## CV Description

Built a local certificate-based authentication lab using OpenSSL, Nginx mTLS, Python, and SQLite. Implemented a private CA chain, browser-importable client certificates, Nginx client certificate enforcement, backend CN-to-user mapping, CRL-based revocation, and test evidence for valid, expired, revoked, and missing certificate scenarios.
