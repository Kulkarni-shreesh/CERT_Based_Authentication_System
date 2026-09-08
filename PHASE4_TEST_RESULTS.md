# Phase 4 Test Results

Date: 2026-05-22

## CRL contents

The intermediate CA CRL contains the revoked demo certificate serial:

```text
Issuer: C=IN, ST=Karnataka, L=Bengaluru, O=Cert Based Auth Lab, OU=Phase 1, CN=Cert Based Auth Intermediate CA
Serial Number: 3000
Revocation Date: May 22 18:02:10 2026 GMT
```

Nginx loads the combined CRL file:

```nginx
ssl_crl "C:/Users/kulka/OneDrive/Desktop/cert-based authentication/pki/crl/ca-chain.crl";
```

## Valid certificate test

Certificate: `phase1-client`

Result: accepted.

```text
HTTP/1.1 200 OK
X-SSL-Client-Verify: SUCCESS
```

Backend mapping:

```json
{
  "authenticated": true,
  "cn": "phase1-client",
  "user": {
    "id": 1,
    "cn": "phase1-client",
    "username": "phase1_client",
    "display_name": "Phase 1 Client",
    "role": "student"
  }
}
```

## Revoked certificate test

Certificate: `revoked-client`

Result: rejected by Nginx during client certificate verification.

```text
HTTP/1.1 400 Bad Request
X-SSL-Client-Verify: FAILED:certificate revoked
```
