# Phase 3 Test Results

Date: 2026-05-22

## Backend direct mapping test

Request: direct HTTP request to `127.0.0.1:8081/app` with trusted Nginx-style headers.

Result: accepted and mapped `CN=phase1-client` to the seeded SQLite user.

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
  },
  "ssl_client_verify": "SUCCESS"
}
```

## Nginx without client certificate

Request: `https://localhost/app` without a client certificate.

Result: rejected before reaching the backend.

```text
HTTP/1.1 400 Bad Request
No required SSL certificate was sent
```

## Nginx with valid client certificate

Request: `https://localhost/app` with `pki/certs/client.crt` and `pki/private/client.key`.

Result: accepted by Nginx and mapped by backend.

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
  },
  "ssl_client_verify": "SUCCESS",
  "ssl_client_s_dn": "CN=phase1-client,OU=Phase 1,O=Cert Based Auth Lab,L=Bengaluru,ST=Karnataka,C=IN",
  "ssl_client_i_dn": "CN=Cert Based Auth Intermediate CA,OU=Phase 1,O=Cert Based Auth Lab,L=Bengaluru,ST=Karnataka,C=IN"
}
```
