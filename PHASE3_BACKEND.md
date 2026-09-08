# Phase 3 - Backend Logic

Nginx performs the cryptographic mTLS verification. The backend only reads the trusted headers sent by Nginx and maps the certificate common name to a user in SQLite.

## Backend

- App: `app/app.py`
- Database: `app/cert_auth.db`
- Listen address: `127.0.0.1:8081`
- Seeded user CN: `phase1-client`

## Nginx headers passed to backend

```nginx
proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
proxy_set_header X-SSL-Client-Issuer-DN $ssl_client_i_dn;
```

## Start backend

```powershell
python app\app.py
```

## Test through Nginx

Open:

```text
https://localhost/app
```

Expected result: the backend page shows `Certificate login successful` and maps `CN=phase1-client` to `Phase 1 Client`.

JSON test:

```powershell
curl.exe -k --cert "pki\certs\client.crt" --key "pki\private\client.key" https://localhost/app -H "Accept: application/json"
```
