# Phase 5 - Testing and Report

## Test Summary

All tests were run against:

```text
https://localhost/app
```

Nginx performs mTLS verification first. Only after a successful client certificate check does the request reach the Python backend.

| Scenario | Certificate Used | Expected Result | Actual Result | Evidence |
|---|---|---|---|---|
| Valid cert | `phase1-client` | Access allowed | `HTTP/1.1 200 OK`, `X-SSL-Client-Verify: SUCCESS` | `evidence/01-valid-client.txt` |
| Expired cert | `expired-client` | Access denied | `HTTP/1.1 400 Bad Request`, `FAILED:certificate has expired` | `evidence/02-expired-client.txt` |
| Revoked cert | `revoked-client` | Access denied | `HTTP/1.1 400 Bad Request`, `FAILED:certificate revoked` | `evidence/03-revoked-client.txt` |
| No cert | none | Access denied | `HTTP/1.1 400 Bad Request`, `X-SSL-Client-Verify: NONE` | `evidence/04-no-client-cert.txt` |

## Evidence Files

- `evidence/01-valid-client.txt`
- `evidence/02-expired-client.txt`
- `evidence/03-revoked-client.txt`
- `evidence/04-no-client-cert.txt`
- `evidence/mtls-access.log`
- `evidence/mtls-error.log`

## Client Certificate Bundle Passwords

```text
client.p12          -> clientpass
expired-client.p12  -> expiredpass
revoked-client.p12  -> revokedpass
```

## Main Commands Used

Valid certificate:

```powershell
$req = "GET /app HTTP/1.1`r`nHost: localhost`r`nAccept: application/json`r`nConnection: close`r`n`r`n"
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\client.crt" -key "pki\private\client.key" -quiet
```

Expired certificate:

```powershell
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\expired-client.crt" -key "pki\private\expired-client.key" -quiet
```

Revoked certificate:

```powershell
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\revoked-client.crt" -key "pki\private\revoked-client.key" -quiet
```

No certificate:

```powershell
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -quiet
```
