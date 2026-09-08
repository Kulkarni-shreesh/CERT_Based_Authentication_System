# Phase 4 - Certificate Revocation List

This phase demonstrates disabling a compromised certificate with a CRL.

## Files

- `pki/certs/revoked-client.crt` - demo client certificate that has been revoked
- `pki/private/revoked-client.key` - private key for the revoked demo certificate
- `revoked-client.p12` - browser-importable revoked demo certificate
- `pki/crl/intermediate.crl` - CRL issued by the intermediate CA
- `pki/crl/root.crl` - empty CRL issued by the root CA for full-chain CRL checking
- `pki/crl/ca-chain.crl` - combined CRL file loaded by Nginx
- `pki/intermediate-ca-db/` - OpenSSL CA database used for revocation tracking

Password for `revoked-client.p12`:

```text
revokedpass
```

## Nginx directive

```nginx
ssl_crl "C:/Users/kulka/OneDrive/Desktop/cert-based authentication/pki/crl/ca-chain.crl";
```

## Demo behavior

- `phase1-client` remains valid and can access `/app`.
- `revoked-client` chains to the same CA, but Nginx rejects it because its serial number appears in the CRL.

## Useful OpenSSL commands

Inspect the CRL:

```powershell
& "C:\Program Files\Git\usr\bin\openssl.exe" crl -in "pki\crl\intermediate.crl" -noout -text
```

Test valid certificate:

```powershell
$req = "GET /app HTTP/1.1`r`nHost: localhost`r`nAccept: application/json`r`nConnection: close`r`n`r`n"
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\client.crt" -key "pki\private\client.key" -quiet
```

Test revoked certificate:

```powershell
$req = "GET /app HTTP/1.1`r`nHost: localhost`r`nAccept: application/json`r`nConnection: close`r`n`r`n"
$req | & "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\revoked-client.crt" -key "pki\private\revoked-client.key" -quiet
```
