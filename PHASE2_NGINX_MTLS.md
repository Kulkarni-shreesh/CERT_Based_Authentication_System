# Phase 2 - Nginx mTLS

This phase makes Nginx require a browser client certificate with:

```nginx
ssl_verify_client on;
```

## Files

- `nginx/nginx-mtls.conf` - Nginx config for HTTPS + required client certificates
- `nginx/mime.types` - minimal MIME type file used by the standalone config
- `pki/certs/server.crt` - localhost server certificate signed by the intermediate CA
- `pki/private/server.key` - localhost server private key
- `pki/certs/server-fullchain.crt` - server certificate plus intermediate CA
- `pki/certs/ca-chain.crt` - intermediate plus root CA used to verify browser client certificates
- `www/index.html` - protected test page
- `logs/` - Nginx mTLS access and error logs

## Browser setup

1. Import `ca.crt` as a trusted certificate authority.
2. Import `client.p12` as your personal/client certificate.
3. Password for `client.p12`: `clientpass`

## Start Nginx on Windows

If you install the official Windows Nginx zip, start it with this project as the prefix:

```powershell
nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf"
```

Then browse to:

```text
https://localhost/
https://localhost/mtls-debug
```

## Required Phase 2 test

Without `client.p12` installed, the browser should be rejected during TLS/client certificate authentication.
With `client.p12` installed, the browser should show the protected page.

You can also test from OpenSSL after Nginx is running:

```powershell
# Expected to fail because no client certificate is sent
& "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt"

# Expected to succeed with Verify return code: 0 (ok)
& "C:\Program Files\Git\usr\bin\openssl.exe" s_client -connect localhost:443 -CAfile "pki\certs\ca.crt" -cert "pki\certs\client.crt" -key "pki\private\client.key"
```

## Stop or reload Nginx

```powershell
nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf" -s reload
nginx.exe -p "C:\Users\kulka\OneDrive\Desktop\cert-based authentication" -c "nginx\nginx-mtls.conf" -s stop
```
