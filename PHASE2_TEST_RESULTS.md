# Phase 2 Test Results

Date: 2026-05-22
Nginx: 1.30.1 Windows stable from nginx.org
URL: https://localhost/
Debug URL: https://localhost/mtls-debug

## Result 1 - No client certificate

Expected: rejected by Nginx because ssl_verify_client is on.
Actual: rejected.

`	ext
HTTP/1.1 400 Bad Request
X-SSL-Client-Verify: NONE

No required SSL certificate was sent
`

## Result 2 - Valid client certificate

Expected: accepted by Nginx with ssl_client_verify=SUCCESS.
Actual: accepted.

`	ext
HTTP/1.1 200 OK
X-SSL-Client-Verify: SUCCESS
X-SSL-Client-DN: CN=phase1-client,OU=Phase 1,O=Cert Based Auth Lab,L=Bengaluru,ST=Karnataka,C=IN

ssl_client_verify=SUCCESS
ssl_client_s_dn=CN=phase1-client,OU=Phase 1,O=Cert Based Auth Lab,L=Bengaluru,ST=Karnataka,C=IN
ssl_client_i_dn=CN=Cert Based Auth Intermediate CA,OU=Phase 1,O=Cert Based Auth Lab,L=Bengaluru,ST=Karnataka,C=IN
`

## Browser certificate setup

The current Windows user certificate stores were configured with:

`powershell
certutil -user -addstore Root ca.crt
certutil -user -p clientpass -importPFX My client.p12 NoRoot
`

The default browser was opened to:

`	ext
https://localhost/mtls-debug
`

If prompted, choose the phase1-client certificate.
