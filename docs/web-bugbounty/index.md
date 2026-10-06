---
title: "Web and Bug Bounty"
description: "A reader-first methodology for testing authentication, authorization, input handling, browser controls, APIs and business logic."
tags:
  - Bug Bounty
  - Web
  - OWASP
  - Methodology
---

# Web application testing and bug bounty

Web testing is the process of asking whether the server enforces the same security boundary that the user interface suggests. The pages here are organized by control, not by a list of payloads: map the application, identify identities and objects, change one assumption at a time, and prove the impact with the smallest safe request.

!!! note "What we are doing"
    We are not trying random strings until a response looks unusual. We are comparing trusted and untrusted states: two accounts, two tenants, two object IDs, two request methods, or the same action before and after a state change. The difference is the evidence.

## The web testing model

| Layer | Question | Typical evidence |
| :--- | :--- | :--- |
| **Surface** | What routes, methods, parameters, files, integrations and versions exist? | Sitemap, API schema, JavaScript routes, raw requests |
| **Identity** | Who is the caller and how is a session, token or recovery flow established? | Cookie/token lifecycle, login/reset/MFA behavior |
| **Authorization** | Is this caller allowed to perform this action on this object in this tenant? | A/B account comparison, status/body/side-effect diff |
| **Input handling** | Does untrusted data stay data in every interpreter and output context? | Context-aware reflection, validation and encoding result |
| **Browser boundary** | Does the browser enforce origin, cookie, framing and script policy correctly? | Headers, DOM sink, `postMessage` origin and cookie behavior |
| **Business state** | Can a user skip, repeat, reorder or combine steps to get an invalid outcome? | State transition trace, balance/limit/role before and after |
| **Operations** | Are logs, errors, rate limits and integrations safe under abuse? | Error response, throttling behavior, audit trail, webhook behavior |

## Pages in this section

- **[Authentication and account takeover](auth-ato-oauth-jwt.md)** — Login, reset, MFA, OAuth/OIDC, sessions and JWT trust decisions.
- **[Access control, IDOR and race conditions](access-control-idor-race.md)** — Object ownership, tenant isolation, forced browsing, method confusion, concurrency and business logic.
- **[Injections](injection-attacks.md)** — SQL/NoSQL, template, XML and command interpreters, with context and impact validation.
- **[XSS, DOM and CSP](xss-csp-client-side.md)** — Output contexts, stored/blind XSS, DOM sinks, `postMessage`, prototype pollution and policy review.
- **[SSRF, CORS, CSRF and smuggling](ssrf-cors-csrf-smuggling.md)** — Server-side network access, browser cross-origin controls and proxy parsing differences.
- **[APIs, GraphQL and file uploads](api-graphql-modern-web.md)** — Inventory, BOLA/BOPLA, GraphQL, WebSockets, upload processing and object storage.

## How to triage a new target

### 1. Build the map before testing payloads

Capture anonymous and authenticated traffic separately. Note the account, tenant, role, object IDs and state transition for each important function. The same endpoint may be safe for one role and broken for another.

### 2. Establish paired identities

Use at least two dedicated test accounts where the program permits it: one low-privilege account in tenant A and one account in tenant B or with a different role. Never use a real user's object as the first proof when a test object can answer the question.

### 3. Test high-value boundaries in order

1. Login, registration, reset, MFA, SSO and session invalidation.
2. Tenant and object authorization on read, create, update, delete, export and bulk endpoints.
3. Roles, invitations, billing, quotas and state transitions.
4. File, URL, webhook, import and rendering features.
5. Client-side sinks and browser policy.
6. Rate limits, error handling, old versions and operational endpoints.

### 4. Compare, then confirm

A different status code is a lead, not proof. Compare the response body, sensitive fields, timing, side effects, audit event and follow-up access. Re-run from a clean session, and stop once the impact is unambiguous.

## A small, safe baseline example

The point of a baseline request is to capture what the application normally returns before changing the object or identity. Keep the command, raw response and timestamp together.

```bash
# Save a baseline response for an object owned by the current test account.
# Use a test token and a target explicitly listed in the engagement scope.
curl --silent --show-error \
  --header "Authorization: Bearer <TEST_TOKEN>" \
  "https://<DOMAIN>/api/v1/items/<YOUR_OBJECT_ID>" \
  --output "evidence/<TARGET_NAME>/baseline-item.json"

# Record the status separately so the body can be redacted without losing it.
curl --silent --output /dev/null --write-out '%{http_code}\n' \
  --header "Authorization: Bearer <TEST_TOKEN>" \
  "https://<DOMAIN>/api/v1/items/<YOUR_OBJECT_ID>" \
  > "evidence/<TARGET_NAME>/baseline-status.txt"
```

Then repeat with the second test account and an object it does not own. The secure result may be `403`, `404`, or a response that intentionally reveals no ownership information. Explain why the observed result is or is not a broken boundary.

## Findings versus interesting behavior

| Observation | What is still needed before reporting |
| :--- | :--- |
| A parameter is reflected | Show executable impact in its actual context, or explain why it is a meaningful unsafe sink. |
| An endpoint returns `200` | Show unauthorized data or an unauthorized state change. |
| A header is accepted | Show that it changes routing, authorization, cache behavior or a reset link in a harmful way. |
| A scanner flags SQLi/SSRF | Reproduce manually and prove the data access, callback or controlled side effect. |
| A rate limit seems weak | Use approved test values, define the window, and show the business consequence without causing lockout or load. |

## Reporting and remediation mindset

Write the server-side control that is missing, not only the payload that triggered it. For example:

- **Access control:** authorize the subject, object and tenant on every server-side operation; never rely on hidden fields or client checks.
- **Authentication:** bind reset and OAuth state to a session, use single-use expiring tokens, require re-authentication for sensitive changes, and validate issuer/audience/PKCE.
- **Input/output:** use parameterized queries, safe template APIs, allow-lists, context-aware output encoding and isolated parsers.
- **Browser boundary:** set secure cookie flags, deliberate CORS origins, CSRF defenses, CSP and strict `postMessage` origin checks.
- **Operations:** enforce rate limits per meaningful identity, bound resource use, log security decisions and remove debug interfaces from production.

The [web checklist](../checklists-arsenal/web-bugbounty-checklist.md) is the coverage tracker; these pages are the reasoning and reproduction notes behind each item.
