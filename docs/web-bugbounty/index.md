---
title: "Bug Bounty"
description: "A complete, reader-first bug bounty methodology from program rules and reconnaissance through validation, reporting and retesting."
tags:
  - Bug Bounty
  - Web
  - OWASP
  - Methodology
---

# Bug bounty methodology

A good bug bounty workflow is not a race to send the most payloads. It is a repeatable loop: understand the program rules, map the target, form a testable hypothesis, change one trust assumption at a time, prove the smallest safe impact, and report it clearly.

!!! note "The goal of each step"
    Every phase should produce something useful for the next phase. Scope produces a target list, discovery produces an attack-surface map, testing produces observations, validation produces evidence, and reporting turns the evidence into a fixable finding.

!!! warning "Stay inside the program"
    Test only assets, accounts and actions allowed by the program. Respect rate limits, exclusions, automation rules and disclosure requirements. Use test accounts and stop when the impact is clear; do not access unrelated user data or create unnecessary load.

## The complete workflow at a glance

| Phase | Question | Useful output |
| :--- | :--- | :--- |
| **1. Read the rules** | What may be tested, how, and during which window? | Saved scope, exclusions, contacts, rate limits and evidence location |
| **2. Discover assets** | What approved domains, applications, APIs, mobile clients and third-party services exist? | Normalized asset list with source and confidence |
| **3. Map the application** | Which routes, roles, objects, states and integrations are reachable? | Anonymous/authenticated sitemap and request inventory |
| **4. Establish identities** | How do login, registration, reset, MFA, SSO and sessions create trust? | Account matrix and session/token lifecycle notes |
| **5. Test boundaries** | Does the server enforce identity, authorization, validation and business rules? | Reproducible observations with request/response comparisons |
| **6. Validate impact** | What is the smallest safe proof of the security consequence? | Redacted evidence, affected boundary and business impact |
| **7. Report** | Can another person reproduce and fix the issue? | Clear report with steps, impact, severity and remediation |
| **8. Retest and close** | Did the fix remove the root cause without introducing a new path? | Retest result, final evidence and status |

## 1. Read the program rules first

Before touching a target, record the program name, in-scope assets, out-of-scope assets, testing window, allowed automation, request limits, prohibited actions, account requirements and disclosure process.

A hostname that looks related is not automatically in scope. A third-party service, a staging system or an acquired brand may require separate permission. Keep the program rules with the notes so an interesting lead cannot silently become an unauthorized test.

### Prepare the test workspace

Create separate locations for raw observations, normalized lists, requests, screenshots and report evidence. Use dedicated test accounts and unique harmless markers so results can be tied to your activity without touching real customer data.

## 2. Discover and prioritize the attack surface

Start with the assets the program has approved, then use low-noise sources to understand their relationships. Look for domains, subdomains, virtual hosts, API hosts, mobile endpoints, documentation, JavaScript routes, cloud storage and third-party integrations.

The result should not be the largest possible list. It should be a trustworthy map with:

- Asset name, URL, IP or provider.
- Source and time first observed.
- Whether ownership and program scope are confirmed.
- Service, technology, version and authentication state.
- Interesting routes, parameters, files, roles or integrations.
- A confidence level and a clear next action.

Prioritize assets that expose valuable functionality, unusual trust boundaries, forgotten versions, administrative workflows or sensitive integrations. Do not treat a scanner result as a finding until it is manually understood.

## 3. Map the application before testing it

Capture anonymous and authenticated traffic separately. Browse the application normally before trying to break a control. Record:

- Routes, methods, parameters and content types.
- Objects such as users, orders, files, projects and messages.
- Roles, tenants and account states.
- Login, registration, reset, MFA and logout transitions.
- Server-side integrations, webhooks, imports and exports.
- Client-side routes and API calls found in JavaScript.

The application map gives you a baseline. Without it, a different response is easy to mistake for a vulnerability when it may only be a normal state transition or an invalid request.

## 4. Build an identity and authorization matrix

Where the program permits it, use dedicated accounts with different roles or tenants. Record which account owns each test object and what each account should be allowed to do.

A simple matrix can compare:

| Test dimension | Comparison |
| :--- | :--- |
| Identity | Anonymous versus authenticated |
| Role | Low privilege versus administrative test role |
| Tenant | Tenant A versus Tenant B |
| Object | Owner versus non-owner |
| State | Before versus after an action |
| Method | Expected HTTP method versus an alternate method |

Authentication answers **who the caller is**. Authorization answers **what that caller may do**. Test both separately: a correctly authenticated user can still be allowed to read or change another user's object.

## 5. Test the highest-value boundaries

Change one assumption at a time and compare the trusted and untrusted result. Useful test areas include:

### Authentication and account recovery

Review login, registration, password reset, MFA, SSO, session invalidation, remember-me behavior and account changes. Look for weak protection, inconsistent identity checks and flows that trust client-controlled state.

See [Authentication and account takeover](auth-ato-oauth-jwt.md) for the detailed page.

### Authorization and object ownership

For reads, creates, updates, deletes, exports and bulk actions, verify the server checks the current subject, object and tenant. A successful status code is only a lead; prove that unauthorized data or a state change is actually possible.

See [Access control, IDOR and race conditions](access-control-idor-race.md).

### Input handling and injection

Trace untrusted input into its interpreter or output context. Consider SQL/NoSQL, template, XML, command and other parser boundaries. Prove the impact with the smallest safe marker or controlled result.

See [Injections](injection-attacks.md).

### Browser controls and client-side behavior

Review output contexts, DOM sinks, cookies, CSP, CORS, CSRF and `postMessage` origin checks. The browser is part of the security boundary, but server-side authorization must not depend on the interface hiding an action.

See [XSS, DOM and CSP](xss-csp-client-side.md) and [SSRF, CORS, CSRF and smuggling](ssrf-cors-csrf-smuggling.md).

### APIs, GraphQL, WebSockets and uploads

Inventory API operations and object types, then compare permissions across roles and tenants. Review GraphQL fields, WebSocket messages, upload parsing, file storage, URL fetches and webhook behavior.

See [APIs, GraphQL and file uploads](api-graphql-modern-web.md).

### Business logic and state transitions

Ask whether a user can skip, repeat, reorder or combine steps to reach an outcome the product should reject. Record the state before the action, the exact transition and the resulting side effect.

## 6. Capture a safe baseline and validate the difference

A baseline request records normal behavior before an identity, object or state is changed. Keep the request, response, timestamp and test account together.

```bash
# Save a baseline response for an object owned by the current test account.
# Use a test token and a target explicitly listed in the program scope.
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

Then repeat with a permitted comparison account and an object it does not own. Compare status, body, sensitive fields, timing, side effects, audit events and follow-up access. A different response is a lead; the security finding is the broken boundary and its impact.

## 7. Decide whether an observation is reportable

| Observation | What is still needed |
| :--- | :--- |
| A parameter is reflected | Show executable impact in its actual context, or explain why it is a meaningful unsafe sink. |
| An endpoint returns `200` | Show unauthorized data or an unauthorized state change. |
| A header is accepted | Show that it changes routing, authorization, cache behavior or a reset link in a harmful way. |
| A scanner flags SQLi or SSRF | Reproduce manually and prove the data access, callback or controlled side effect. |
| A rate limit seems weak | Use approved test values, define the window and show the consequence without causing lockout or load. |
| A control blocks the test | Record the prevention or detection result instead of escalating without a new hypothesis. |

Stop once the impact is unambiguous. More requests do not make a clear finding stronger and may increase risk or expose unnecessary data.

## 8. Write a useful report

A strong bug bounty report lets the triager reproduce the issue without guessing. Include:

1. **Title:** affected feature, weakness and consequence.
2. **Summary:** what trust boundary is broken.
3. **Prerequisites:** account role, tenant, object and any setup.
4. **Steps:** numbered requests or UI actions with sensitive values redacted.
5. **Expected result:** what the server should have enforced.
6. **Observed result:** what actually happened.
7. **Impact:** data exposure, account access, privilege change or business consequence.
8. **Evidence:** minimal requests, responses, screenshots or controlled markers.
9. **Remediation:** the server-side control that should be fixed.
10. **Retest notes:** what changed and how the fix was verified.

Avoid inflated impact claims. Explain the highest consequence you demonstrated, separate it from possible follow-on impact, and keep the proof within the program's rules.

## 9. Retest, clean up and close

After a fix, repeat the original steps from a clean session and confirm the root cause is addressed. Check both the original path and nearby methods, roles or tenants for regressions.

Remove test objects, files, accounts, tokens, webhooks and markers that the program expects you to clean up. Record what was removed, what could not be removed and who was notified. Close the evidence set with the final status and date.

## Pages in this section

- **[Authentication and account takeover](auth-ato-oauth-jwt.md)** — Login, reset, MFA, OAuth/OIDC, sessions and JWT trust decisions.
- **[Access control, IDOR and race conditions](access-control-idor-race.md)** — Object ownership, tenant isolation, forced browsing, method confusion, concurrency and business logic.
- **[Injections](injection-attacks.md)** — SQL/NoSQL, template, XML and command interpreters, with context and impact validation.
- **[XSS, DOM and CSP](xss-csp-client-side.md)** — Output contexts, stored/blind XSS, DOM sinks, `postMessage`, prototype pollution and policy review.
- **[SSRF, CORS, CSRF and smuggling](ssrf-cors-csrf-smuggling.md)** — Server-side network access, browser cross-origin controls and proxy parsing differences.
- **[APIs, GraphQL and file uploads](api-graphql-modern-web.md)** — Inventory, BOLA/BOPLA, GraphQL, WebSockets, upload processing and object storage.

The [bug bounty checklist](../checklists-arsenal/web-bugbounty-checklist.md) is the coverage tracker; these pages are the reasoning and reproduction notes behind each item.
