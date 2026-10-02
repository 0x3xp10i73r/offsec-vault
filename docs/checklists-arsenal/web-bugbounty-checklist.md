---
title: "Web & Bug Bounty Pentesting Checklist"
description: "Interactive web application penetration testing checklist covering recon, auth, authorization, injection, logic, and client-side testing"
tags:
  - Checklists
  - Web
  - Bug Bounty
  - Methodology
---

# Web & Bug Bounty Pentesting Checklist

!!! tip "How to Use"
    Tick items as you go — progress is saved in your browser. Use `/` to search for a specific technique, and pair this checklist with the deep-dive playbooks in the **Web & Bug Bounty** section.

---

## 1. Reconnaissance & Mapping

- [ ] Enumerate subdomains (passive + active) and resolve live hosts
- [ ] Probe ports & services; identify all web-facing services
- [ ] Fingerprint technology stack (frameworks, servers, CDN, WAF)
- [ ] Discover directories, files, and backups (ffuf / feroxbuster)
- [ ] Fuzz Virtual Hosts for internal dashboards
- [ ] Crawl the application with an authenticated session (Katana / Burp Spider)
- [ ] Extract endpoints & secrets from JavaScript bundles and source maps
- [ ] Check for exposed `.git`, `.svn`, `.env`, `actuator`, `swagger`, `phpinfo`
- [ ] Enumerate API versions (v1/v2/beta/internal/mobile) and compare authz
- [ ] Test for subdomain takeover on dangling CNAMEs
- [ ] Review the mobile app for hidden API endpoints (APK/IPA strings)
- [ ] Identify all third-party integrations (S3, Firebase, Stripe, analytics, SSO)

## 2. Authentication

- [ ] Test username/email enumeration on login, register, and reset endpoints
- [ ] Test password policy & brute-force protection (account lockout, rate limits)
- [ ] Test default credentials on all admin/management interfaces
- [ ] Test password reset: host header poisoning, token leakage, token reuse, weak tokens
- [ ] Test pre-account takeover via unverified email + SSO linking
- [ ] Test email/MFA change flows for missing re-authentication
- [ ] Test session fixation, session invalidation on logout/password change
- [ ] Test remember-me and long-lived token behavior after revocation
- [ ] Test JWT: alg=none, key confusion, weak secret, kid/jku injection, claim tampering
- [ ] Test OAuth: redirect_uri bypass, state CSRF, code leak, PKCE downgrade
- [ ] Test 2FA/OTP bypass: response manipulation, brute force, reuse, missing enforcement
- [ ] Test API keys: scope, expiry, rotation, leakage in logs/URLs/JS

## 3. Authorization & Access Control

- [ ] Enumerate all object identifiers (numeric, UUID, base64, hashed, slugs)
- [ ] Test IDOR/BOLA horizontally (same role, different user) and vertically (lower → higher role)
- [ ] Test IDOR on every HTTP method (GET/POST/PUT/PATCH/DELETE)
- [ ] Test multi-tenant boundaries (X-Org-Id, tenant params, org switching)
- [ ] Test forced browsing to admin/privileged functionality
- [ ] Test 403/401 bypasses: path obfuscation, header spoofing, method tampering
- [ ] Test mass assignment on create/update endpoints (role, is_admin, verified, balance)
- [ ] Test GraphQL: introspection, node() IDOR, field suggestions, hidden mutations
- [ ] Test authorization on exports, reports, PDFs, and bulk endpoints
- [ ] Test that server-side validation matches client-side hidden/disabled controls
- [ ] Test file/attachment access is scoped to the owner's tenant

## 4. Injection & Input Validation

- [ ] SQLi: boolean, error, time-based, and out-of-band on all parameters
- [ ] NoSQLi: `$ne`, `$gt`, `$regex`, `$where` in JSON and query params
- [ ] SSTI: polyglot detection on all reflected/templated fields and email/PDF generators
- [ ] XXE: XML endpoints, SVGs, DOCX/XLSX uploads, SSO/SAML responses
- [ ] OS command injection (incl. argument injection and blind time-based)
- [ ] LDAP / XPath / IMAP / SMTP header injection
- [ ] CRLF injection leading to response splitting, header injection, cache poisoning
- [ ] Log injection / log forging (rendered in admin panels → blind XSS)
- [ ] Deserialization endpoints (Java/PHP/.NET/Python) and gadget chains
- [ ] Server-side JavaScript / expression injection in rules/automation features

## 5. SSRF, CORS, CSRF & Request Smuggling

- [ ] SSRF on URL/webhook/import/render parameters (in-band + blind via Collaborator)
- [ ] SSRF filter bypasses (IP encoding, redirects, DNS rebinding, IPv6)
- [ ] Cloud metadata access (AWS IMDSv1/v2, GCP, Azure, DigitalOcean)
- [ ] CORS: reflected origin with credentials, null origin, regex bypass, subdomain trust
- [ ] CSRF: token presence/validation, SameSite behavior, method override, JSON CSRF
- [ ] HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2.CL/H2.TE) if a front-end proxy exists
- [ ] Web cache poisoning / deception (unkeyed headers, unkeyed query params)
- [ ] Open redirect (all params) — and chain it into OAuth/SSRF/CSRF
- [ ] Host header injection (password reset, cache, routing, absolute URLs)

## 6. Business Logic & Race Conditions

- [ ] Test negative/zero/huge quantities and amounts (price manipulation)
- [ ] Test multi-step flows: skip steps, replay steps, reorder steps
- [ ] Test coupon/gift-card/referral abuse and stacking
- [ ] Test trial/subscription abuse (re-register, change email, cancel race)
- [ ] Test limit overrun with the HTTP/2 single-packet attack (coupons, withdrawals, votes)
- [ ] Test OTP/quota/attempt counters under parallel requests
- [ ] Test refund, transfer, and cancellation logic for state confusion
- [ ] Test currency/rounding/decimal precision handling
- [ ] Test role/plan upgrade downgrade paths for privilege retention
- [ ] Test "invite" flows for seat-limit and role-escalation bypasses

## 7. Client-Side & Browser

- [ ] Reflected XSS in every reflection context (HTML, attribute, JS, URL)
- [ ] Stored XSS in all persisted fields (including admin-only views)
- [ ] Blind XSS in support tickets, user-agent, referer, filenames, EXIF
- [ ] DOM XSS: `innerHTML`, `eval`, `document.write`, `location` sinks
- [ ] DOM Clobbering and client-side prototype pollution
- [ ] postMessage: missing origin checks, sensitive data leakage, wildcard targetOrigin
- [ ] CSP analysis and bypass (JSONP, whitelisted CDN gadgets, base-uri, nonce reuse)
- [ ] Clickjacking (X-Frame-Options / CSP frame-ancestors missing + sensitive actions)
- [ ] Tabnabbing (`target="_blank"` without `rel="noopener"`) on sensitive flows
- [ ] Reverse tabnabbing on password reset / OAuth pages (Referer token leak)
- [ ] Clipboard / pastejacking and drag-and-drop injection issues

## 8. Files, Uploads & Downloads

- [ ] Extension & content-type bypass on upload (`.php.jpg`, `%00`, double extension)
- [ ] SVG/HTML upload → stored XSS on the app or a CDN domain
- [ ] XXE via DOCX/XLSX/SVG/PDF upload
- [ ] Path traversal in filename handling and download endpoints
- [ ] Zip Slip / archive extraction path traversal
- [ ] Image processing abuse (ImageTragick, Ghostscript, DoS via large images)
- [ ] SSRF via remote file import / "import from URL"
- [ ] Filename reflected in response headers (header injection, CRLF)
- [ ] Access control on uploaded file URLs (guessable vs. signed URLs)

## 9. APIs & Infrastructure

- [ ] Enumerate all API endpoints and HTTP methods (OPTIONS)
- [ ] Test rate limiting per endpoint, per token, and per IP (and bypass via headers/rotation)
- [ ] Test pagination limits and unbounded resource consumption
- [ ] Test error handling for verbose stack traces / internal paths
- [ ] Test HTTP security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy)
- [ ] Test TLS configuration (weak ciphers, certificate issues, old protocols)
- [ ] Test debug/health/metrics endpoints for internal data exposure
- [ ] Test WebSocket handshake for origin validation and message-level authz
- [ ] Test GraphQL batching/aliasing for rate-limit and 2FA brute-force bypass
- [ ] Test cookie flags (Secure, HttpOnly, SameSite) on all sessions
- [ ] Test for account enumeration differences (timing, response length, status codes)

## 10. Reporting & Wrap-Up

- [ ] Every finding has a reproducible PoC (raw request/response or exact steps)
- [ ] Impact is expressed in business terms (data, money, users, compliance)
- [ ] Severity is justified with CVSS + a real-world attack scenario
- [ ] Remediation is specific and actionable (code-level where possible)
- [ ] Test data created during the engagement is cleaned up or reported
- [ ] Screenshots/evidence are timestamped and stored in the report folder
- [ ] A summary of coverage (what was tested and what was NOT) is included