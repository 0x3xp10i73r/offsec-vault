---
title: "Web and Bug Bounty"
description: "Step-by-step methodologies, payloads, and bypasses for modern web application penetration testing and bug bounty hunting"
tags:
  - Bug Bounty
  - Web
  - OWASP
  - HowToHunt
---

# Web application testing and bug bounty

Guides and cheatsheets for web application testing, grouped by vulnerability class. Each page follows the same shape: how to find it, how to confirm it, how to exploit it, and what the fix looks like.

---

## Pages in this section

  - **[Auth, ATO, OAuth 2.0 & JWT](auth-ato-oauth-jwt.md)** — Zero-click & one-click Account Takeover (ATO), Password Reset poisoning, 2FA/OTP bypasses, OAuth redirect_uri/state flaws, and JWT algorithm confusion (none/RS256/JKU).

  - **[Injections: SQLi, SSTI, XXE & RCE](injection-attacks.md)** — Polyglot SQLi & NoSQLi, Server-Side Template Injection (Jinja2, Twig, Freemarker, Velocity), Out-of-Band XXE, and OS Command Injection filter bypasses.

  - **[SSRF, CORS, CSRF & HTTP Desync](ssrf-cors-csrf-smuggling.md)** — Cloud metadata SSRF (AWS IMDSv2, GCP, Azure), DNS rebinding, CORS regex bypasses, SameSite Lax CSRF gadgets, and HTTP/1.1 & H2C Request Smuggling (CL.TE / TE.CL).

  - **[IDOR / BOLA, 403 Bypass & Race](access-control-idor-race.md)** — UUID prediction & parameter pollution IDORs, 403/401 path & header bypasses, HTTP/2 Single-Packet Race Conditions, and multi-step business logic abuse.

  - **[XSS, DOM, PostMessage & CSP](xss-csp-client-side.md)** — Context-aware XSS polyglots, DOM Clobbering, Client-Side Prototype Pollution, insecure postMessage listeners, Blind XSS hunters, and JSONP/Script-Gadget CSP bypasses.

  - **[APIs, GraphQL & File Uploads](api-graphql-modern-web.md)** — REST mass assignment (BOPLA), GraphQL introspection bypass, alias batching & field stuffing, WebSocket hijacking, and polyglot file upload to RCE tricks.

---

## How I triage a new target

| Phase | Target Feature | High-Yield Vulnerability Classes to Test First |
| :--- | :--- | :--- |
| **1. Onboarding & Auth** | Sign-up, Login, SSO, OAuth, Password Reset | Pre-Account Takeover, Host Header Reset Poisoning, OAuth `redirect_uri` leak, 2FA Response Manipulation |
| **2. Core Multi-Tenant CRUD** | Organizations, Teams, Invites, Roles, Billing | IDOR / BOLA on org/user IDs, Mass Assignment (`"role":"admin"`), Privilege Escalation via Invite API |
| **3. File & Media Processing** | Avatars, PDF Exports, CSV Imports, Webhooks | Blind SSRF via Webhooks/Headless Chrome PDF, SVG/DOCX XXE, Polyglot Webshell Upload, LFI |
| **4. Financial & Quota Actions** | Coupons, Transfers, Credits, API Rate Limits | Single-Packet HTTP/2 Race Condition (Limit Overrun), Negative Quantity/Amount Logic Flaw |