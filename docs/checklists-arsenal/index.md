---
title: "Checklists"
description: "Interactive engagement checklists, Burp Suite configuration, tool arsenal, and a color-coded security reference index"
tags:
  - Checklists
  - Methodology
  - Arsenal
  - Reference
---

# Checklists and tooling

!!! tip "The checklists are interactive"
    The checkbox items on the checklist pages are clickable and your progress is saved in your browser, with a counter above the list. That means you can work through an engagement over several days without losing your place. Hit **Reset** when you start a new target.

---

## Pages in this section

  - **[Web & Bug Bounty Checklist](web-bugbounty-checklist.md)** — 85+ checklist items across reconnaissance, authentication, authorization, injection, business logic, client-side, and infrastructure testing — in the order I actually test them.

  - **[Internal & AD Checklist](internal-ad-checklist.md)** — Unauthenticated foothold, credentialed enumeration, Kerberos & ADCS abuse, lateral movement, dominance, and reporting/cleanup — in engagement order.

  - **[Burp Suite & Tool Arsenal](burp-extensions-arsenal.md)** — Burp Pro project options, match/replace rules, my top 15 extensions, upstream proxy chaining, plus the full recon/web/AD/cloud/mobile tool stack with one-line installs.

  - **[Reference index](security-reference-index.md)** — External resources I actually use, sorted by discipline (offensive, defensive, cloud, OSINT, training).

---

## Engagement readiness

- [ ] Scope document signed, in-scope/out-of-scope hosts explicitly listed
- [ ] Emergency contact + escalation path defined with the client
- [ ] Testing window and rate-limit constraints confirmed
- [ ] Client aware of potentially disruptive tests (DoS, password spray, phishing)
- [ ] Legal authorization & get-out-of-jail letter on hand (physical/on-site work)
- [ ] Testing infrastructure isolated (VPN, dedicated VMs, no personal accounts)
- [ ] Logging enabled on attacker infrastructure (for the report timeline)
- [ ] Evidence collection method standardized (screenshots + timestamps + raw request/response)
- [ ] Reporting template & severity matrix (CVSS + business impact) prepared
- [ ] Cleanup & deconfliction plan agreed (backdoors, created accounts, uploaded files)