---
title: "Checklists"
description: "Interactive engagement checklists, tooling notes and references that turn a broad assessment into an auditable workflow."
tags:
  - Checklists
  - Methodology
  - Arsenal
  - Reference
---

# Checklists and tooling

A checklist is a coverage control, not a substitute for judgment. It prevents the easy-to-forget steps—scope, second-account authorization checks, evidence, cleanup and reporting—from disappearing when the interesting part of an engagement starts.

!!! tip "How the interactive state works"
    The checkbox items on the checklist pages are clickable and progress is saved per page in your browser. The counter is local to your browser; it is not a client record and it is not shared with other testers. Use **Reset** for a new target, and keep the actual engagement evidence in the approved evidence store.

## The assessment loop

| Checklist stage | What it means in words | Exit condition |
| :--- | :--- | :--- |
| **Ready** | Scope, contacts, accounts, rate limits, evidence path and stop conditions are known. | The ROE is signed and the test environment is ready. |
| **Map** | The reachable assets, identities, versions and trust boundaries are recorded. | There is a prioritized attack-surface inventory. |
| **Test** | Each security control is tested with a controlled comparison. | A finding is reproducible or the negative result is recorded. |
| **Prove** | Impact is demonstrated with the smallest safe evidence. | The affected boundary and business consequence are clear. |
| **Close** | Test data and changes are removed and the client is notified. | Cleanup is verified and the report has an owner. |

## Pages in this section

- **[Web and bug bounty checklist](web-bugbounty-checklist.md)** — coverage from reconnaissance through authentication, authorization, input handling, business logic, browser controls, APIs and reporting.
- **[Internal and AD checklist](internal-ad-checklist.md)** — network position, identity graph, credential paths, ADCS/ACL, lateral movement, objectives and cleanup.
- **[Burp Suite and tooling](burp-extensions-arsenal.md)** — project setup, useful extensions, command-line tools and installation hygiene.
- **[Reference index](security-reference-index.md)** — external offensive, defensive, cloud, OSINT and training resources.

## Engagement readiness

- [ ] Scope document signed; in-scope and out-of-scope hosts are explicit
- [ ] Emergency contact, testing window and stop signal are confirmed
- [ ] Disruptive tests are named separately: spray, phishing, upload, DoS, relay and persistence
- [ ] Dedicated test accounts, device images and cloud projects are ready
- [ ] Attacker infrastructure and evidence storage are isolated from personal accounts
- [ ] UTC timestamps and request/response logging are enabled
- [ ] Canary data and safe proof strategy are agreed
- [ ] Cleanup owner and deconfliction plan are written down
- [ ] Report template, severity model and client audience are known

## How to use a checkbox

Before checking an item complete four small notes: **scope**, **identity**, **result**, and **evidence reference**. If an item is not applicable, mark it as `N/A` in the engagement record instead of silently leaving it unchecked. If a test is blocked by a control, record the block: prevention and detection are results.
