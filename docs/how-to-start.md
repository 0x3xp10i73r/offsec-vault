---
title: "How to start"
description: "A practical starting path for navigating the security notes, checklists and methodology pages."
---

# How to start

This page is the starting point for the vault. Begin with the scope and safety notes, choose the area that matches your goal, and use the linked methodology pages as a path through the material.

The pages are a working reference rather than a linear course. Read the context first, then use the checklists and examples to decide what to verify next. Expect gaps, check versions and validate anything before relying on it.

!!! danger "Read this first"
    Everything on this site is written for **authorized security testing, red team engagements, CTFs and lab environments**. Do not use any of it against systems you do not own or have written permission to test.

## What is here

| Section | Contents |
| :--- | :--- |
| [Recon](recon/index.md) | Subdomain and virtual host enumeration, ASN and DNS work, port and service playbooks, content discovery, JavaScript review, dorking |
| [Bug Bounty](web-bugbounty/index.md) | Authentication and account takeover, injections, SSRF and request smuggling, access control bugs, XSS and client-side, APIs and file uploads |
| [Web Application Pentesting](web-application-pentesting/index.md) | Beginner-friendly authentication foundations, authentication vulnerabilities, brute-force risks and username enumeration |
| [Active Directory](active-directory/index.md) | Enumeration and BloodHound, Kerberos and credential attacks, ADCS and ACL abuse, lateral movement, domain dominance and persistence |
| [Red Team](red-team/index.md) | Initial access and payload delivery, command and control infrastructure, what actually matters for EDR and AMSI evasion |
| [Privilege Escalation](privesc/index.md) | Linux and Windows escalation paths, ordered roughly by how often they work |
| [Android](android/index.md) | APK internals, traffic interception, static and dynamic analysis, Frida, and the full testing checklist |
| [Cloud](cloud-mobile/index.md) | AWS, Azure and Entra ID, GCP |
| [Checklists](checklists-arsenal/index.md) | Interactive web and internal AD checklists, Burp configuration, tooling notes, external reference index |
| [Blog](blog/index.md) | One sample long-form writeup showing how the notes are developed |
| [About](index.md) | Profile, projects, skills and contact details |

## About the commands on this site

Commands in these pages use placeholders so they can be copied between targets without rewriting half of them:

| Placeholder | Meaning |
| :--- | :--- |
| `<TARGET_IP>` | The host you are testing |
| `<DOMAIN>` | The AD domain or primary web domain |
| `<DC_IP>` | Domain controller |
| `<LHOST>` / `<LPORT>` | Your own listening host and port |
| `<USER>` | A domain or application user |

On any page whose commands contain one of the placeholders below you will see a **Command variables** box above the first code block. Fill it in once and every command on the page is updated, including the text the copy button puts on your clipboard. The values are remembered in your browser, and the **Reset** button puts the defaults back.

The checklists work the same way: tick items off as you go and your progress is kept per page.

## A note on these notes

Anything on this site that I have only read about is marked as such in the text. Where I know a technique is noisy, unreliable or usually blocked, I say so, because knowing when *not* to run something saves more time than knowing how to run it.

If something is wrong, open an issue on GitHub or send me an email. Corrections are welcome and I usually fix them the same week.
