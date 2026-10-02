---
title: "Reference index"
description: "Curated external security resources organized by operational color code: Red, Blue, Yellow, Grey, and Training"
tags:
  - Reference
  - Resources
  - OSINT
  - Blue Team
  - Training
---

# Reference index

Resources I actually return to during engagements and research, sorted by discipline. Everything here is public and free unless noted.
---

## Offensive security

| Resource | What It Is | Best For |
| :--- | :--- | :--- |
| [Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/) | AD & internal pentest cheatsheets (swisskyrepo) | AD attack reference |
| [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings) | The payload bible | Every web vuln class |
| [HackTricks](https://book.hacktricks.wiki/) | Massive pentesting methodology wiki (Carlos Polop) | Linux/Windows/cloud/web privesc |
| [HackTricks Cloud](https://cloud.hacktricks.wiki/) | Cloud-specific attack paths | AWS/Azure/GCP |
| [Pentest Book (six2dez)](https://www.pentest-book.com/) | Practical pentest knowledge base | Ports, web attacks, checklists |
| [ired.team](https://www.ired.team/) | Red team & AD tradecraft notes | Post-exploitation depth |
| [Navigating The Shadows](https://red.0xbad53c.com/) | Red team ops GitBook | C2, initial access, ops |
| [Hacker's Rest (zweilosec)](https://zweilosec.gitbook.io/hackers-rest) | OSCP/CTF focused notes | Fundamentals & privesc |
| [HowToHunt (KathanP19)](https://kathan19.gitbook.io/howtohunt) | Vulnerability-specific hunting guides | Bug bounty methodology |
| [GTFOBins](https://gtfobins.github.io/) | Unix binaries for privesc & bypass | Linux privesc |
| [LOLBAS](https://lolbas-project.github.io/) | Windows living-off-the-land binaries | Evasion & execution |
| [HackTricks Hardware](https://hacktricks-hardware.wiki/) | Hardware hacking | IoT/physical |
| [The Hacker Recipes](https://www.thehacker.recipes/) | AD & Exchange attack recipes | AD exploitation |
| [WADComs](https://wadcoms.github.io/) | Interactive cheat sheet | AD tooling commands |

---

## Defensive, detection and DFIR

| Resource | What It Is | Best For |
| :--- | :--- | :--- |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | Vendor-agnostic detection rules | Writing detections |
| [Awesome Detection Engineering](https://github.com/m00zh33/awesome-detection-engineering) | Curated detection engineering resources | Building a program |
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary TTP knowledge base | Mapping coverage |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Defensive countermeasure mapping | Defense design |
| [Event ID Reference (Ultimate Windows Security)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) | Windows event ID encyclopedia | Log analysis |
| [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) | Modular Sysmon config | Endpoint telemetry |
| [Awesome Sysmon](https://github.com/PreciseSecurity/awesome-sysmon) | Sysmon configs & resources | Telemetry tuning |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Atomic tests mapped to ATT&CK | Detection validation |
| [Velociraptor](https://docs.velociraptor.app/) | Endpoint DFIR & hunting platform | IR at scale |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast Windows event log hunting | DFIR triage |
| [LOLDrivers](https://www.loldrivers.io/) | Vulnerable/malicious drivers | BYOVD hunting |

---

## Cloud, containers and engineering

| Resource | What It Is | Best For |
| :--- | :--- | :--- |
| [HackTricks Cloud](https://cloud.hacktricks.wiki/) | Cloud attack techniques | AWS/Azure/GCP testing |
| [AWS Security Maturity Model](https://maturitymodel.security.aws.dev/) | AWS security posture guidance | Cloud hardening |
| [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) | Vulnerable-by-design AWS labs | AWS practice |
| [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/) | Azure ATT&CK-style matrix | Entra ID testing |
| [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Vulnerable K8s cluster | K8s practice |
| [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security) | Cloud-native security fundamentals | Architecture review |
| [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/) | Pipeline security risks | CI/CD testing |
| [Docker Security Cheat Sheet (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | Container hardening | Container review |

---

## OSINT, privacy and OPSEC

| Resource | What It Is | Best For |
| :--- | :--- | :--- |
| [OSINT Framework](https://osintframework.com/) | Categorized OSINT tool tree | Starting an investigation |
| [Bellingcat's Online Investigation Toolkit](https://bellingcat.gitbook.io/toolkit) | Journalist-grade OSINT tools | Verification & attribution |
| [Awesome OSINT](https://github.com/jivoi/awesome-osint) | Huge curated OSINT list | Tool discovery |
| [theHarvester](https://github.com/laramies/theHarvester) | Email/subdomain/OSINT gathering | External recon |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | Automated OSINT correlation | Broad recon automation |
| [TinyCheck](https://github.com/KasperskyLab/TinyCheck) | Mobile traffic analysis | Device investigations |
| [PrivacyGuides](https://www.privacyguides.org/) | Privacy tooling recommendations | Operator OPSEC |
| [Whonix / Tails docs](https://www.whonix.org/wiki/Documentation) | Anonymity systems | High-risk OPSEC |

---

## Training and labs

| Resource | What It Is | Best For |
| :--- | :--- | :--- |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free, best-in-class web labs | Web exploitation mastery |
| [Hack The Box](https://www.hackthebox.com/) | Machines, Pro Labs, Academy | Practical AD & exploit practice |
| [TryHackMe](https://tryhackme.com/) | Guided learning paths | Structured beginners path |
| [VulnHub](https://www.vulnhub.com/) | Downloadable vulnerable VMs | Offline practice |
| [PentesterLab](https://pentesterlab.com/) | Code-review & web exercises | White-box web testing |
| [OffSec (OSCP/OSEP/OSWE/OSED)](https://www.offsec.com/) | Certification paths | Careers & fundamentals |
| [Zero-Point Security (CRTO)](https://training.zeropointsecurity.co.uk/) | Red team ops certification | C2 & adversary simulation |
| [SANS Courses & Posters](https://www.sans.org/posters/) | Cheat sheet posters | Quick reference |
| [pwn.college](https://pwn.college/) | Free binary exploitation curriculum | Exploit development |
| [Maldev Academy](https://maldevacademy.com/) | Windows malware dev & evasion | Payload engineering |
| [Awesome Bug Bounty](https://github.com/djadmin/awesome-bug-bounty) | Bug bounty resources & writeups | Program strategy |
| [Bug Bounty Reports Explained](https://github.com/djadmin/awesome-bug-bounty#write-ups) | Real disclosed reports | Report-writing patterns |

---

## How to use this list

```text
1. Pick a DOMAIN you are weak in (e.g. ADCS, K8s, or detection engineering).
2. Choose ONE primary resource (not five) + ONE lab environment.
3. Build a small test range: a vulnerable VM or CloudGoat scenario.
4. Follow the resource end-to-end while exploiting the lab — never read passively.
5. Write your own note for every technique you successfully execute.
6. Teach it: a short blog post or internal talk forces real understanding.
7. Repeat monthly — one domain at a time beats a shallow tour of everything.
```