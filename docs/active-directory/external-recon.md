---
title: "External Recon & Enumeration Principles"
description: "Passive OSINT before going internal — mapping IP space and domains, harvesting usernames and breach data, and turning an email format into a spray-ready user list."
tags:
  - Active Directory
  - OSINT
  - Recon
  - External
---

# External Recon & Enumeration Principles

Before touching the internal network, you look at the organisation from the outside — the way a real attacker would. External recon is almost entirely **passive**: you read public data rather than scan live hosts. The goal is not to break in from the internet but to gather the raw material that makes the internal phase faster — valid usernames, the email/username format, breach passwords, and a picture of the tech stack and defences.

!!! note "Why bother if you already have internal access?"
    Even on an internal engagement, external recon pays off. It validates the scope document, turns up infrastructure the client forgot to mention, surfaces leaked credentials that may work on a VPN or portal, and — most importantly — builds the username list you will spray internally. A single reused password found in breach data can be the whole foothold.

## What to look for

| Data point | What you are after |
| :--- | :--- |
| **IP space** | ASN, netblocks, cloud providers, DNS records |
| **Domain info** | Subdomains, mail servers, name servers, VPN portals, defensive products |
| **Schema / format** | Email format (`first.last`), the derived AD username format, password-policy hints |
| **Data disclosures** | PDFs/Office docs with metadata, intranet links, credentials committed to GitHub |
| **Breach data** | Leaked usernames, passwords, and hashes |

## Where to look

| Resource | Tools / sites |
| :--- | :--- |
| ASN / IP blocks | Hurricane Electric BGP toolkit (`bgp.he.net`), IANA, ARIN, RIPE |
| DNS records | `viewdns.info`, DomainTools, PTRArchive, `nslookup`, `dig` |
| Usernames / emails | LinkedIn, company contact pages, `linkedin2username` |
| File hunting | Google dorks |
| Breach data | HaveIBeenPwned, Dehashed |
| Code / cloud leaks | GitHub (TruffleHog), GrayHat Warfare, exposed S3 / Azure Blob |
| People | LinkedIn, Twitter/X, Glassdoor, Indeed job postings |

## Finding documents and emails — Google dorks

Search operators narrow Google to exactly the files and pages that leak useful data. Replace `inlanefreight.com` with your authorised target.

```bash
# PDFs hosted on the target domain (check their metadata next)
filetype:pdf inurl:inlanefreight.com

# Office documents
filetype:docx inurl:inlanefreight.com
filetype:xlsx inurl:inlanefreight.com

# Email addresses on the site
intext:"@inlanefreight.com" inurl:inlanefreight.com

# Login portals
inurl:inlanefreight.com intext:"login"

# Cloud storage buckets referencing the company
site:s3.amazonaws.com "inlanefreight"
site:blob.core.windows.net "inlanefreight"
```

## Validating DNS

```bash
# Check the name servers
nslookup ns1.inlanefreight.com

# Full record dump
dig any inlanefreight.com
```

A reverse-IP lookup (via `viewdns.info` or similar) shows other domains hosted on the same address — useful, but a reminder that small orgs often sit behind **shared infrastructure** (Cloudflare, AWS, Azure) you are not authorised to attack.

## From email format to username list

The single most valuable output of external recon is a list of **likely valid usernames**. Public contact pages give you the email format, and the AD `sAMAccountName` is almost always a predictable transform of it:

- `john.smith@inlanefreight.com` → AD username is probably `j.smith`, `john.smith`, or `jsmith`

```bash
# Scrape LinkedIn into candidate username formats (flast, first.last, f.last)
python3 linkedin2username.py -u <YOUR_LINKEDIN> -c "Inlanefreight"

# Search breach data for leaked creds tied to the domain
python3 dehashed.py -q inlanefreight.local -p
# Returns email, username, plaintext password, and/or hash
```

Feed the generated names into Kerbrute during [Initial Domain Enumeration](initial-domain-enumeration.md) to confirm which ones actually exist, then into [Password Spraying](password-spraying.md).

!!! tip "Metadata is an underrated goldmine"
    Document properties often expose the internal username format directly. In one engagement where standard lists and LinkedIn turned up nothing, the **Author field** of a handful of published PDFs revealed a four-character GUID username scheme (`[A-Z0-9]{4}`). Because the exact charset was known, every possible username could be generated and fully enumerated:

    ```bash
    #!/bin/bash
    for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
      do echo "$x"
    done
    # 1,679,616 candidate usernames → Kerbrute → 100% enumeration
    ```

    Predictable "random" formats can be **more** exploitable than `first.last` once the pattern is discovered. The defensive lesson: scrub metadata before publishing files.

## What job postings reveal

Recruitment pages quietly disclose the tech stack:

- "SharePoint 2013 and 2016" → an in-place upgrade means old, possibly vulnerable versions may linger.
- "Azure" → cloud presence and likely Entra ID / hybrid identity.
- Named products and versions → a shortlist of known CVEs to research before you go internal.

## Principles and reminders

- External recon is **passive** — no active scanning of real-world IPs unless explicitly authorised.
- Any host not **explicitly in scope** is off-limits, even if you stumble onto it.
- Shared hosting (Cloudflare/AWS/Azure) may need **written approval from the provider** before testing — confirm with the client.
- **Document as you go**: screenshots, saved tool output, timestamps. Don't rely on memory.

## Key takeaways

- Breach data plus a known email format is often enough to start internal password spraying.
- Job postings expose the full tech stack and exact software versions.
- A single low-privilege domain user is enough to begin most internal AD enumeration.
- `linkedin2username` + Dehashed is the fastest route to a usable credential list.
