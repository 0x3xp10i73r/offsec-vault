---
title: "Subdomain, ASN & VHost Enumeration"
description: "Horizontal and vertical domain enumeration, DNS brute-forcing, VHost fuzzing, and subdomain takeover hunting"
tags:
  - Recon
  - Subdomains
  - DNS
  - Bug Bounty
---

# Subdomain, ASN & Virtual Host Enumeration

!!! note "What this page is doing"
    This page moves from ownership and passive evidence to DNS validation and virtual-host testing. A discovered name is a lead; keep the source, confirm scope, measure wildcard behavior, and only then treat the host as an active target.

---

## 1. Horizontal Recon: Acquisitions, ASNs & IP Ranges

When testing large enterprises (unlimited/wide scope), always map subsidiary root domains and Autonomous System Numbers (ASNs) first.

```bash
# Collect organization and ASN leads. Treat every result as a candidate until
# ownership and scope are confirmed.
metabigor net --org "<DOMAIN>" -o asn_ranges.txt
amass intel -org "<DOMAIN>"

# Resolve certificate names and keep only names related to the approved domain.
asnmap -d <DOMAIN> -silent \
  | tlsx -san -cn -silent \
  | grep -i "<DOMAIN>" \
  | sort -u \
  > certificate-names.txt
```

```bash
# Hash the approved site's favicon for an asset-index lookup.
# The request is read-only; do not submit a target's favicon to a third-party
# service unless that service is allowed by the engagement.
python3 favicon_hash.py "https://<DOMAIN>/favicon.ico"
```

```python
# favicon_hash.py — calculate the Shodan-compatible MurmurHash3 value.
import base64
import sys

import mmh3
import requests

response = requests.get(sys.argv[1], timeout=10)
response.raise_for_status()
encoded = base64.b64encode(response.content)
print(mmh3.hash(encoded))
```

Use the resulting value as a search lead such as `http.favicon.hash:<HASH>`; verify the returned asset before treating it as part of the target.

---

## 2. Vertical Recon: Passive Subdomain Enumeration

=== "Subfinder & Amass"

    ```bash
    # Run Subfinder with all passive API keys configured (~/.config/subfinder/provider-config.yaml)
    subfinder -d <DOMAIN> -all -recursive -silent -o subfinder_<DOMAIN>.txt
    # Amass passive mode
    amass enum -passive -d <DOMAIN> -o amass_passive_<DOMAIN>.txt
    ```

=== "Certificate Transparency (crt.sh & CertSpotter)"

    ```bash
    # Query crt.sh JSON API directly
    curl -s "https://crt.sh/?q=%25.<DOMAIN>&output=json" \
      | jq -r '.[].name_value' \
      | sed 's/\*\.//g' \
      | sort -u > crtsh_<DOMAIN>.txt
    # Query CertSpotter API
    curl -s "https://api.certspotter.com/v1/issuances?domain=<DOMAIN>&include_subdomains=true&expand=dns_names" \
      | jq -r '.[].dns_names[]' \
      | sed 's/\*\.//g' | sort -u >> crtsh_<DOMAIN>.txt
    ```

=== "GitHub Subdomain Scraping"

    ```bash
    # Scrape subdomains leaked inside GitHub repositories
    github-subdomains -d <DOMAIN> -t $GITHUB_TOKEN -o github_subs_<DOMAIN>.txt
    ```

---

## 3. Active DNS Brute-Forcing & Permutations

Passive sources miss internal-facing or newly spun-up staging hosts. Use `puredns` (powered by `massdns`) with wildcard filtering.

```bash
# Fetch fresh validated public DNS resolvers
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt
# Active DNS brute-force with SecLists 2M wordlist
puredns bruteforce /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt <DOMAIN> \
  -r resolvers.txt -w bruteforced_subs.txt
# Permutation / Alteration scanning with gotator or alterx
cat passive_subs.txt bruteforced_subs.txt | sort -u > known_subs.txt
alterx -l known_subs.txt -enrich | puredns resolve -r resolvers.txt -w permuted_live_subs.txt
```

---

## 4. Virtual Host (VHost) Discovery

Many internal dashboards (`dev.<DOMAIN>`, `jenkins.<DOMAIN>`, `admin.<DOMAIN>`) have no public DNS record and only respond when the `Host:` HTTP header matches on `<TARGET_IP>`.

```bash
# Fuzz Virtual Hosts using FFUF and filter out baseline response size (-fs)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -u http://<TARGET_IP>/ \
     -H "Host: FUZZ.<DOMAIN>" \
     -mc all -fc 400,404 -fs 4218 -t 80
# VHost discovery with Gobuster (vhost mode)
gobuster vhost -u http://<DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

---

## 5. Subdomain Takeover Hunting

Inspired by **HowToHunt** and **can-i-take-over-xyz**: when a subdomain has a `CNAME` pointing to a third-party cloud service (S3, GitHub Pages, Azure App Service, Heroku, Fastly, Shopify) that has been deleted or unclaimed, register the external resource to hijack the subdomain.

```bash
# Check CNAME records across all discovered subdomains using dnsx
dnsx -l known_subs.txt -cname -resp -silent -o cname_records.txt
# Scan for vulnerable dangling CNAMEs using nuclei takeover templates & subzy
nuclei -l known_subs.txt -t http/takeovers/ -o nuclei_takeovers.txt
subzy run --targets known_subs.txt --hide_fails
```

| Cloud / SaaS Provider | Vulnerable CNAME Pattern | Fingerprint / Response String | Takeover Status |
| :--- | :--- | :--- | :--- |
| **AWS S3 Bucket** | `*.s3.amazonaws.com` | `NoSuchBucket` (`The specified bucket does not exist`) | Yes Exploitable |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here.` | Yes Exploitable |
| **Microsoft Azure** | `*.azurewebsites.net`, `*.cloudapp.net` | `404 Web Site not found` / NXDOMAIN | Yes Exploitable |
| **Heroku** | `*.herokuapp.com` | `No such app` / `herokucdn.com/error-pages/no-such-app.html` | Yes Exploitable |
| **Cargo Collective** | `subdomain.cargocollective.com` | `404 Not Found` (`If you're moving your domain away...`) | Yes Exploitable |
| **DigitalOcean Spaces** | `*.digitaloceanspaces.com` | `NoSuchBucket` | Yes Exploitable |

!!! tip "Escalating Subdomain Takeover Impact"
    Once you claim a dangling subdomain:
    1. **Session Cookie Theft**: Check if the parent domain sets cookies with `Domain=.<DOMAIN>` without `HttpOnly` or reads cookies across subdomains.
    2. **CORS Bypass**: Check if `api.<DOMAIN>` trusts `*.<DOMAIN>` in `Access-Control-Allow-Origin`.
    3. **OAuth `redirect_uri` Whitelist**: Use the hijacked subdomain as a trusted `redirect_uri` target to steal OAuth authorization codes.