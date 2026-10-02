---
title: "Burp Suite and tooling"
description: "Burp Suite Pro project configuration, top extensions, match/replace rules, and the full offensive security tool stack"
tags:
  - Burp Suite
  - Arsenal
  - Tools
  - Web
---

# Burp Suite configuration and tooling

---

## 1. Burp Suite Project Setup (Do This First on Every Engagement)

```text
[TARGET] Settings -> Scope
  - Add in-scope: ^https?://([a-z0-9-]+\.)?<DOMAIN>/.*
  - Add out-of-scope for noise: logout, sign-out, static assets, analytics, CDNs
  - Enable "Advanced scope control" to restrict scanning to exact hosts

[PROXY] Settings -> Proxy -> Match and Replace (add these on every engagement!)
  # 1. Identify yourself as a researcher to the client (and avoid WAF bans)
  Request/Header: Add -> User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ...
  Request/Header: Add -> X-Bug-Bounty: 0x3xp10i73r
  # 2. Force all traffic through a specific host/IP (when testing a staging VHost)
  Request/Header: Add -> Host: <DOMAIN>
  Request/Header: Add -> X-Forwarded-Host: <DOMAIN>
  # 3. Strip headers that hide your exploits
  Request/Header: Remove -> If-None-Match
  Request/Header: Remove -> If-Modified-Since
  Request/Header: Remove -> Origin (only when testing CSRF defects!)
  # 4. Force-response improvements for testing
  Response/Header: Add -> Cache-Control: no-store (prevent cached response confusion)
  Response/Header: Add -> X-Frame-Options: ALLOWALL (quick clickjacking PoC view)
  # 5. Auto-replace interesting values (e.g. tenant IDs, emails, user IDs) during testing
  Request/Body: Replace -> "user_id":<YOUR_ID> -> "user_id":<VICTIM_ID>

[SETTINGS] Misc
  - Upstream proxy: chain through a VPS/residential proxy when the target blocks your IP
  - Disable "Update" checks to cut noise (Pro only)
  - Log all requests/responses to disk for the report evidence (Logger++ handles this better)
  - Enable "Intercept responses based on rules" only when needed (avoid clutter)

[SCANNER] (Pro)
  - Configure a custom scan configuration with all insertion points
  - Use "Audit single request" for surgical testing instead of full site scans
  - Always review findings manually — scanner output is a lead, not a finding
```

---

## 2. Burp extensions I install first

| Extension | Purpose | Must-Have For |
| :--- | :--- | :--- |
| **Logger++** | Advanced request/response logging with filters & grep | Every engagement |
| **Autorize** | Automated authorization/IDOR testing (browse as user A, replay as user B) | Access control |
| **AuthMatrix** / **Authz** | Role × endpoint privilege matrix | Multi-role apps |
| **Param Miner** | Find unkeyed headers/params → cache poisoning, hidden params, web cache deception | Web cache bugs |
| **Turbo Intruder** | Raw-socket, high-speed, single-packet-attack fuzzing | Race conditions, OTP brute |
| **HTTP Request Smuggler** | Automated desync detection (CL.TE, TE.CL, H2) | Front-end proxies |
| **JWT Editor** | Decode, edit, sign, attack JWTs (alg confusion, jku, kid) | Token testing |
| **InQL** | GraphQL introspection, query generation, and attack surface mapping | GraphQL APIs |
| **Collaborator Everywhere** | Auto-inject Collaborator payloads into every header/param for blind bugs | Blind SSRF/XSS/XXE |
| **Active Scan++** | Extra scan checks (host header, edge cases, cache) | Pro scanning |
| **Backslash Powered Scanner** | Detects unknown injection classes by differential fuzzing | Injection discovery |
| **Reflected Parameters** | Track which params are reflected (lead generation) | XSS/SSTI hunting |
| **JSON Web Tokens** (older) | JWT manipulation for legacy workflows | Tokens |
| **Upload Scanner** | Systematic file upload testing (extensions, magic bytes, polyglots) | File uploads |
| **Nuclei/Burp Bridge** | Turn Burp traffic into Nuclei templates & vice versa | Automation |
| **Burp Bounty** (Pro) | Custom active/passive scan profiles with your own payload lists | Coverage |
| **Hackvertor** | Inline payload transformation (encoding, hashing, conversion) | Payload crafting |
| **Collaborator Client** | Out-of-band detection for blind vulnerabilities | Blind bugs |
| **WSDL Wizard / SOAP** | SOAP/WSDL API testing | Legacy APIs |
| **DOM Invader** (built-in) | DOM XSS, prototype pollution, postMessage analysis | Client-side |
| **Burp Sitemap Search** | Grep the whole sitemap for secrets/leaks quickly | Post-recon sweep |
| **GAP** (Burp BApp) | Automated discovery of hidden parameters on large sitemaps | Hidden params |

```bash
# --- Quick install of the free BApp store extensions (or use the Extender tab) ---
# Extender -> BApp Store -> install the ones above. For Pro-only features, use Burp Pro.
```

---

## 3. Command-line tooling

=== " Recon & Enumeration"

    ```bash
    # Subdomains & DNS
    subfinder amass assetfinder findomain puredns dnsx dnsvalidator shuffledns
    # HTTP probing & tech detection
    httpx tlsx katana gau waybackurls gospider hakrawler wafw00f whatweb
    # Content discovery & fuzzing
    ffuf feroxbuster gobuster dirsearch arjun x8 paramspider
    # JS analysis
    linkfinder xnLinkFinder SecretFinder subjs sourcemapper js-beautify trufflehog gitleaks
    # Screenshots & visual recon
    aquatone gowitness eyewitness
    # Vulnerability scanning
    nuclei nikto zaproxy
    # OSINT
    theHarvester spiderfoot recon-ng sherlock holehe h8mail
    ```

=== " Web Exploitation"

    ```bash
    # SQLi / Injection
    sqlmap ghauri NoSQLMap commix
    # Template & XML
    tplmap sstimap
    # SSRF / Request smuggling
    ssrfmap smuggler.py Gopherus
    # Fuzzing & brute force
    wfuzz patator hydra medusa
    # XSS
    dalfox xsstrike XSStrike xsser
    # JWT / OAuth
    jwt_tool JWT-forge
    # WordPress / CMS
    wpscan joomscan droopescan cmseek
    # API
    kiterunner postman-cli graphql-cop clairvoyance inql
    ```

=== " Internal & Active Directory"

    ```bash
    # Enumeration & exploitation
    netexec (nxc) impacket-bloodhound bloodhound-python ldapdomaindump
    enum4linux-ng smbclient smbmap rpcclient nbtscan onesixtyone snmpwalk
    kerbrute responder mitm6 ntlmrelayx coercer petitpotam
    # Credential attacks
    hashcat john hydra medusa
    # ADCS & AD abuse
    certipy-ad bloodyAD pywhisker PKINITtools Rubeus Mimikatz Kekeo
    # Lateral movement & pivoting
    evil-winrm xfreerdp ligolo-ng chisel sshuttle proxychains4 socat
    # Windows privesc & post-exploitation
    winPEAS PrivescCheck PowerUp SharpUp Seatbelt SharpHound GodPotato SigmaPotato
    # Linux privesc
    linpeas linux-exploit-suggester pspy linenum traitor deepce
    ```

=== " Cloud & Mobile"

    ```bash
    # AWS / Azure / GCP
    pacu ScoutSuite enumerate-iam cloudsplaining PMapper
    roadrecon roadtx azurehound microburst az cli awscli gcloud
    cloud_enum S3Scanner slurp GCPBucketBrute
    # Containers / K8s
    trivy kube-hunter kubeaudit peirates deepce cdk
    # Mobile
    apktool jadx frida-tools objection mobsf apksigner uber-apk-signer
    frida-ios-dump class-dump
    ```

---

## 4. Install script (Kali / Debian / Ubuntu)

```bash
#!/usr/bin/env bash
# Tooling bootstrap — apt + Go + pipx + git-based tools
set -e

sudo apt update && sudo apt install -y \
  nmap masscan feroxbuster ffuf gobuster dirsearch nikto sqlmap hydra john hashcat \
  smbclient smbmap enum4linux-ng nbtscan onesixtyone snmp snmp-mibs-downloader \
  ldap-utils rpcbind nfs-common responder proxychains4 chisel socat \
  python3-pip pipx golang-go ruby-full default-jdk apktool jadx adb \
  seclists wordlists whatweb tcpdump wireshark
# --- Go-based tooling (fast, single binaries) ---
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/ropnop/kerbrute@latest
go install -v github.com/ropnop/go-windapsearch/cmd/windapsearch@latest
go install -v github.com/jpillora/chisel@latest
# --- Pipx (isolated Python CLI tools) ---
pipx install netexec
pipx install impacket
pipx install certipy-ad
pipx install bloodyAD
pipx install bloodhound
pipx install arjun
pipx install sqlmap
pipx install wafw00f
pipx install shodan
pipx install theHarvester
# --- Git-based tools ---
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/peass-ng/PEASS-ng peass
git clone https://github.com/nicocha30/ligolo-ng ligolo-ng
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/swisskyrepo/PayloadsAllTheThings payloads-all-the-things
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/GTFOBins/GTFOBins.github.io gtfo

echo "[+] Arsenal installed. Add ~/go/bin and ~/.local/bin to your PATH."
```

!!! tip "Recon → Exploit Handoff"
    Keep everything in a per-target directory (`recon/<DOMAIN>/`) and use `anew` to accumulate
    unique lines as new tools run. A clean, deduplicated dataset is what makes the difference
    between a shallow and a deep engagement.