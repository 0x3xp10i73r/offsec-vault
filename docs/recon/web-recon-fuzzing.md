---
title: "Web Recon, Fuzzing & JS Mining"
description: "Content discovery, parameter fuzzing, JavaScript endpoint and secret extraction, and WAF fingerprinting"
tags:
  - Recon
  - Web
  - Fuzzing
  - JavaScript
  - FFUF
---

# Web Recon, Content Fuzzing & JavaScript Mining

!!! note "What this page is doing"
    This workflow turns a live HTTP host into an application map. Establish a normal response first so a fuzzing result is a meaningful difference rather than a false positive caused by a wildcard, redirect or WAF.

---

## 1. HTTP Probing & Tech Fingerprinting

```bash
# Probe a list of hosts for status code, title, content-length, server header, and tech stack
httpx -l subdomains.txt -p 80,443,8000,8080,8443,8888,9000 \
      -sc -cl -title -tech-detect -server -vhost -threads 100 -o httpx_probed.txt
# Detect WAF presence before launching noisy fuzzers
wafw00f https://<DOMAIN>
```

---

## 2. Directory, File & Backup Fuzzing

Inspired by **six2dez's Web Fuzzers Comparison**, I rely on **FFUF** for speed/precision and **Feroxbuster** for automatic recursive discovery.

=== "FFUF (Fast Web Fuzzer)"

    ```bash
    # Standard directory & extension fuzzing with auto-calibration (-ac)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
         -u https://<DOMAIN>/FUZZ \
         -e .php,.asp,.aspx,.jsp,.json,.bak,.zip,.env,.sql,.old \
         -ac -mc all -fc 404 -t 60 -o ffuf_dirs.json
    # Bypass simple IP rate limits or 403s during fuzzing via headers
    ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
         -u https://<DOMAIN>/api/FUZZ \
         -H "X-Forwarded-For: 127.0.0.1" \
         -H "X-Original-URL: /api/FUZZ" \
         -ac
    ```

=== "Feroxbuster (Recursive Rust Fuzzer)"

    ```bash
    # Recursive content discovery + link extraction from responses & JS
    feroxbuster -u https://<DOMAIN> \
         -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
         -x php,html,js,json,txt,bak \
         --extract-links --auto-bail -t 50 -o ferox_<DOMAIN>.txt
    ```

=== "High-Value Config & Leak Paths"

    ```text
    /.env
    /.git/HEAD
    /.git/config
    /actuator/env
    /actuator/heapdump
    /swagger-ui.html
    /v2/api-docs
    /v3/api-docs
    /openapi.json
    /graphql
    /server-status
    /phpinfo.php
    /.DS_Store
    /crossdomain.xml
    /wp-json/wp/v2/users
    ```

---

## 3. Hidden Parameter Discovery (`Arjun` & `x8`)

Hidden `GET`, `POST`, and `JSON` parameters (`?debug=true`, `?admin=1`, `?redirect=`, `?file=`, `?template=`) are prime entry points for IDOR, SSRF, SQLi, and mass assignment.

```bash
# Discover hidden GET/POST/JSON parameters using Arjun
arjun -u https://<DOMAIN>/api/v1/user/profile -m GET,POST,JSON -t 20
# High-speed parameter brute-forcing with x8
x8 -u "https://<DOMAIN>/profile" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -X GET POST
# FFUF GET parameter value fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "https://<DOMAIN>/index.php?FUZZ=1" -ac
```

---

## 4. JavaScript Mining: Endpoints, Source Maps & Secrets

Modern SPAs (React, Next.js, Vue, Angular) bundle internal API routes, GraphQL queries, feature flags, and sometimes hardcoded AWS/Stripe/Firebase keys inside `.js` bundles and `.js.map` source maps.

```bash
# 1. Collect all JavaScript URLs via Katana, Gau, and subjs
katana -u https://<DOMAIN> -jc -d 3 -ef css,png,jpg,svg,woff2 | grep -E "\.js(\?|$)" | sort -u > js_urls.txt
# 2. Extract hidden API endpoints from JS files using LinkFinder / xnLinkFinder
xnLinkFinder -i js_urls.txt -sf <DOMAIN> -o js_endpoints.txt
# 3. Hunt for hardcoded API keys, JWTs, AWS keys, and Slack webhooks with SecretFinder / Mantra
while read url; do
  python3 SecretFinder.py -i "$url" -o cli
done < js_urls.txt
# 4. Check for exposed Webpack/Vite Source Maps (.js.map) & reconstruct original TypeScript source!
while read url; do
  map_url="${url}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    echo "[!] EXPOSED SOURCE MAP: $map_url"
    sourcemapper -output ./unpacked_src -url "$map_url"
  fi
done < js_urls.txt
```