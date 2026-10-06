---
title: "OSINT and dorking"
description: "Curated Google Dorks, GitHub secret dorks, and Shodan/Censys/FOFA queries for finding exposed assets and origin IPs"
tags:
  - OSINT
  - Dorking
  - Bug Bounty
  - Shodan
  - GitHub
---

# OSINT, dorking and origin IPs

!!! note "What this page is doing"
    Public search results are evidence about exposure, not permission to access an asset. Use them to form a hypothesis, verify ownership and scope, and report the minimum sensitive material needed to explain the risk.

Dorks I keep coming back to for exposed credentials, cloud storage buckets and origin servers that are hiding behind a CDN or WAF.

---

## 1. High-Signal Google Dorks (`site:<DOMAIN>`)

```text
# Exposed configuration, environment, backup & log files
site:<DOMAIN> ext:env OR ext:ini OR ext:conf OR ext:cnf OR ext:sql OR ext:bak OR ext:log
site:<DOMAIN> inurl:".env" OR inurl:"wp-config.php" OR inurl:"config.json"
# Directory listing & exposed backups
site:<DOMAIN> intitle:"index of" "parent directory"
site:<DOMAIN> intitle:"index of" (".git" OR ".svn" OR "backup" OR "admin" OR "uploads")
# Exposed API Docs, Swagger, GraphQL & Spring Boot Actuators
site:<DOMAIN> inurl:swagger OR inurl:api-docs OR inurl:openapi.json
site:<DOMAIN> inurl:/graphql OR inurl:/graphiql OR inurl:/playground
site:<DOMAIN> inurl:/actuator/env OR inurl:/actuator/health OR inurl:/actuator/heapdump
# Sensitive parameters prime for Open Redirect, SSRF, and LFI
site:<DOMAIN> inurl:redirect= OR inurl:url= OR inurl:next= OR inurl:returnTo= OR inurl:dest=
site:<DOMAIN> inurl:file= OR inurl:path= OR inurl:template= OR inurl:include= OR inurl:doc=
# Cloud Storage & Third-Party Leaks for Target Organization
site:s3.amazonaws.com "<DOMAIN>"
site:blob.core.windows.net "<DOMAIN>"
site:googleapis.com "<DOMAIN>"
site:trello.com OR site:notion.site OR site:postman.com "<DOMAIN>"
```

---

## 2. GitHub Dorking for Leaked Secrets & Internal Code

Search both the organization's official GitHub repos (`org:target`) and personal employee repos mentioning `"<DOMAIN>"`:

```text
"<DOMAIN>" (password OR passwd OR pwd OR secret OR token OR apikey OR api_key)
"<DOMAIN>" filename:.env OR filename:.npmrc OR filename:.dockercfg OR filename:id_rsa
"<DOMAIN>" "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"
"<DOMAIN>" "AKIA" OR "aws_access_key_id" OR "aws_secret_access_key"
"<DOMAIN>" "jdbc:mysql://" OR "mongodb+srv://" OR "postgres://" OR "redis://"
"<DOMAIN>" "xoxb-" OR "xoxp-" OR "hooks.slack.com"
"<DOMAIN>" "Authorization: Bearer" OR "eyJhbGciOi"
```

```bash
# Scan only repositories and organizations named in the approved scope.
# `--only-verified` reduces noise; it does not make a secret safe to print.
trufflehog github --org=<GITHUB_ORG> --only-verified

# Scan a local clone without echoing secret values into a shared terminal log.
gitleaks detect --source ./cloned_repo --redact --verbose
```

---

## 3. Shodan, Censys & FOFA Queries (Finding Origin IPs)

When `<DOMAIN>` sits behind Cloudflare, CloudFront, or Akamai WAF, finding the **unprotected origin IP** lets you send payloads directly (`curl -k https://<ORIGIN_IP> -H "Host: <DOMAIN>"`) and bypass the WAF completely!

=== "Shodan Queries"

    ```text
    # Find servers presenting SSL certificates for <DOMAIN>
    ssl.cert.subject.cn:"<DOMAIN>"
    ssl:"<DOMAIN>" 200
    # Match exact HTTP Title or Favicon Hash
    http.title:"Target Portal Login"
    http.favicon.hash:116323821
    # Exposed Jenkins, Grafana, Kibana, Spring Boot, or Docker APIs inside target org
    org:"Target Organization" product:"Jenkins"
    org:"Target Organization" http.title:"Grafana"
    org:"Target Organization" port:2375,2376,6443,9200,27017
    ```

=== "Censys Search v2"

    ```text
    services.tls.certificates.leaf_data.names: "<DOMAIN>"
    services.http.response.html_title: "<DOMAIN>" and not autonomous_system.name: "CLOUDFLARE*"
    ```

=== "Historical DNS & SPF / Mail Header Tricks"

    ```bash
    # 1. Check historical A records before Cloudflare was enabled:
    # SecurityTrails, ViewDNS.info, DNSRepo, CrimeFlare
    # 2. Check SPF TXT records for netblocks (ip4:...) owned by the target
    dig +short TXT <DOMAIN> | grep -i spf
    # 3. Trigger "Forgot Password" or registration email to your inbox
    # and inspect the raw "Received: from" headers for the backend server IP!
    ```