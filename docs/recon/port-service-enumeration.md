---
title: "Ports and services"
description: "High-speed port scanning workflows and a complete port-by-port service enumeration and exploitation reference"
tags:
  - Recon
  - Ports
  - Nmap
  - Network Pentesting
  - SMB
  - Kerberos
---

# Ports and services

!!! note "What this page is doing"
    The objective is service identification, not a race to exploit every open port. Discover broadly, fingerprint narrowly, preserve the baseline, and choose the next service-specific question from the result.

---

## 1. Two-Stage High-Speed Port Scanning

Never run `-sC -sV -p-` in a single pass on slow links. First discover open TCP/UDP ports fast, then run targeted NSE scripts only against open ports.

```bash
# Stage 1A: RustScan fast TCP sweep -> pipes open ports directly into Nmap
rustscan -a <TARGET_IP> --ulimit 5000 -b 2500 -- -sC -sV -Pn -oA nmap_<TARGET_IP>_tcp
# Stage 1B: Masscan (ideal for /16 or /24 internal networks)
sudo masscan -p1-65535,U:53,88,123,161,389,500,1434 <TARGET_IP> --rate=5000 -e tun0 -oG masscan.gnmap
# Stage 2: Top 100 UDP port scan (SNMP 161, DNS 53, TFTP 69, IKE 500, IPMI 623)
sudo nmap -sU --top-ports 100 --min-rate 1000 -Pn <TARGET_IP> -oA nmap_<TARGET_IP>_udp
```

---

## 2. Port-by-port reference

Quick reference for the ports I run into most often. Each row gives the first thing to run and the attack paths worth trying on that service.

| Port(s) | Protocol / Service | Quick Triage Command | High-Value Attack Vectors |
| :--- | :--- | :--- | :--- |
| **21/TCP** | FTP | `nmap -sV -p21 --script ftp-anon,ftp-bounce <TARGET_IP>` | Anonymous login (`anonymous:anonymous`), writable webroot upload, binary vs ASCII transfer corruption |
| **22/TCP** | SSH | `ssh-audit <TARGET_IP>` | Weak credentials, leaked `id_rsa`/`id_ed25519`, `AuthorizedKeysCommand`, libssh/OpenSSH CVEs |
| **25/465/587** | SMTP | `smtp-user-enum -M VRFY -U users.txt -t <TARGET_IP>` | User enumeration (`VRFY`/`EXPN`/`RCPT TO`), Open Relay, Log Poisoning via mail spool (`/var/mail/<USER>`) |
| **53/TCP/UDP** | DNS | `dig axfr @<TARGET_IP> <DOMAIN>` | Zone transfer (`AXFR`), dynamic DNS updates (`nsupdate`), internal hostname discovery |
| **80/443/8080** | HTTP / HTTPS | `httpx -u http://<TARGET_IP> -sc -title -tech-detect` | VHosts, directory fuzzing, OWASP Top 10, Tomcat/Jenkins/Axis2 manager panels |
| **88/TCP** | Kerberos | `kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt` | Username enumeration, AS-REP Roasting (`GetNPUsers.py`), Kerberoasting (`GetUserSPNs.py`), PKINIT |
| **111/2049** | RPCBind / NFS | `showmount -e <TARGET_IP>` | Exported NFS shares with `no_root_squash` -> upload SUID `/bin/bash` binary |
| **135/593** | MSRPC / DCOM | `impacket-rpcdump @<TARGET_IP>` | `rpcclient` null session user/SID enum, DCOM lateral movement, PrintNightmare / Coercer |
| **139/445** | SMB / CIFS | `nxc smb <TARGET_IP> -u '' -p '' --shares` | Null/guest shares, SMB Relay (when signing disabled), MS17-010, GPP cPassword, SYSVOL scripts |
| **161/UDP** | SNMP | `onesixtyone -c community.txt <TARGET_IP>` | Default community strings (`public`/`private`), process args (`hrSWRunParameters`), netstat & creds |
| **389/636/3268** | LDAP / LDAPS | `ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local"` | Anonymous bind dump, user `description` passwords, LAPS passwords, BloodHound ACL mapping |
| **1433/TCP** | MSSQL | `nxc mssql <TARGET_IP> -u <USER> -p 'Pass' --local-auth` | `xp_cmdshell` RCE, `xp_dirtree` NTLM hash capture, `EXECUTE AS` impersonation, Linked SQL Servers |
| **3306/TCP** | MySQL / MariaDB | `mysql -h <TARGET_IP> -u root -p` | UDF (User Defined Function) RCE, `INTO OUTFILE` webshell write, `LOAD_FILE()` LFI |
| **3389/TCP** | RDP | `xfreerdp /v:<TARGET_IP> /u:<USER> /p:'Pass' /cert:ignore` | RestrictedAdmin Pass-the-Hash (`/pth:HASH`), sticky keys (`sethc.exe`) backdoor, BlueKeep |
| **5985/5986** | WinRM | `evil-winrm -i <TARGET_IP> -u <USER> -p 'Pass'` | Direct PowerShell shell with credentials or NTLM hash (`-H <NTLM_HASH>`), file upload/download |
| **6379/TCP** | Redis | `redis-cli -h <TARGET_IP> INFO` | Unauthenticated access -> SSH `authorized_keys` injection, webshell write (`CONFIG SET dir`), Rogue Server RCE |

---

## 3. Deep-Dive Service Commands

=== " SMB (139/445) & RPC (135)"

    ```bash
    # Check SMB signing status, OS version, and enumerate shares with Null Session & Guest
    nxc smb <TARGET_IP> -u '' -p '' --shares
    nxc smb <TARGET_IP> -u 'guest' -p '' --shares
    # Recursively spider readable SMB shares for credentials & config files
    nxc smb <TARGET_IP> -u '<USER>' -p 'Password123!' -M spider_plus
    # Enumerate users & RID cycling via rpcclient / impacket-lookupsid
    rpcclient -U "" -N <TARGET_IP> -c "enumdomusers; querydispinfo"
    impacket-lookupsid '<DOMAIN>/<USER>:Password123!@<TARGET_IP>'
    ```

=== " DNS (53) & SNMP (161/UDP)"

    ```bash
    # Attempt DNS Zone Transfer (AXFR) against target DNS server
    dig axfr @<TARGET_IP> <DOMAIN>
    fierce --domain <DOMAIN> --dns-servers <TARGET_IP>
    # Walk full SNMP MIB tree and extract running processes (often leaks CLI passwords!)
    snmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2
    snmpwalk -v2c -c public <TARGET_IP> NET-SNMP-EXTEND-MIB::nsExtendObjects
    braa public@<TARGET_IP>:1.3.6.*
    ```

=== " NFS (2049) `no_root_squash` Privesc"

    ```bash
    # List exported NFS paths before mounting anything.
    showmount -e <TARGET_IP>

    # Mount the approved test export on the assessment host.
    sudo mkdir -p /mnt/nfs_target
    sudo mount -t nfs <TARGET_IP>:/shared /mnt/nfs_target -o nolock
    ```

    A `no_root_squash` export means root on the client can create root-owned files on the share. Prove the permission with a lab marker, not an interactive backdoor:

    ```c
    /* Lab proof: record the effective identity when the target executes it. */
    #include <stdio.h>
    #include <unistd.h>

    int main(void) {
        FILE *proof = fopen("/tmp/nfs-identity-proof", "w");
        if (proof == NULL) return 1;
        fprintf(proof, "uid=%d\\n", geteuid());
        fclose(proof);
        return 0;
    }
    ```

    ```bash
    # Save the C proof as /mnt/nfs_target/nfs-proof.c, then compile it on the
    # mounted share. The target must execute it for the result to mean anything.
    sudo gcc /mnt/nfs_target/nfs-proof.c -o /mnt/nfs_target/nfs-proof
    sudo chmod +s /mnt/nfs_target/nfs-proof

    # After the approved lab execution, remove the binary and marker.
    sudo rm -f /mnt/nfs_target/nfs-proof /mnt/nfs_target/nfs-proof.c
    ```

=== " MSSQL (1433) & Redis (6379)"

    ```bash
    # Connect to MSSQL with the approved test account.
    impacket-mssqlclient '<DOMAIN>/<USER>:<TEST_PASSWORD>@<TARGET_IP>' -windows-auth
    ```

    Commands at the `SQL>` prompt are not shell commands; keep them in a SQL block:

    ```sql
    -- Confirm the current SQL identity before testing permissions.
    SELECT SYSTEM_USER, USER_NAME();

    -- Only test command execution when the scope explicitly allows it.
    EXEC xp_cmdshell 'whoami';

    -- Enumerate linked servers without changing their configuration.
    EXEC sp_linkedservers;
    ```

    Redis is stateful. First read its identity and configuration; do not flush a database or write an SSH key unless the engagement explicitly calls for a disposable lab.

    ```bash
    # Read-only Redis checks.
    redis-cli -h <TARGET_IP> PING
    redis-cli -h <TARGET_IP> INFO server
    redis-cli -h <TARGET_IP> CONFIG GET dir
    redis-cli -h <TARGET_IP> CONFIG GET dbfilename
    ```