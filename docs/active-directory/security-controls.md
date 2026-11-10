---
title: "Enumerating Security Controls"
description: "Checking for Windows Defender, AppLocker, PowerShell Constrained Language Mode, and LAPS before running loud tools against a host."
tags:
  - Active Directory
  - Defender
  - AppLocker
  - LAPS
  - OPSEC
---

# Enumerating Security Controls

Once you have a foothold, don't immediately start running PowerView or dropping binaries. Check what's actually watching the host first. The defensive products in place dictate which tools will work at all, which will get flagged, and how you need to modify your approach — and controls are frequently applied unevenly, so a check on one box doesn't guarantee the same result on the next.

!!! note "This is informational, not an attack"
    Nothing here compromises anything on its own. Bypassing what you find (Defender exclusions, AppLocker gaps, CLM escapes) is covered in depth elsewhere — this page is strictly the recon step that comes before you decide what to run.

## Windows Defender

```powershell
Get-MpComputerStatus
```

```text
RealTimeProtectionEnabled : True
```

Defender's defaults will block well-known tools like PowerView outright, so check `RealTimeProtectionEnabled`, `AntivirusEnabled`, `BehaviorMonitorEnabled`, and `IoavProtectionEnabled` before assuming a script will even load.

## AppLocker

Microsoft's application-whitelisting control — restricts which executables, scripts, MSI packages, and DLLs can run, and commonly blocks `cmd.exe` and `powershell.exe` outright.

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

| Field | Meaning |
| :--- | :--- |
| `PathConditions` | The path a rule applies to |
| `Action: Deny` / `Action: Allow` | Blocks or permits execution |
| `UserOrGroupSid` | Who the rule applies to (`S-1-5-...-513` = Domain Users) |

!!! tip "A common gap"
    Orgs frequently block the standard 64-bit PowerShell path but forget the alternates:

    ```text
    # Usually blocked:
    %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe

    # Often NOT blocked:
    %SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe   (32-bit)
    PowerShell_ISE.exe
    ```

## PowerShell Constrained Language Mode (CLM)

Locks down which PowerShell features are available — no COM objects, only approved .NET types, no XAML workflows or custom classes. Many PowerShell-based attack tools simply fail outright under CLM.

```powershell
$ExecutionContext.SessionState.LanguageMode
```

| Value | Meaning |
| :--- | :--- |
| `FullLanguage` | No restriction |
| `ConstrainedLanguage` | Locked down — significantly limits what PowerShell attack tooling can do |

## LAPS (Local Administrator Password Solution)

LAPS randomises and periodically rotates the **local Administrator** password per machine, which is the direct fix for the [local-admin password reuse](password-spraying.md#local-administrator-password-reuse) spraying technique. Use the **LAPSToolkit** to enumerate how it's deployed.

```powershell
# Groups delegated to read LAPS passwords — these are often privileged groups in their own right
Find-LAPSDelegatedGroups

# Users/groups with "All Extended Rights" — can read LAPS passwords even without explicit delegation
Find-AdmPwdExtendedRights

# Read the actual passwords (cleartext) + their expiration, if your user has access
Get-LAPSComputers
```

**Why this matters to an attacker:** the account that originally joined a computer to the domain is automatically granted **All Extended Rights** on it, which includes reading its LAPS password — a frequently-overlooked privilege path. Also worth checking: which computers have **no** LAPS applied at all — those are the ones where password reuse across the fleet is still live.

## Quick reference

| Control | Command | Look for |
| :--- | :--- | :--- |
| Windows Defender | `Get-MpComputerStatus` | `RealTimeProtectionEnabled` |
| AppLocker | `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | Blocked paths → find an unblocked alternate |
| Constrained Language Mode | `$ExecutionContext.SessionState.LanguageMode` | `ConstrainedLanguage` vs `FullLanguage` |
| LAPS delegation | `Find-LAPSDelegatedGroups` | Who can read LAPS passwords |
| LAPS extended rights | `Find-AdmPwdExtendedRights` | Accounts with All Extended Rights |
| LAPS passwords | `Get-LAPSComputers` | Cleartext values + machines missing LAPS |

## Next

If tooling is more restricted than this page's checks suggest — or the client wants a pure stealth pass — switch to native binaries only, covered in [Living Off the Land](living-off-the-land.md).
