---
title: "What is Android?"
description: "The Android platform from a pentester's view — the layered architecture, the app sandbox and permission model, the ART runtime, and how an app is compiled and run."
tags:
  - Android
  - Fundamentals
  - Architecture
---

# What is Android?

Before testing an Android app it helps to know what you are actually standing on. Android is a **Linux-based mobile operating system** where every app runs as its own isolated Linux user, inside a managed runtime, on top of a stack of system services. Almost every Android-specific vulnerability comes from an app weakening one of those boundaries — so this page walks the boundaries first.

## The layered architecture

Android is built in layers. Each layer trusts the one below it and exposes a narrower, safer surface to the one above.

| Layer | What runs there |
| :--- | :--- |
| **1. Linux kernel** | The kernel, device drivers, SELinux enforcement, and the sandbox primitives — per-app UIDs, process isolation and namespaces. |
| **2. Native libraries + Android Runtime** | Native libraries (Bionic libc, media, OpenSSL/BoringSSL) plus **ART/DVM** — the runtime that executes app bytecode and bridges to the kernel. |
| **3. Application framework** | The Java/Kotlin APIs apps are built on: Activity Manager, Package Manager, Content Providers, Location, Telephony and other system services. |
| **4. Applications** | The apps themselves — system apps and installed apps — each in its own sandboxed process. |

When you test an app you mostly live in layer 4, but your findings are about whether the app respects the guarantees of layers 1–3 (the sandbox, the permission model, the runtime).

## The app sandbox

This is the single most important concept. At install time, Android assigns each app a **unique Linux user ID (UID)**. The app's private data directory, `/data/data/<package>/`, is owned by that UID and is `0700` — no other app can read it.

```text
/data/data/com.example.app/     owner: u0_a123 (the app's UID), mode 0700
├── databases/     SQLite databases
├── shared_prefs/  XML key/value settings
├── files/         app files
└── cache/         temporary data
```

Because the OS already isolates app data, any time an app **voluntarily** exposes data or actions to other apps — through an exported component, a world-readable file, or external storage — it is punching a hole in that sandbox. That hole is the finding.

!!! note "Root changes what *you* can see, not what the app should trust"
    On a rooted device or emulator you can read any app's private files. That is a testing convenience, not a vulnerability by itself. The question is always: *could another app, or a remote server, reach this without root?*

## The permission model

Apps declare the permissions they need in the manifest with `uses-permission`. Permissions fall into protection levels:

- **Normal** — low-risk (e.g. internet access). Granted automatically at install.
- **Dangerous** — touch user data or the device (camera, location, contacts, storage). Prompted at runtime on modern Android.
- **Signature** — granted only to apps signed with the same key as the app that declared the permission. This is how an app restricts a component to its own other apps.

A component protected by a *signature* permission is only reachable by the same developer's apps; one with **no** permission and `exported="true"` is reachable by **anything on the device**. Spotting that difference in the manifest is the core of component testing.

## The runtime: DVM and ART

App code is **not** ordinary Java bytecode and does not run on a normal JVM.

- **DVM (Dalvik Virtual Machine)** — the original register-based VM, designed for constrained devices. Superseded.
- **ART (Android Runtime)** — replaced Dalvik in Android 5. It ahead-of-time/just-in-time compiles app bytecode. Every modern device uses ART, and instrumentation tools like **Frida** attach to ART to hook methods at runtime.

## How an app is compiled and run

Knowing the pipeline is what makes the tooling make sense:

```text
Java / Kotlin source
      │  javac / kotlinc
      ▼
  .class files
      │  D8 / R8  (dex compiler + shrinker/obfuscator)
      ▼
  classes.dex   (Dalvik bytecode)
      │  packaged + signed
      ▼
   app.apk  ──install──▶  runs on ART
```

A few terms you will meet constantly:

| Term | Meaning |
| :--- | :--- |
| **DEX** | The compiled bytecode container inside the APK (`classes.dex`, sometimes several). |
| **Smali** | A human-readable, assembly-like representation of DEX bytecode. `apktool` disassembles an APK to smali so you can patch a check and reassemble it. |
| **IPC** | Inter-process communication — how apps and system services talk, mostly over **Binder**. Most Android-specific bugs live here. |

## Where this leads

Everything a pentester does maps back to these fundamentals:

- Reading the **manifest** tells you which sandbox holes the app opened (exported components, permissions, `debuggable`, `allowBackup`).
- **Static analysis** decompiles the DEX back to readable code to find secrets and logic.
- **Dynamic analysis** watches what the app writes to its sandbox and sends over IPC and the network.
- **Component exploitation** is just driving those exposed IPC endpoints from outside the sandbox.

Next: [APK structure &amp; signing](apk-structure.md), then the [app components](components.md) themselves.
