---
title: "APK structure & signing"
description: "What an APK actually contains — manifest, DEX, resources, native libraries — the smali/DEX layer, and why APK signing blocks tampering."
tags:
  - Android
  - Fundamentals
  - APK
  - Reversing
---

# APK structure & signing

An **APK** (Android Package) is the file you install. It is just a **ZIP archive** with a fixed internal layout — you can `unzip` it. Knowing what each part holds tells you where to look for secrets, logic and misconfiguration.

## Inside an APK

| Path | Contents | Why it matters to a tester |
| :--- | :--- | :--- |
| `AndroidManifest.xml` | App metadata, permissions, declared components | **The first file to read.** Exported components, dangerous flags and the attack surface are declared here. (Binary XML — decode with `apktool`.) |
| `classes.dex` | Compiled app code (Dalvik bytecode) | The logic you decompile with JADX. Large apps have `classes2.dex`, `classes3.dex`… |
| `resources.arsc` | Compiled resource table | Maps resource IDs to values — strings, layouts, arrays. |
| `res/` | Layouts, images, `strings.xml` | Where hardcoded URLs, keys and secrets often hide. |
| `assets/` | Raw bundled files | Config, seed databases, and the **JavaScript bundle** for hybrid/cross-platform apps (`assets/www/`, `index.android.bundle`). |
| `lib/` | Native `.so` libraries, one folder per ABI | C/C++ code — often where crypto, keys and detection logic live. |
| `META-INF/` | Signature files (`MANIFEST.MF`, `.SF`, `.RSA`/`.EC`) | The APK signature, verified at install and update. |

```bash
# Peek at the raw layout without decoding anything
unzip -l app.apk | head

# Decode resources, manifest and smali into a readable tree
apktool d app.apk -o app_decoded

# Decompile the DEX back to readable Java for code review
jadx -d app_src app.apk
```

## DEX and smali

App code ships as **DEX** (Dalvik Executable) bytecode, not Java `.class` files. Two views matter:

- **Decompiled Java (JADX / dex2jar + JD-GUI)** — readable, best for *understanding* logic, secrets and flows. It can be lossy or fail on obfuscated apps.
- **Smali (apktool)** — a faithful, assembly-like representation of the exact bytecode. This is what you **edit** when you want to patch a check (a root check, a pinning check, a license test) in an app you cannot rebuild from source. After editing smali, `apktool b` rebuilds the APK.

```smali
# A smali method that returns a boolean — flip 0x0/0x1 to invert a check
.method public isDeviceRooted()Z
    .locals 1
    const/4 v0, 0x0      # change to 0x1 to force "rooted = true", etc.
    return v0
.end method
```

!!! tip "Pick the right view"
    Read in **JADX**, patch in **smali**. Trying to understand logic from smali is slow; trying to reliably patch from decompiled Java is error-prone because it may not recompile.

## APK signing — and why it stops you

Every APK is **signed**. The developer signs it with a private key and ships the matching public certificate inside `META-INF/`. Android verifies that signature at install and at every update.

This has two consequences for testing:

1. **You cannot just edit and reinstall.** The moment you change anything — patch smali, swap the Burp CA into `res/xml/network_security_config.xml`, remove a flag — the original signature no longer matches and the install is **rejected**. So every patch-and-rebuild workflow ends by **re-signing** with a key *you* control:

    ```bash
    apktool b app_decoded -o app_patched.apk
    # Zipalign, then sign with your own key (uber-apk-signer wraps both)
    java -jar uber-apk-signer.jar -a app_patched.apk
    adb install app_patched.apk-aligned-signed.apk
    ```

2. **An app can check its own signature.** A hardened app reads its own signing certificate at runtime and refuses to run if it does not match the expected one — defeating a naive re-sign. That integrity check is a *separate* control from the OS signature check, and bypassing it (usually by hooking the check with Frida) is its own task.

Signature schemes have evolved — **v1 (JAR)**, **v2**, **v3** and **v4**. Modern Android requires at least v2; `apksigner verify -v app.apk` shows which schemes an APK uses.

## Where this leads

The APK is the raw material for the two halves of the assessment: [static analysis](static-analysis.md) reads the decoded manifest, DEX and resources for secrets and logic, and the patch-and-resign workflow above is what lets you defeat client-side checks during [dynamic analysis](dynamic-analysis.md).

Next: the [app components](components.md) declared in that manifest.
