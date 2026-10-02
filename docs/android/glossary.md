---
title: "Glossary"
description: "Android penetration testing terms: components, attacks, tooling and platform concepts, in one table."
tags:
  - Android
  - Reference
---

# Glossary

Terms that come up repeatedly in Android testing — the platform components, the attack classes, and the tools. If a term in another page is unfamiliar, it is probably here.

| Term | Category | What it means |
| :--- | :--- | :--- |
| Activity | Component | A single UI screen. An exported activity (`android:exported="true"`) can be launched by any other app, which is the classic privilege escalation and auth-bypass vector |
| Activity hijacking | Attack | Registering a higher-priority intent filter to intercept implicit intents meant for another activity — OAuth callbacks are the usual target |
| ADB (Android Debug Bridge) | Tooling | Command line tool for talking to a device over USB or TCP. Shell access, file push and pull, logcat, backups and port forwarding all go through it |
| Android sandbox | Platform | Each app runs under its own Linux UID with its own data directory under `/data/data/`. Shared UIDs or world-readable files break that isolation |
| AndroidManifest.xml | Platform | The app's blueprint: permissions, components, exported flags, and the network security configuration. The first file to read, because misconfigurations here define the attack surface |
| APK | Platform | Android Package Kit — the installable `.apk` file. Decompiled with apktool or jadx to inspect code, resources and manifest |
| apktool | Tooling | Decodes APK resources and smali, and reassembles the APK after patching. Essential for manifest analysis and smali-level bypasses |
| Backup abuse | Attack | `android:allowBackup="true"` lets `adb backup` extract `/data/data` without root. Frequently overlooked, and it exposes databases and preferences |
| Binder | Platform | Android's inter-process communication mechanism. Used to call service methods that were not meant to be exposed |
| BroadcastReceiver | Component | Listens for system and app events. An exported receiver that accepts implicit intents can be triggered by any app on the device |
| Burp Suite | Tooling | HTTP/S interception proxy. Used with a system-store CA and a pinning bypass to capture and tamper with API traffic |
| Certificate pinning | Control | The app validates the server's certificate or public key rather than trusting any CA. It has to be bypassed (Frida, Objection, or a smali patch) before HTTPS is interceptable |
| Content provider injection | Attack | Sending crafted URIs or query strings to an exported ContentProvider to get SQL injection or path traversal |
| ContentProvider | Component | Exposes structured data through `content://` URIs. Misconfigured providers with no read permission leak databases or files to any app |
| Dalvik / ART | Platform | The Android runtimes that execute DEX bytecode. ART replaced Dalvik in Android 5. Understanding the bytecode helps with patching and instrumentation |
| Deeplink / intent hijacking | Attack | A malicious app registers the same URI scheme or implicit intent filter to steal data or launch sensitive flows |
| DEX | Platform | Dalvik executable — the compiled bytecode inside the APK. `dex2jar` converts it to a JAR for Java decompilation in jadx or JD-GUI |
| drozer | Tooling | Android security assessment framework. Tests IPC surfaces by running exploits against activities, providers and services over ADB |
| Dynamic analysis | Method | Running the app and observing it in real time: network traffic, file writes, IPC calls, method invocations via Frida or logcat |
| Frida | Tooling | Dynamic instrumentation toolkit. Injects JavaScript to hook Java and native methods at runtime — pinning, root checks, crypto, biometric prompts |
| Insecure data storage | Vulnerability | Sensitive data in SharedPreferences, SQLite or external storage without encryption. Check `/data/data/<package>/` after rooting or via ADB backup |
| Insecure logging | Vulnerability | Credentials, tokens or PII written to logcat, readable by any app with `READ_LOGS` or over ADB |
| Insecure WebView | Vulnerability | `setJavaScriptEnabled(true)` plus `loadUrl()` with attacker-controlled input gives XSS, and often local file read. Check `shouldOverrideUrlLoading()` as well |
| Intent | Component | Message object used to start components or pass data. Implicit intents and URI data are common injection and hijack targets |
| jadx | Tooling | Java decompiler for APK and DEX files. Produces near-original Java for code review, with a GUI (`jadx-gui`) and a CLI |
| JavaScript interface injection | Attack | `WebView.addJavascriptInterface()` exposes Java objects to JavaScript. XSS in the WebView can then call them, which was remote code execution on older Android versions |
| Keystore / Keychain | Platform | System APIs for storing cryptographic keys. Check whether keys are hardware-backed or extractable from a software keystore |
| Man-in-the-disk | Attack | An app using external storage without validating what it reads is open to data tampering by any other app that shares that storage |
| MITM proxy setup | Method | Intercepting HTTPS needs three things: the proxy CA in the device store (the system store from Android 7, which needs root), a configured proxy, and pinning bypassed |
| MobSF | Tooling | Mobile Security Framework — automated static and dynamic analysis of APKs, good for triage and a starting report |
| Objection | Tooling | Frida-based runtime exploration toolkit. Wraps the common tasks: SSL unpinning, root bypass, memory search, class enumeration |
| Permissions | Platform | `android:permission` attributes guard component access. Check for missing, custom or signature-level permissions on exported components |
| Reverse engineering | Method | Reconstructing app logic from bytecode and smali with jadx and apktool, and from native code with ghidra for `.so` libraries |
| Root detection | Control | The app looks for `su`, Magisk or busybox. Bypass with Frida hooks, MagiskHide/Shamiko, or by patching the smali |
| SELinux | Platform | Mandatory access control enforced by the kernel. Permissive mode — common on test ROMs — removes many restrictions, so note the mode you tested under |
| Service | Component | A background component. An exported service without a permission check can be invoked by a malicious app to trigger sensitive operations |
| Signature verification | Control | Android verifies APK signatures at install and update time. Bypassing or replacing keys — re-signing after patching — is required for testing modified builds |
| SMALI | Platform | Assembly-like representation of DEX bytecode. Patched to bypass root detection, certificate pinning and licence checks |
| Static analysis | Method | Analysing the APK without running it: decompiling, reading the manifest, searching for hardcoded secrets, reviewing code logic |
| Strandhogg | Attack | A task-affinity attack that hijacks the UI of a legitimate app by manipulating the Android task back-stack when it is launched |
| Tapjacking | Attack | An overlay attack that tricks the user into tapping hidden UI elements. Mitigated with `filterTouchesWhenObscured` |
| Weak cryptography | Vulnerability | ECB mode, MD5 or SHA1 for passwords, static IVs, hardcoded keys. Found by decompiling and searching for crypto API calls |
| Zygote | Platform | The parent process every app process forks from. Frida can attach here to instrument the app before its own code runs |

## A few quick checks

```bash
# Is SELinux enforcing on this device?
adb shell getenforce
# Enforcing = normal. Permissive = restrictions lifted, note it in the report

# Which UID is the app running as, and what groups does it hold?
adb shell ps -A -o USER,PID,NAME | grep <package_name>

# What device is this, and what Android version?
adb shell getprop ro.build.version.release
adb shell getprop ro.product.model
adb shell getprop ro.build.tags      # test-keys means a modified or test build
```
