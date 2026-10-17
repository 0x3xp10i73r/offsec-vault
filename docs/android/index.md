---
title: "Android"
description: "Android application penetration testing: APK internals, static and dynamic analysis, traffic interception, Frida and the full testing checklist."
tags:
  - Android
  - Mobile
  - Static Analysis
  - Dynamic Analysis
  - Frida
---

# Android penetration testing

Notes from testing Android applications: what an APK is made of, how to pull one apart, how to watch what it does at runtime, and what to look for at each step. Everything here assumes the app is in scope and that you have written permission, or that it is your own lab build.

The workflow the pages follow is always the same shape:

1. Get the APK and the device or emulator set up.
2. Get traffic flowing through Burp, which usually means installing a CA in the system store because user certificates are not trusted by apps on Android 7 and later.
3. Read the app statically — manifest, decompiled Java, smali, native libraries, resources.
4. Run it and watch it — storage, logs, memory, IPC, network.
5. Compare the client behavior with the server behavior and prove the finding with a controlled test, not a code smell.
6. Reset the snapshot, remove certificates and test data, and write down the exact app/device/tool versions.

## What an Android assessment is trying to prove

| Question | What to inspect | Useful evidence |
| :--- | :--- | :--- |
| **What can the app reach?** | Manifest, permissions, endpoints, exported components, deep links and SDKs | Component/permission inventory and a baseline request |
| **What does the app trust?** | TLS, certificate pinning, signing certificate, local flags, WebView origins and server responses | Trust decision, failure log and controlled bypass result |
| **What does it store?** | Preferences, databases, cache, external storage, logs, backups and memory | Minimal canary record and access conditions |
| **What does the server enforce?** | API authentication, object authorization, replay, rate limits and tenant boundaries | Request/response comparison from two test states |
| **Can a local component be abused?** | Activities, services, receivers, providers, intents and bridges | Reproducible component call and observed side effect |

A rooted device or emulator helps you inspect the client; it does not make client-side authorization a valid security boundary. If changing a local flag unlocks a feature, continue testing the server and report the missing server-side control when it affects real data or actions.

## OWASP Mobile Top 10

The list below is the OWASP Mobile Top 10 for Android, with what each class actually looks like on a real target.

| # | Vulnerability | What it looks like in practice |
| :--- | :--- | :--- |
| 1 | Improper credential usage | Passwords or API keys in plaintext in `SharedPreferences`, hardcoded in code, or sent over a weak authentication flow |
| 2 | Inadequate supply chain security | Third-party SDKs, ad libraries or build dependencies that ship their own bugs, telemetry or hardcoded keys |
| 3 | Insecure authentication and authorisation | Weak session handling, client-side authorisation checks, login state trusted from a local flag |
| 4 | Insufficient input and output validation | Injection through intents, deep links, content providers or WebView bridges |
| 5 | Insecure communication | Cleartext HTTP, no certificate pinning, TLS misconfiguration |
| 6 | Inadequate privacy controls | Sensitive data in logs, analytics SDKs receiving more than they should, missing consent |
| 7 | Insufficient binary protections | The APK reverses trivially, no obfuscation, no integrity checking, no root detection |
| 8 | Security misconfiguration | `debuggable`, `allowBackup`, exported components, risky `usesCleartextTraffic` |
| 9 | Insecure data storage | Tokens, messages or PII sitting in SQLite, XML preferences, caches or external storage |
| 10 | Insufficient cryptography | ECB mode, MD5/SHA1, static IVs, keys derived from constants or stored next to the ciphertext |

## App types, and why it changes the approach

| Type | Built with | What it means when testing |
| :--- | :--- | :--- |
| Native | Java or Kotlin for Android; Swift or Objective-C for iOS | Full hardware access, and the code you decompile is the code that runs. The straightforward case |
| Cross-platform | One codebase, multiple targets — Flutter, React Native, .NET MAUI | The Java layer is a shell. Real logic lives in Dart or JavaScript, and the networking stack often ignores the system proxy, so traffic work needs reFlutter or a bundle-specific approach |
| Hybrid | HTML, CSS and JavaScript in a native container — Cordova, Ionic | The app is a web app. Look at `assets/www/`, and expect web-class bugs (XSS, insecure storage in the browser layer) with native permissions attached |

Picking the wrong tool for the type is the most common way to waste an hour: `grep` over decompiled Java finds nothing in a Flutter app because there is nothing there to find.

## How an Android app is built and run

An APK is a ZIP file with a fixed layout, and the code inside it is not Java bytecode. Knowing the pipeline is what makes the tooling make sense.

Compilation flow: Java or Kotlin source is compiled to `.class` files, then run through D8/R8 to produce `.dex` (Dalvik executable) bytecode, which runs on the Android Runtime.

| Term | Meaning |
| :--- | :--- |
| Smali | Assembly-like representation of Dalvik bytecode. Tools like `apktool` disassemble an APK to smali and reassemble it after editing, which is how you patch a check in an app you cannot rebuild from source |
| DVM (Dalvik Virtual Machine) | The original process VM that ran Android apps. Register-based, designed for constrained devices |
| ART (Android Runtime) | Replaced Dalvik in Android 5. Ahead-of-time and later just-in-time/partially compiled, and the default runtime on every modern device. Frida and other instrumentation attach to ART |
| JADX | Decompiler that turns an APK or a `.dex` file back into readable Java for code review |
| dex2jar | Converts an APK or `.dex` to a JAR so another Java decompiler (JD-GUI) can open it |
| APKTool | Decodes resources, the manifest and smali, and rebuilds the APK afterwards |
| IPC | Inter-process communication. The channel apps use to talk to each other and to system services, mostly over Binder. Most Android-specific bugs live here |
| DEX | The compiled bytecode container inside the APK, usually one or more `classes.dex` files |

### APK structure

| Path | Contents | Why it matters |
| :--- | :--- | :--- |
| `AndroidManifest.xml` | App info, permissions, declared components | First file to read. Exported components and dangerous attributes live here |
| `META-INF/` | Signature files (`MANIFEST.MF`, `.SF`, `.RSA`) | Used to verify the APK at install and update time |
| `classes.dex` | Compiled code | The app logic you decompile |
| `resources.arsc` | Compiled resource table | Maps resource IDs to values — strings, layouts, arrays |
| `res/` | Layouts, images, string XML | Where hardcoded keys and URLs often hide |
| `assets/` | Raw extra files | Bundled JavaScript for hybrid apps, config, seed databases |
| `lib/` | Native `.so` libraries per ABI | C/C++ code, often where crypto and key material live |

### APK signing, and why it stops you

The developer signs the APK with a private key and ships the matching public certificate inside it. Android verifies that signature at install and update time. If you modify the APK — patch smali, swap a certificate, remove `networkSecurityConfig` — the signature breaks and the install fails. That is why every patch-and-rebuild workflow ends with re-signing using a key you control (see [Tools and references](tools.md)), and why an app that checks its own signing certificate is a separate problem from an app that does not.

## Android architecture

| Layer | What runs there |
| :--- | :--- |
| 1. Kernel | Linux kernel, drivers, SELinux enforcement, the sandbox primitives (UIDs, namespaces) |
| 2. Libraries and Android Runtime | Native libraries (Bionic, media, SSL) plus ART/DVM — the translation layer between the kernel and the framework |
| 3. Application framework | The Java APIs apps are built on: activity manager, package manager, content providers, system services |
| 4. Applications | The apps themselves, each in its own sandboxed process |

## Core components

| Component | What it is | Attack angle |
| :--- | :--- | :--- |
| Activity | A single UI screen | An exported activity (`android:exported="true"`) can be launched by any other app. Classic authentication bypass when the screen behind login is reachable directly |
| Service | Long-running background task, started and stopped explicitly | An exported service with no permission check can be invoked by any app to trigger privileged work |
| BroadcastReceiver | Listens for system or app events | An exported receiver that accepts implicit broadcasts can be triggered by anything on the device |
| ContentProvider | Structured data sharing through `content://` URIs with `insert`, `query`, `update`, `delete` | Missing read/write permissions leak whole databases; string-built queries give SQL injection |
| ContentResolver | The client side that requests data from a provider | The handle you use from an app or from `adb shell content` |
| Intent | Message object that asks another component to do something | Implicit intents and attacker-controlled extras are the usual injection and hijack vectors |
| Explicit intent | Names the exact component and package | Internal to the app — lower risk, still worth checking for redirection bugs |
| Implicit intent | Describes an action, lets the system choose the handler | Multiple apps can claim it. This is how intent hijacking and Strandhogg-style attacks work |
| Intent resolution | The process that decides which component handles an implicit intent | Priority in the intent filter decides the winner — a malicious app can register higher priority than the legitimate one |

## Manifest attributes worth reading first

| Attribute | Meaning | Risk when set |
| :--- | :--- | :--- |
| `android:compileSdkVersion` | API level the app was built against | Older targets miss newer platform protections |
| `android:debuggable="true"` | A debugger may attach to the process | Any app or ADB user with the right setup can inspect memory and bypass checks |
| `android:allowBackup="true"` | The OS may back up app data | `adb backup` can extract the app's private data without root |
| `android:networkSecurityConfig` | Points at an XML file with network rules | Often used to allow cleartext, or to pin certificates, in one place |
| `android:extractNativeLibs` | Whether `.so` files are unpacked at install or loaded from the APK | Affects how you patch native libraries |
| `android:appComponentFactory` | Custom class used to instantiate components | Rare, but a hook point for instrumentation |
| `uses-permission` | Permissions the app requests | Normal permissions are granted automatically; dangerous ones prompt the user |
| `queries` | Which other packages the app may interact with | Shows what the app expects to talk to on the device |

## Pages in this section

- **[Setup and ADB](setup-adb.md)** — device, emulator, ADB, wireless ADB, package handling, MobSF.
- **[Intercepting traffic](proxy-certificates.md)** — Burp CA into the system store on a rooted device, proxy configuration, and what breaks on Android 7 and later.
- **[Static analysis](static-analysis.md)** — hardcoded secrets, weak crypto, hybrid app bundles, obfuscation, native libraries, backup and debuggable flags, Firebase.
- **[Dynamic analysis](dynamic-analysis.md)** — insecure storage, root and emulator detection, pinning signals, logs and memory.
- **[Testing checklist](checklist.md)** — the working list, from pinning bypass to biometric bypass, with the command that proves each one.
- **[Frida](frida.md)** — server setup, hook template, tracing, codeshare scripts, biometric hooks.
- **[Glossary](glossary.md)** — Android and tooling terms in one place.
- **[Tools and references](tools.md)** — the tool table, misc commands and sources.
- **[iOS and cross-platform apps](ios-cross-platform.md)** — the same discipline applied to iOS, plus Flutter, React Native and Cordova targets.
