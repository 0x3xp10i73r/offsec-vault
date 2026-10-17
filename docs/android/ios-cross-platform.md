---
title: "iOS and cross-platform apps"
description: "iOS and cross-platform mobile testing: device setup, Frida injections, jailbreak detection, keychain and storage review."
tags:
  - Mobile
  - Android
  - iOS
  - Frida
  - Reverse Engineering
---

# iOS and cross-platform apps

!!! note "What this page is doing"
    Mobile frameworks move security decisions into different runtimes. Identify the platform and framework first, follow the data and trust boundary, and keep patched binaries, certificates and device changes inside the lab evidence set.

---

## 1. Lab Setup

=== " Android"

    ```bash
    # --- Emulator / device preparation ---
    # A rooted emulator (Google APIs, x86_64) or a physical rooted device
    adb devices
    adb shell getprop ro.build.version.release # Android version
    adb shell su -c id # Confirm root
    # --- Core tools ---
    # Magisk (root) + Zygisk + LSPosed modules (Shamiko, HideMyApplist)
    # Frida server (matching your frida-tools version):
    adb push frida-server-<VER>-android-x86_64 /data/local/tmp/frida-server
    adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
    adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042 &'"
    frida-ps -U # Confirm the connection
    # --- Static analysis ---
    apktool d target.apk -o target_decoded # Resources + smali
    jadx-gui target.apk # Java decompilation (best for reading logic)
    unzip -o target.apk -d target_apk # Raw contents (libs, assets, META-INF)
    # MobSF (automated static + dynamic analysis):
    # docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
    ```

=== " iOS"

    ```bash
    # --- Prerequisites: a jailbroken device (checkra1n / Dopamine / unc0ver) + Frida ---
    frida-ps -Uai # List installed apps (with bundle IDs)
    # Decrypt IPA from the device (encrypted binaries must be dumped in-memory):
    # frida-ios-dump -o ./decrypted -u <BUNDLE_ID>
    # or bagbak / Clutch
    # --- Static analysis ---
    # Hopper / IDA / Ghidra for the Mach-O binary
    # class-dump / dsdump for Objective-C headers
    # otool -L binary (linked libraries) | strings -a binary | grep -i http
    # plutil -p Info.plist (URL schemes, background modes, ATS config)
    # MobSF also supports IPA analysis.
    ```

---

## 2. Frida Universal SSL Pinning & Root Bypass

```javascript
// ===== frida_bypass.js — universal Android SSL pinning + root/jailbreak detection bypass =====
// Usage: frida -U -f <PACKAGE_NAME> -l frida_bypass.js --no-pause

Java.perform(function () {
  console.log("[*] 0x3xp10i73r universal bypass script loaded");

  // ---------- 1. TRUST MANAGER / OKHTTP PINNING ----------
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
      name: 'com.bypass.TrustManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    SSLContext_init.implementation = function (km, tm, sr) {
      console.log("[+] SSLContext.init() hooked -> using permissive TrustManager");
      SSLContext_init.call(this, km, TrustManagers, sr);
    };
  } catch (e) { console.log("[-] TrustManager hook failed: " + e); }

  // ---------- 2. OKHTTP3 CERTIFICATE PINNER ----------
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
      console.log("[+] OkHttp3 CertificatePinner.check() bypassed for: " + arguments[0]);
      return;
    };
  } catch (e) {}

  // ---------- 3. NETWORK SECURITY CONFIG / CONSCRYPT ----------
  try {
    var Platform = Java.use('com.android.org.conscrypt.Platform');
    Platform.checkServerTrusted.implementation = function () { return; };
  } catch (e) {}
  try {
    var HostnameVerifier = Java.use('javax.net.ssl.HttpsURLConnection');
    // Hook custom hostname verifiers if the app defines one
  } catch (e) {}

  // ---------- 4. ROOT / EMULATOR / DEBUGGER DETECTION ----------
  var rootIndicators = ['su', 'magisk', 'superuser', 'busybox', '/system/xbin/su', 'test-keys'];
  try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < rootIndicators.length; i++) {
        if (path.toLowerCase().indexOf(rootIndicators[i]) !== -1) {
          console.log("[+] Hiding root indicator: " + path);
          return false;
        }
      }
      return this.exists();
    };
  } catch (e) {}

  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
        console.log("[+] Blocking detection command: " + cmd);
        return null;
      }
      return this.exec(cmd);
    };
  } catch (e) {}

  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = "release-keys";
  } catch (e) {}

  // ---------- 5. FLUTTER / REACT NATIVE NOTE ----------
  // Flutter uses BoringSSL natively -> hook with frida-gadget + the "disable-flutter-tls-verification"
  // patcher, or hook nativessl / BoringSSL symbols. React Native typically uses OkHttp (covered above).
  console.log("[*] Hook installation complete.");
});
```

```bash
# --- Quick run ---
frida -U -f com.target.app -l frida_bypass.js --no-pause
# --- Or with Objection (spawn + patch in one go) ---
objection -g com.target.app explore --startup-command "android sslpinning disable"
objection -g com.target.app explore --startup-command "android root disable"
# --- iOS equivalent ---
objection -g com.target.app explore --startup-command "ios sslpinning disable"
```

---

## 3. Android

Android has its own section: [Android](index.md) covers device setup, traffic interception, static
and dynamic analysis, the full [testing checklist](checklist.md) and [Frida](frida.md).

Two commands from the old one-page version are still worth keeping here, because they answer
"what does the manifest say" in one line:

```bash
# Print the decoded manifest without unpacking the APK
apkanalyzer manifest print target.apk

# Read the flags that decide most of the attack surface from the installed package
adb shell dumpsys package com.target.app | grep -iE "debuggable|allowBackup|exported"
```

---

## 4. iOS testing checklist

```bash
# ---------- STORAGE & FILE SYSTEM ----------
# On a jailbroken device:
find /var/mobile/Containers/Data/Application/<UUID>/ -type f 2>/dev/null | head -50
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/*.plist
sqlite3 /var/mobile/Containers/Data/Application/<UUID>/Library/.../app.db
# Keychain extraction (the juicy stuff):
# objection -g <BUNDLE_ID> explore -> ios keychain dump
# frida -U -f <BUNDLE_ID> -l keychain_dump.js
# ---------- URI SCHEMES & UNIVERSAL LINKS ----------
plutil -p Payload/App.app/Info.plist | grep -A 20 "CFBundleURLSchemes"
# Test every scheme for unvalidated parameters -> deep-link hijack, token leak, WebView RCE
xcrun simctl openurl booted "targetapp://admin?action=delete"
# ---------- BINARY PROTECTIONS (evaluate) ----------
otool -hv binary # PIE flag
otool -l binary | grep -A 4 LC_ENCRYPTION_INFO # Cryptid (1 = encrypted)
# Check for: Stack canary, ARC, PIE, anti-debugging (ptrace PT_DENY_ATTACH),
# jailbreak detection, ATS configuration (NSAppTransportSecurity)
# ---------- ATS / TLS ----------
plutil -p Info.plist | grep -A 10 NSAppTransportSecurity
# NSAllowsArbitraryLoads = true -> cleartext allowed -> MITM opportunity
plutil -p Info.plist | grep -A 5 NSExceptionDomains
```

---

## 5. Common High-Impact Mobile Findings

| Finding | Impact | How to Demonstrate |
| :--- | :--- | :--- |
| **Hardcoded API keys / secrets in the binary** | Full backend access, cloud takeover | `strings`, grep on assets, Firebase keys → enumerate the backend |
| **Insecure local storage (SharedPreferences / Keychain / SQLite)** | Token theft on device/backup | Root/jailbreak + dump; check `allowBackup`/backup exports |
| **SSL pinning absent + cleartext traffic** | Credential/token interception on a hostile network | Frida bypass (if pinned) or mitmproxy with a system CA |
| **Exported components with no permission** | Auth bypass, arbitrary data access, RCE via WebView | `adb am start` / `content query` |
| **Deep link / URL scheme abuse** | Account takeover via token leak, admin action trigger | Craft an intent with an attacker-controlled parameter |
| **Unvalidated WebView + JS bridge** | RCE in the app context, credential theft | `@JavascriptInterface` methods reachable from a loaded URL |
| **Weak biometric implementation** | Auth bypass (Frida return true) | Hook `onAuthenticationSucceeded` / `evaluatePolicy` callback |
| **Root/jailbreak detection only client-side** | Trivial bypass → all protections void | Hook the detection routine |
| **Missing certificate / integrity pinning on API calls** | Tampering, replay, fraud | Replay requests with modified bodies |
| **Debug/verbose logging enabled in production** | Sensitive data into device logs / third parties | `adb logcat` / Console.app during usage |
| **Firebase/backend rules misconfigured** | Full database read/write | Query the Firebase REST API without auth |

!!! tip "Mobile Testing Workflow"
    1. **Static first** — MobSF + jadx/class-dump; find endpoints, secrets, exported components.
    2. **Then dynamic** — Frida bypass → proxy all traffic through mitmproxy/Burp → map the API.
    3. **Then API abuse** — the mobile API is usually the least-protected surface (no WAF, no
       rate limiting, older version endpoints still live, verbose error messages). Test it with
       the same rigor as a web app: IDOR, mass assignment, and broken authz are everywhere.
    4. **Report with evidence** — video PoC + exact commands + the specific security control missing.