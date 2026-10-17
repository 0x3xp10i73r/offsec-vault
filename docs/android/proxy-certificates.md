---
title: "Intercepting traffic"
description: "Installing a Burp CA into the Android system store on a rooted device, configuring the proxy, and the reasons HTTPS interception fails."
tags:
  - Android
  - Burp Suite
  - TLS
  - Certificate Pinning
---

# Intercepting traffic

!!! note "What this page is doing"
    Traffic interception is a trust-chain exercise: the device must reach the proxy, the app must trust the test CA, and pinning must be handled separately. Change one layer at a time and restore the proxy and certificate state when finished.

Before any application testing, get HTTPS traffic into Burp. On Android this has three parts: a CA the app will accept, a proxy the device sends traffic to, and — usually — a pinning bypass.

## Why the certificate has to go in the system store

Android splits its CA store in two:

- **User store** — certificates you install through Settings. Apps on Android 7 (API 24) and later ignore this store by default, because `targetSdkVersion >= 24` opts the app into trusting only system CAs. A freshly installed Burp certificate therefore does nothing for the app you are testing, even though the browser is happy.
- **System store** — `/system/etc/security/cacerts/`. Trusted by every app. Writing to it needs root, because `/system` is mounted read-only.

That is the whole reason the procedure below exists. Two alternatives when you cannot root the device: build a patched APK with `networkSecurityConfig` set to trust user certificates, or use Frida to unpin — both are covered on the [checklist](checklist.md) page.

## Step 1 — Log in to the phone, set the proxy, run a request

Start from a request you can repeat. Everything below is written for a rooted Xiaomi Redmi Note 5 Pro (`whyred`) as the example device.

```bash
# =====================================================================
# Burp Suite System CA install on rooted Android
# Target: Xiaomi Redmi Note 5 Pro (whyred)
# =====================================================================

# [1] Convert the Burp certificate from DER to PEM.
#     Export it first: Burp -> Proxy -> Options -> Export CA Certificate -> DER format
openssl x509 -inform DER -in ~/Downloads/burp -out burp.pem

# [2] Ask OpenSSL for the subject hash. Android names CA files after this
#     hash, so the name has to be generated, not invented.
#     -subject_hash_old is required: Android uses the old MD5-based hash
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1
# Example output: 9a5ba575

# [3] Rename the certificate to <hash>.0 — Android only loads files
#     ending in .0 and expects the hash as the file name
cp burp.pem 9a5ba575.0     # replace 9a5ba575 with the hash from step 2

# [4] Push the renamed certificate to the device's shared storage
adb push 9a5ba575.0 /sdcard/
```

## Step 2 — Move it into the system store

```bash
# [5] Get a shell, then root. "su" lands you in a root shell on the device
adb shell
su

# [6] Remount the filesystem read-write.
#     Note: on Android 10+ the layout is system-as-root, so /system is not a
#     separate entry in /proc/mounts — remount "/" instead of "/system"
mount -o rw,remount /

# [7] Copy the certificate into the system CA store and set the permissions
#     Android expects: readable by everyone, writable only by the owner
cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/9a5ba575.0

# [8] Put the filesystem back to read-only. Good habit: leaving it writable
#     makes the device behave differently from a normal one
mount -o ro,remount /

# [9] Reboot so the trust store is reloaded
reboot

# [10] After the reboot, confirm the certificate is where it should be
adb shell ls /system/etc/security/cacerts/ | grep 9a5ba575
# Expected output: 9a5ba575.0
```

On Android 14 and later the runtime CA store lives under `/apex/com.android.conscrypt/cacerts`, which is not writable in the same way. There, use a Magisk module that mounts the certificate into the store (or fall back to a Frida unpinning script) instead of copying the file.

## Step 3 — Point the device at Burp

```bash
# [11] Get the host machine's IP on macOS — this is what the phone will proxy to
ipconfig getifaddr en0

# [12] On the phone:
#      Settings -> Wi-Fi -> long press the network -> Modify
#      -> Advanced -> Proxy -> Manual
#        Hostname: <the host IP from step 11>
#        Port:     8080
#
# [13] In Burp Suite on the host:
#      Proxy -> Options -> Proxy Listeners
#      -> bind to All Interfaces (0.0.0.0:8080)
```

The same certificate steps on Windows differ only in the file paths:

```bash
# [1] Convert DER to PEM
openssl x509 -inform DER -in C:\Users\YourUser\Downloads\burp -out burp.pem

# [2] Get the hash Android will look for
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1

# [3] Rename to <hash>.0 (copy replaces cp on Windows)
copy burp.pem 9a5ba575.0

# [4] Push to the device
adb push 9a5ba575.0 /sdcard/
```

## Setting the proxy from ADB

The Settings menu is fine for a phone you are holding. On an emulator, or when you are scripting a rebuild-and-retest loop, ADB is quicker and repeatable.

```bash
# Set the global HTTP proxy. Traffic from apps that honour the system proxy
# goes through this address
adb shell settings put global http_proxy <ip>:<port>

# Clear the proxy — shorthand for "port 0", which disables it
adb shell settings put global http_proxy :0

# Clear it properly: delete all three keys that make up the setting
adb shell settings delete global http_proxy
adb shell settings delete global global_http_proxy_host
adb shell settings delete global global_http_proxy_port
```

Apps using OkHttp, HttpURLConnection and most networking stacks follow the system proxy. Apps with their own stack, or with certificate pinning, will not — those are the ones that need the bypasses on the [checklist](checklist.md).

## Burp with MobSF in Docker

```bash
# Start MobSF; the dynamic analyser needs the host's port 8000 free
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Point the device at Burp from ADB
adb shell settings put global http_proxy 10.10.10.117:8080

# Certificate: download it from Burp, convert .der to .cer, install on the
# device, then check Settings -> Security -> Trusted Credentials to confirm
```

## When traffic still does not appear

| Symptom | Likely cause |
| :--- | :--- |
| Browser works, app does not | The app targets API 24+ and ignores the user store — install to the system store, or patch `networkSecurityConfig` |
| `Trust anchor for certification path not found` | The CA is not trusted by the app. Same fix as above |
| `SSLPeerUnverifiedException` | Certificate pinning. The app is checking the server's key or certificate, not just the CA — needs a Frida hook or a smali patch |
| `Certificate pinning failure` in logcat | Pinning, and it is telling you which class to hook |
| Nothing at all in Burp | The proxy is not set, the phone is on mobile data instead of Wi-Fi, or the listener is bound to loopback only |
| Traffic only from some endpoints | Some SDKs ship their own networking stack; check with `adb shell dumpsys connectivity` or Frida-trace the socket calls |

```bash
# Quick look at what the app is complaining about
adb logcat | grep -iE "trust anchor|pinning|SSLPeerUnverified|Certificate"
```
