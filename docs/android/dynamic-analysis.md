---
title: "Dynamic analysis"
description: "Running the app and watching it: insecure storage, SharedPreferences, temp files, external storage, root and emulator detection, and what certificate pinning looks like."
tags:
  - Android
  - Dynamic Analysis
  - Data Storage
  - SSL Pinning
---

# Dynamic analysis

Static analysis tells you what the app could do. Dynamic analysis tells you what it actually does — what it writes to disk, what it logs, what it sends, and which checks it fails when the environment is not what it expects.

Do this on a rooted device or an emulator with a snapshot you can roll back, because you will be pulling data, attaching Frida and rebooting.

## 1. Insecure data storage

Every app has a private directory, owned by its Linux UID. With root (or via `run-as` on a debuggable build) you can read all of it.

```text
/data/data/<package_name>/
├── databases/     SQLite databases — messages, tokens, cached API responses
├── shared_prefs/  XML preference files — session flags, saved credentials
├── files/         General purpose files — exports, downloads, logs
├── cache/         Temporary data — HTTP responses, images, thumbnails
└── lib/           Native libraries shipped with the app
```

```bash
# Copy the database to the host so you can work on it with a normal
# sqlite3 client instead of the limited on-device one
adb pull /data/data/<package>/databases/<db_name>

# Open it
sqlite3 name.db

# List the tables, then read the interesting ones. The query below asks
# SQLite's own schema table what objects of type "table" exist
SELECT name FROM sqlite_master WHERE type='table';
```

What makes this a finding: anything in those tables that should have been encrypted or not stored at all — tokens, session cookies, message bodies, location history, personal data. A plaintext copy on a rooted device is not a finding on its own; a plaintext copy on a device where the app also claims to encrypt data is.

## 2. SharedPreferences in plaintext

`SharedPreferences` is a simple key-value store that serialises to XML in `shared_prefs/`. Developers use it for settings and, far too often, for credentials and session tokens.

```bash
# Pull the whole directory
adb pull /data/data/<package_name>/shared_prefs

# Then read the XML. Look for keys that name a secret: token, password,
# session, api_key, auth, pin, jwt
cat ./shared_prefs/*.xml
```

```bash
# Flutter apps keep everything in one file, and it is worth checking directly
# because the app's own crypto is often just left off
adb shell "su -c 'cat /data/data/com.rozana.customer/shared_prefs/FlutterSharedPreferences.xml'"
```

## 3. Temporary files

Temp files are where half-finished sensitive data ends up: a token written before a redirect, an export written before it is encrypted, a debug dump nobody deleted.

```bash
# List the preferences and cache directories, looking for anything with a
# "tmp" or "cache" name that contains readable content
adb shell /data/data/<package>/shared_prefs/
adb shell ls -R /data/data/<package>/cache/

# Read a candidate file. If it holds credentials or tokens, that is the finding
cat users<id>tmp
```

## 4. External storage

External storage (`/sdcard/Android/data/<package>/`) is world-readable on older Android versions and is used by exactly the apps that should not use it. Two problems follow: data disclosure, and tampering — another app can modify what your app reads. That second one is the "man-in-the-disk" class of attack.

```bash
# Look for temp files, exports and caches under the shared storage path
adb shell ls -R /sdcard/Android/data/<package>/files/
adb shell ls -R /sdcard/Android/data/<package>/cache/
```

## 5. Root detection

Apps check for root to protect data or to enforce a policy. Knowing which check is in use tells you which bypass to use.

```bash
# Build tags. On Windows PowerShell, Select-String; on Linux or macOS, grep
adb shell getprop | grep -i "tags"
#   test-keys     custom or modified firmware — what a rooted/test ROM usually shows
#   release-keys  official stock ROM
#   dev-keys      development build or emulator

# Look for the root binaries themselves. su is the obvious one
adb shell which su

# busybox is not proof of root on its own, but it is common on rooted devices
adb shell which busybox
```

```bash
# The paths apps commonly check. If you are writing a bypass, these are the
# strings to match on:
#   /data/local/  /sbin/  /su/bin/  /system/bin/  /system/xbin/
#   /system/app/Superuser.apk  /cache  /data  /dev
#
# Modern root (Magisk) hides most of these, which is why the app also checks
# the environment: Magisk paths, mount state, package names, and the presence
# of a root manager app
```

## 6. Emulator detection

The same idea as root detection: does the device look like a real phone or like a test rig?

```text
# Values and strings apps look for:
#   generic, emulator, google_sdk, goldfish, ranchu, sdk_gphone
#   genymotion, memu, bluestacks, nox, vbox, virtualbox
```

```bash
# Native libraries often hold the detection strings, since they are harder
# to read than Java. -i makes the grep case-insensitive
strings "lib/arm64-v8a/libURLConst.so" | grep -iE "goldfish|generic|sdk|genymotion|memu|bluestacks|nox"
```

Bypassing these usually means hooking one method and returning `false` — the pattern is on the [Frida](frida.md) page.

## 7. Certificate pinning

Pinning is the app refusing to trust any CA except the one it expects. The app compares the server's certificate, or its public key, against a value baked into the app or fetched at build time. If the values do not match, the connection is rejected before any HTTP happens.

This is why a perfectly installed Burp CA still produces no traffic: browsers use the system trust store, apps with pinning do not.

```text
# Where pinning lives in a decompiled app:
#   CertificatePinner           OkHttp's built-in pin check
#   TrustManager / X509TrustManager   custom trust logic
#   HostnameVerifier            hostname checks done by hand
#   SSLSocketFactory            low-level TLS setup
#   network_security_config     <pin> entries in the manifest-linked XML
#
# If the app pins a public key hash (SPKI), changing the server certificate
# breaks the app — which is the point of pinning.
```

```bash
# What a pinning failure looks like in the logs. These three strings are the
# ones to search for when traffic stops
adb logcat | grep -iE "Trust anchor for certification path not found|SSLPeerUnverifiedException|Certificate pinning failure"
```

Eight ways to get around it — iptables redirection, patching the hardcoded hash, editing the manifest, reFlutter for Flutter apps, swapping the pinned certificate, Objection, Frida scripts, and smali patching — are on the [testing checklist](checklist.md#1-ssl-pinning-bypass).

## What to do with what you find

For each item, the write-up needs three things: the exact data, the exact command that produced it, and the impact. "Tokens are stored in plaintext and readable by anyone with a rooted device or a backup" is a finding. "The database is unencrypted" is a note to self.

Next: the [testing checklist](checklist.md) for the full list of checks, or [Frida](frida.md) if you need to hook something right now.
