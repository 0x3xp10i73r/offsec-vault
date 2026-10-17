---
title: "Static analysis"
description: "Reading an APK without running it: hardcoded secrets, weak cryptography, hybrid app bundles, obfuscation, native libraries, backup and debuggable flags, Firebase and permissions."
tags:
  - Android
  - Static Analysis
  - Reverse Engineering
  - Cryptography
---

# Static analysis

!!! note "What this page is doing"
    Static analysis answers what the APK can do and where its trust assumptions live. Start with the manifest and resources, identify the app architecture, then follow a secret, permission, parser or endpoint to its runtime use before calling it a finding.

Static analysis means reading the APK without running it: the manifest, the decompiled Java, the smali, the resources and the native libraries. It is where you find most of the quick wins, and it is where you work out what to attack once the app is running.

The order below is roughly the order I go in — cheap greps first, then the parts that need reading.

## 1. Hardcoded strings

The highest-value thing in most APKs is a string that should not be there: an API key, an internal hostname, a basic-auth credential, a debug endpoint.

What to look for:

| Target | Why it matters |
| :--- | :--- |
| API keys | Often unauthenticated or scoped wider than the app needs |
| Database credentials | Direct backend access if the service is reachable |
| OAuth tokens | Long-lived access to a user or a tenant |
| Cryptographic keys | Decrypts anything else you find |
| Hardcoded passwords or passphrases | Internal admin panels, keystores |
| PII | Sample data or fixtures shipped by accident |
| Internal URLs and IPs | Staging and admin systems that are usually weaker than production |
| Debug flags and verbose logging paths | Extra functionality that is off in the UI but on in code |

```bash
# Decode the APK: resources, manifest and smali land in ./myapp
apktool d myapp.apk

# -R walks the tree, -n shows line numbers, -w matches whole words.
# Start with the words that pay: password, secret, key, token, api
grep -Rnw './myapp' -e 'password'
grep -Rnw './myapp' -e 'api_key'

# Smali is where the code actually went. List the classes first, then read
# the ones that look interesting (auth, network, config, crypto)
ls -l ./myapp/smali/com/example/myapplication/
cat ./myapp/smali/com/example/myapplication/MainActivity\$2.smali

# Resources hold values the developers wanted to keep out of code but left
# readable anyway: strings.xml, arrays, and the network security config
cat ./myapp/res/values/strings.xml
cat ./myapp/res/xml/network_security_config.xml
```

Reading `strings.xml` is worth doing early. It is also where the crypto keys from the next section live.

## 2. Bad cryptography

Cryptography in mobile apps fails in four predictable ways:

1. Outdated algorithms — DES, RC4, MD5, SHA1, ECB mode.
2. Hardcoded keys — the key is a constant in the APK.
3. Improper key storage — the key sits next to the ciphertext, or in `SharedPreferences` in cleartext.
4. Insecure randomness — `java.util.Random` used to generate keys, IVs or one-time codes, or a hardcoded seed.

If the key and the IV are both in the APK, the encryption is decoration: you can reproduce the decryption offline.

```bash
# Find the crypto calls in the decompiled code
grep -Rnw . -e 'AES' -e 'DES' -e 'SecretKeySpec' -e 'IvParameterSpec'

# Look for the constants themselves
grep -Rni -e 'key' -e 'iv' -e 'seed' ./myapp/res/values/strings.xml
```

### Worked example: an encrypted chat app

This one comes from a lab target (`com.hackthebox.chatapp`). It is a useful template because the whole chain — install, list data, pull the database, read it, then find the key in the APK — is the same on a real engagement.

```bash
# Install the lab APK from the host and confirm the package identifier.
adb install <path-to-apk>
adb shell pm list packages | grep chatapp

# Read the lab app's private directory through a rooted test device.
# The package UID normally prevents this without root or a debuggable build.
adb shell su -c 'ls -la /data/data/com.hackthebox.chatapp/'
adb shell su -c 'ls -la /data/data/com.hackthebox.chatapp/databases/'

# Copy only the lab database to shared storage, then pull it to the host.
adb shell su -c 'cp /data/data/com.hackthebox.chatapp/databases/messages.db /sdcard/'
adb pull /sdcard/messages.db ./messages.db
```

The device commands show the data location; they do not prove that the data is protected. Open the pulled copy on the host so the original database remains unchanged:

```text
# SQLite client command: list tables before reading application data.
.tables
```

```sql
-- Read only the lab rows needed to demonstrate the storage behavior.
SELECT id, message, direction FROM encrypted_messages;
```

Example lab output is evidence, not a command to paste back into SQLite:

```text
# Illustrative output from the isolated lab target.
1|3TeYGFf35IYMKAOC4weoNeEmhKfzD5TVaD5Q4tKtTQk=|OUTGOING
2|SVXQJjZ3y1AjG1w9aI9UqoPUyWX/XneKq8syYiAWYNE=|INCOMING
3|1a9aV2NE2Q6/ZYOeQsB7ZZITBoYzBflNxfmzeIz+fHo=|OUTGOING
4|EAhZhNmdW0FBs6WXCM7IMqhSJLn9JRKQDyqNqpKiE2o=|INCOMING
```

The messages look encrypted — base64, and the `=` padding suggests a block cipher. Now look for the key in the decompiled APK:

```bash
# Search decoded resources for names that commonly hold initialization
# vectors or keys. The command prints a lead for manual review.
grep -n -iE 'initial|vector|secret|key' \
  ./chatapp/res/values/strings.xml
```

The lab resource contains values like these. They are sample output, not shell commands:

```xml
<!-- Illustrative lab values; never publish real credentials or key material. -->
<string name="initialization_vector">4fR7!jW3@1nV6#yZ</string>
<string name="secret_key">9xG5#vQ2@LmP8!zB</string>
```

Both the key and the IV are in the APK as plain strings, all 16 bytes of each. The database is therefore decryptable offline by anyone with a copy of the app, and the "encrypted" messages table offers no protection at all. In the lab the decryption yields the flag:

```text
HTB{Pr1v3t_3ncrypt3d_M3ss4g3!}
```

The finding to write up is not "message database encrypted" — it is that the key material ships with the ciphertext in the same binary.

## 3. Reversing hybrid apps

Hybrid and cross-platform apps keep their real logic in JavaScript, which means the Java you decompile is a wrapper and the interesting code is in a bundle.

The bundle lives in `assets/`:

| Framework | File to look for |
| :--- | :--- |
| React Native (plain) | `assets/index.android.bundle` — readable JavaScript |
| React Native (Hermes) | `assets/index.android.bundle` compiled to Hermes bytecode, starts with a Hermes magic header |
| Cordova / Ionic | `assets/www/` — HTML, CSS and JavaScript |
| Flutter | `lib/*/libapp.so` plus `assets/flutter_assets/` — compiled Dart, not JavaScript |

### Reading a React Native bundle

```bash
# Decode the APK
apktool d myapp.apk

# The bundle is minified into one long line. js-beautify expands it so it
# can be read, and writes the result to a new file rather than overwriting
js-beautify myapp/assets/index.android.bundle \
  -o beautified_index.android.bundle.js
```

### Reading Hermes bytecode

Newer React Native apps compile the bundle to Hermes bytecode, which is not JavaScript and will not beautify.

```bash
# Decode the APK and look at the bundle
apktool d hermes.apk
cd hermes/assets/

# Check what it actually is — "Hermes JavaScript bytecode" confirms it
file index.android.bundle

# Install the decompiler, then turn the bytecode back into JavaScript
pip3 install --upgrade git+https://github.com/P1sec/hermes-dec
hbc-decompiler index.android.bundle output.js
```

## 4. Obfuscated code

Obfuscation does not stop analysis, but it costs time. Recognizing which kind you are looking at tells you whether to keep reading or to switch to runtime tooling like [Frida](frida.md).

| Technique | What it looks like |
| :--- | :--- |
| Name obfuscation | Classes, methods and variables renamed to `a`, `b`, `c` |
| Control flow obfuscation | Fake loops, switch statements over constants, unreachable branches |
| Repackaging | Package structure rearranged so classes do not group logically |
| String encryption | Literal strings replaced by a decrypt call made at runtime |
| Class encryption | Classes decrypted and loaded only when needed (common in malware, not in apps) |
| Dummy code | Non-functional code inserted to pad the output |

```bash
# ProGuard and R8 are the standard Android shrinkers: they remove unused
# code and rename what is left. Their output looks like this:
#   public class a { public String a(String b) { ... } }
#
# Unobfuscated code is the giveaway that a check is worth reading:
#   public class TokenManager { public String generateToken(...) { ... } }

# Deguard is a probabilistic deobfuscator that suggests original names
# for ProGuard-renamed methods. Useful when the app is only name-obfuscated
pip3 install deguard
```

If strings are encrypted at runtime, static grep finds nothing; hook the decryption method instead and log its return value.

## 5. Native libraries

Secrets in C/C++ code are still strings in the binary, even when the Java side is clean.

```bash
# Unpack the APK so the lib/ directory is accessible
unzip myapp.apk

# strings prints printable runs from the .so, then grep keeps the long ones.
# The {60,} length filter is a rough "this looks like a key or a token"
# heuristic — API keys, JWTs and base64 blobs are long and have no spaces
strings lib/x86_64/libmyapp.so | \
  grep -E "[a-zA-Z0-9_-]{60,}"
```

Native libraries are also where certificate pinning is implemented when it is done properly. `ghidra` or `radare2` for the disassembly; `strings` first, because it is free.

## 6. Exported PreferenceActivities

A `PreferenceActivity` renders a settings screen straight from XML. If it is exported, another app on the device can open the app's settings UI — which sometimes includes flows that change the server URL, disable TLS verification, or export data.

```text
# Look at AndroidManifest.xml for any activity that:
#   - has android:exported="true"
#   - extends PreferenceActivity, or points at a res/xml/*.xml preference file
#   - has no android:permission guarding it
```

```bash
# The decoded manifest prints both attributes together, which is the fastest
# way to triage what is reachable from outside the app
grep -n "exported" myapp/AndroidManifest.xml
```

## 7. Backup enabled

With `android:allowBackup="true"`, the platform lets `adb backup` copy the app's private data — no root, no debug build, no prompt beyond a confirmation on screen.

```xml
<application allowBackup="true" ...>
<!-- Should be false for anything holding tokens or personal data -->
```

```bash
# Take the backup of the vulnerable app
adb backup -f backup.ab com.example.vulnerableapp

# An .ab file is a header plus a zlib-compressed tar. Skip the 24-byte
# header with dd, decompress the stream with openssl, and you have a tar
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar

# Unpack it
tar -xvf backup.tar

# The app's private data is now on the host, including preferences and databases:
# apps/com.example.app/shared_prefs/userdata.xml
```

## 8. Debuggable app

`android:debuggable="true"` on a release build means a debugger can attach to the running process. In practice that gives you memory inspection, breakpoints over JDWP, and a trivial path around client-side checks.

```text
# In the manifest:
#   <application android:debuggable="true" ...>
#
# With that set, you can:
#   - attach with jdb / Android Studio and inspect memory
#   - read decrypted values out of the heap
#   - step over an authentication check instead of bypassing it
#
# jdwp is also how Frida attaches early; a debuggable flag makes the whole
# class of runtime instrumentation easier
```

## 9. Permissions

Permissions are declared in the manifest and split into two categories that matter for testing:

| Type | Behaviour | Examples |
| :--- | :--- | :--- |
| Normal | Granted at install without asking the user | Internet access, network state |
| Dangerous | Prompted at runtime and revocable in settings | Location, camera, contacts, microphone, SMS |

Read them as an attack surface, not a checklist: an app that requests `READ_SMS` and `RECEIVE_SMS` alongside `INTERNET` is a candidate for message exfiltration, and a custom permission with `protectionLevel="normal"` that guards an exported component is effectively no protection at all.

```bash
# See which permissions an installed package actually holds
adb shell dumpsys package <package_name> | grep -A 20 "requested permissions"

# And which of those are granted
adb shell dumpsys package <package_name> | grep -A 20 "install permissions"
```

## 10. Firebase misconfiguration

Many apps use Firebase as the whole backend. If the database rules are open — which they often are on staging or older projects — anyone with the project ID can read or write everything.

```bash
# Automated: FireBaseScanner walks the APK for the config values
# (this one is Python 2; run it in a python2 environment)
python2 FireBaseScanner.py -p /path/apk

# Manual: the database URL is a string in the resources or the code
grep -R "firebaseio" .

# Then test the endpoint. If it returns JSON without auth, the rules are open:
#   https://appname.firebaseio.com/.json
```

```bash
# Check the appspot host with a read-only request. A permissive CORS header
# alone is not proof; inspect whether a test record is actually disclosed.
curl --silent --show-error --head \
  "https://<APP_NAME>.appspot.com/.json"
curl --silent --show-error \
  "https://<APP_NAME>.appspot.com/.json" \
  --output firebase-response.json
```

An open `.json` endpoint is a critical finding: it usually exposes every user record, and if writes are open it is also a data-integrity problem. Report it with the exact request and response, and stop before writing anything.

## 11. Sensitive data in the codebase

The last pass, and the one that catches what the targeted greps missed. Look for:

- Hardcoded usernames and passwords
- Internal IP addresses and hostnames
- API keys and tokens
- Secrets in test fixtures, sample data and comments
- URLs pointing at staging, admin or debug infrastructure

```bash
# -R recursive, -i case-insensitive. Run these against the decoded APK
# directory, not the original zip
grep -Ri "password" .
grep -Ri "apikey" .
grep -Ri "token" .
grep -Ri "secret" .
```

Those four greps are the starting set. Once you know the app, add its own vocabulary: the internal service names, the SDK names it uses, and any prefix the developers favour for config (`prefs_`, `cfg_`, `debug_`).
