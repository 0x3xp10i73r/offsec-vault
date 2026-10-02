---
title: "Tools and references"
description: "The Android testing toolchain in one table, plus the small commands that are worth keeping to hand."
tags:
  - Android
  - Tooling
  - Reference
---

# Tools and references

## The toolchain

| Tool | What it does | When I reach for it |
| :--- | :--- | :--- |
| ADB | Talks to the device over USB or TCP | Everything: shell, files, logcat, backup, install |
| JADX | Decompiles an APK to readable Java | Reading app logic; `jadx-gui` for a specific flow |
| APKTool | Decodes and rebuilds APK resources and smali | Manifest analysis, and any patch-and-rebuild |
| dex2jar | Converts APK or DEX to a JAR | When another Java decompiler reads the code better |
| Frida | Dynamic instrumentation, hooks methods at runtime | Bypassing client-side checks |
| Objection | Frida wrapper with prebuilt hooks | Fast SSL unpinning and root bypass |
| Fridump | Dumps app memory through Frida | Hunting keys that never touch disk |
| MobSF | Automated static and dynamic analysis | Triage, and a first pass at the manifest |
| Burp Suite | HTTP/S interception proxy | Every network-facing test |
| Firebase Scanner | Finds misconfigured Firebase instances | Apps that use Firebase as their backend |
| reFlutter | Patches Flutter apps for traffic interception | Flutter targets, where proxy settings are ignored |
| Deguard | Reverses ProGuard name obfuscation | Obfuscated apps that still have string constants |
| uber-apk-signer | Signs APKs after modification | After every rebuild |

## Commands worth keeping to hand

```bash
# Set and clear the system proxy
adb shell settings put global http_proxy 192.168.1.10:8081
adb shell settings put global http_proxy :0

# Check the CPU architecture, so you download the matching frida-server
adb shell getprop ro.product.cpu.abi

# Push and start frida-server
adb push frida-server /data/local/tmp
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Rebuild an APK after patching.
# -r skips resource decoding when you only changed smali
# --use-aapt2 uses the current resource compiler
apktool d app.apk -r -f
apktool b <folder> --use-aapt2 -o mod.apk

# Decode into a named folder when you are juggling several builds
java -jar /usr/local/bin/apktool.jar d app-release -o appmodified

# Objection: search process memory for a string. Useful when a secret is
# decrypted at runtime and never written to disk
memory search "FLAG{" --string
```

```bash
# Greps that pay, in rough order of usefulness

# Firebase endpoints anywhere in the decoded app
grep -R "firebaseio" .

# Root and detection strings in the decoded tree, case-insensitive,
# with line numbers
grep -Rni "root" app_decoded/

# Detection logic in a specific smali file
grep -n "xbin\|root\|su\|detect" app/smali/Consts.smali
```

## APK signing quick reference

Every modified APK follows the same three steps. Full detail is on the [testing checklist](checklist.md#method-8-reverse-engineering-the-smali).

```bash
# 1. One-time: create a key to sign with
keytool -genkey -v -keystore my-key.jks -alias my-alias -keyalg RSA -keysize 2048 -validity 10000

# 2. Align, then sign (alignment must happen before signing)
zipalign -v 4 mod.apk aligned.apk
apksigner sign --ks my-key.jks --ks-key-alias my-alias -out signed.apk aligned.apk

# 3. Install over the existing package
adb install -r signed.apk
```

## References

- Android Pentesting Checklist — [github.com/Hrishikesh7665/Android-Pentesting-Checklist](https://github.com/Hrishikesh7665/Android-Pentesting-Checklist)
- Nine methods for bypassing SSL pinning on Android — [medium.com/@vaishalinagori112](https://medium.com/@vaishalinagori112/9-different-ways-to-bypass-ssl-pinning-in-android-2d8c7f81b837)
- Mobile Hacking Lab "Strings" walkthrough — [akshayravic09yc47.medium.com](https://akshayravic09yc47.medium.com/mobile-hacking-lab-strings-writeup-37c1036df40b)
