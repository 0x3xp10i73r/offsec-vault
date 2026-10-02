---
title: "Frida"
description: "Frida on a rooted Android device: server setup, the hook template, tracing internal methods, codeshare scripts for root and pinning bypass."
tags:
  - Android
  - Frida
  - Instrumentation
  - Hooking
---

# Frida

Frida injects JavaScript into a running app and lets you replace Java and native methods while it runs. On Android that is how most client-side checks get bypassed: root detection, emulator detection, certificate pinning, biometric prompts, and any "is this value correct" comparison the app makes locally.

Two parts: `frida-server` running on the device, and the client (Python or the `frida` CLI) on your machine.

## Server setup

```bash
# Check the device's CPU architecture first — the server build has to match it
adb shell getprop ro.product.cpu.abi
# arm64-v8a, armeabi-v7a, x86, x86_64 — download the matching frida-server

# Push the server binary to a writable, common location
adb push frida-server /data/local/tmp

# Make it executable (755 = owner can write and execute, everyone else
# can read and execute)
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start it, backgrounded, as root
adb shell "/data/local/tmp/frida-server &"
```

```bash
# Verify the server is up. On Linux use grep instead of findstr
adb shell ps -A | grep frida

# The client should now see the device and list processes
frida-ps -U
```

Version mismatch between the client and the server is the most common failure: a server older or newer than the client refuses to talk. Match the versions, or install the client that matches the server already on the device.

## The hook template

Most hooks are the same five lines with different names in them.

```javascript
// Java.perform ensures the runtime is up before we touch classes.
// Everything Frida does with Java goes inside this wrapper
Java.perform(function () {
    // Resolve the class by its fully qualified name
    var classRef = Java.use("<package_name>.<ClassName>");

    // Replace the method body. The wrapper receives the original arguments
    // and the return value of your implementation becomes the method's result
    classRef.<methodToHook>.implementation = function (args) {
        // Do something here: log the call, change an argument,
        // short-circuit a check, return a fixed value
        return this.<methodToHook>(args);   // call through to the original
    };
});
```

```bash
# Load the script. -f spawns the app fresh, so the hook is in place before
# the app's own code runs — important for checks that happen at startup
frida -U -f <package> -l script.js --no-pause
```

Run the app with the hook attached rather than attaching after launch whenever the check you are bypassing happens during startup. Attaching late is the second most common reason a hook appears to do nothing.

## Forcing a method to return false

The common case is a boolean check. In Frida, return `false` from the implementation. In smali — for a patch-and-rebuild instead of a runtime hook — the equivalent is a constant return at the top of the method:

```text
.method public final a()Z
    .locals 1
    const/4 v0, 0x0    # load constant 0 (false) into register v0
    return v0          # return it immediately; the real body never executes
.end method
```

The `Z` in the method signature means it returns a boolean, and `const/4` is the one-nibble constant instruction — the cheapest way to put a fixed value in a register. Patching the method this way survives restarts and does not need Frida running, but it does mean re-signing the APK.

## Commands

```bash
# List running processes on the USB device
frida-ps -U

# List all installed applications, with their identifiers.
# -a includes apps not currently running, -i adds the identifier
frida-ps -Uai

# Spawn the app and inject a script
frida -U -f <package> -l script.js --no-pause
```

## Discovering methods and calls

Before hooking anything you need the method name. These three tools find it.

```bash
# List packages with PID, name and identifier
frida-ps -Uai

# Narrow to the app you care about
frida-ps -Uai | grep -i '<part_of_the_package_name>'

# Discover internal methods and calls, and keep the output.
# tee writes to the file while still showing it on screen
frida-discover -U -f <package_name_of_the_apk> | tee <file_path_and_name>
```

## Tracing methods and calls

```bash
# Trace every internal method call of a running app
frida-trace -p <pid_of_an_app>

# Trace specific methods — the wildcard matters, since most names are
# prefixed or suffixed
frida-trace -p <pid_of_an_app> -i '<function_name>*'

# Worked example: find out what an app logs, and from where
frida-trace -p 852
frida-trace -p 852 -i 'log*'
```

Tracing is heavy: on a busy app it produces thousands of lines a second. Start with one wildcard, watch the shape of the output, then narrow to the methods you actually care about.

## Codeshare scripts

Frida's codeshare holds community scripts for the common bypasses. Loading one is a single command instead of a script you maintain.

```bash
# Root detection bypass
frida --codeshare dzonerzy/fridantiroot -f <package_name_of_the_apk>

# SSL pinning bypass — the most widely used one
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f <package_name_of_the_apk>

# Emulator detection bypass (local script)
frida -l emulator_detection_bypass.js -f <package_name_of_the_apk>

# Several at once: root plus pinning plus emulator
frida --codeshare dzonerzy/fridantiroot \
      --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida \
      -l emulator_detection_bypass.js \
      -f <package_name_of_the_apk>

# All-in-one community script for the usual detection set
frida --codeshare fdciabdul/frida-multiple-bypass -f <package_name_of_the_apk>
```

Two cautions. Community scripts are written against particular library versions, so a script that worked last year may do nothing against a newer app — read its output rather than assuming success. And any script that patches many methods at once can change app behaviour in ways you did not intend; when a finding depends on a bypass, verify the finding still reproduces with the app's own behaviour intact.

## Biometric and credential hooks

The hooks for `BiometricPrompt` and the device-credential result are on the [testing checklist](checklist.md#21-biometric-authentication-bypass), since they belong with the test rather than the tooling.

## Related

- [Dynamic analysis](dynamic-analysis.md) — what to look at once Frida is attached.
- [Testing checklist](checklist.md) — every bypass that uses Frida, with the command.
- [Tools and references](tools.md) — Objection, which wraps most of these hooks.
