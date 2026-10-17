---
title: "Setup and ADB"
description: "Device and emulator setup, ADB commands for a rooted test device, wireless ADB, package handling and MobSF."
tags:
  - Android
  - ADB
  - Emulator
  - MobSF
---

# Setup and ADB

!!! note "What this page is doing"
    This page prepares a repeatable mobile lab. The purpose of each command is to establish a device identity, a known package, a reversible snapshot and a working path for evidence—not to alter a production phone.

Everything on this page is the plumbing: getting a device or emulator that you can actually test on, and getting ADB to talk to it.

## Installation order

The order matters because each step depends on the previous one.

1. **Install Java**, then the **JDK**. Apktool, apksigner, keytool and many Frida tooling wrappers are Java programs, and `keytool` and `apksigner` only exist once a JDK is on the machine.

2. **Install an emulator** — Genymotion or MEmu. Emulators give you root by default on many images, a clean snapshot to roll back to, and no risk to a real device.

3. **In Genymotion:** add a device, download Oracle VirtualBox when prompted (Genymotion runs on top of it), then open the network settings and add a manual DHCP server plus an adapter IP. Without that, the emulator has no working network and Burp will never see traffic.

4. **Install ADB on Windows.** ADB is the single most important tool in this whole set — shell access, file push and pull, logcat, backups and port forwarding all go through it.

```bash
# Confirm ADB sees the device or emulator. State meanings:
#   device       ready for commands
#   unauthorized accept the prompt on the device
#   offline      restart the ADB server and reconnect
adb devices
```

## Basic ADB commands

```bash
# List every installed package on the device
adb shell pm list packages

# Install an APK from the host machine (path is on the host, not the device)
adb install "<path>"

# Find the package name when you only know the app label:
# -f prints the APK path, then grep narrows it to the app you saw on screen
adb shell "pm list packages -f | grep <appname>"

# Print the on-device path of an installed package's APK
adb shell pm path <package_name>

# Copy a file off the device (works without root only for world-readable paths)
adb pull <path>
```

## Getting the APK

Several routes, in the order I tend to try them:

```bash
# 1. Straight off a device you control — the most reliable source,
#    and the only one guaranteed to match the version being tested
adb shell pm path <package_name>     # e.g. /data/app/.../base.apk
adb pull /data/app/.../base.apk

# 2. Find a published APK by search — usually for a second opinion
# <app name> universal apk site:apkmirror.com

# 3. From a lab target, take whatever the exercise ships with
```

```bash
# Decompile with JADX, GUI or CLI. The GUI is faster for reading a
# specific flow; the CLI is what you script in bulk
jadx-gui app.apk
jadx -d out app.apk

# Get smali source with apktool. -d decodes: manifest, resources and smali
# land in a folder you can edit and rebuild later
apktool d app.apk

# Convert to a JAR for a Java decompiler
dex2jar app.apk
```

## Wireless ADB

Over USB is fine until the phone is in a mount, behind a case, or on the other side of the room. ADB over TCP is two commands once the device is reachable.

```bash
# Confirm the device is connected over USB first — you need USB for this step
adb devices

# Show the device's own routing table, which tells you its Wi-Fi IP
adb shell ip route

# Switch the ADB daemon on the device to listen on TCP port 5555
adb tcpip 5555

# Connect to the device over the network (use the IP from ip route above)
adb connect 192.168.1.6:5555

# Check that both the USB and the network connection are listed
adb devices
```

```bash
# The general flow, in two lines:
#   adb tcpip <port>                  put the device into TCP mode
#   adb connect <device_ip>:<port>    connect over the network
#
# Note: adb tcpip alone does nothing visible — it only takes effect
# on the next connection attempt.
```

## Working with packages

```bash
# Every package, system and user
adb shell pm list packages

# User-installed apps only.
# -3 filters to third-party packages; cut splits on ":" and keeps the
# name after the "package:" prefix
adb shell pm list packages -3 | cut -f 2 -d ":"

# Other useful filters used by the same command:
#   -f  show the APK path        -d  only disabled packages
#   -e  only enabled packages    -s  only system packages
#   -i  show the installer       -U  show the UID
```

```bash
# Search by keyword instead of reading the whole list
adb shell pm list packages 'keyword' | cut -d ':' -f2
```

```bash
# Process list for the whole device
adb shell ps

# Narrow it to the app you care about — the PID here is what you feed
# to frida-trace, /proc/<pid>/maps and other runtime tooling
adb shell ps | grep <package_name>
```

```bash
# Launch the app two ways, because the obvious one does not always work:

# Method 1 — Monkey: sends a launch event to the package's main activity.
# -c 1 keeps it to a single event instead of a random fuzz session
adb shell monkey -p <package_name> -c 1

# Method 2 — dump the package record and read the launcher activity
# from it, then start that activity explicitly (see below)
adb shell dumpsys package <package_name>
```

```bash
# Start a specific activity by name. Useful for jumping straight to a
# screen behind login, and for testing exported activities
adb shell am start -n <package_name>/.<activity_name>
```

```bash
# Remove an app
adb uninstall <package_name>

# Remove the app but keep its data and cache — handy when you want to
# reinstall and land back in the same logged-in state
adb uninstall -k <package_name>
```

## Backups over ADB

`adb backup` is the fastest way to get an app's private data when the manifest allows it — no root required.

```bash
# Basic device backup. -f names the output file
adb backup -f <some_file_name>.ab

# Back up one specific app, without system apps or the APK itself
adb backup -nosystem -noapk -noshared -f <some_file_name>.ab <package_name>

# Everything: APK, expansion files, shared storage, system and all apps
adb backup -apk -obb -shared -all -system -f <some_file_name>.ab
```

```text
# Options, and what each one actually includes:
#   -f <filename>        output file name (default backup.ab in the current directory)
#   -apk | -noapk        include the APK itself (default: -noapk)
#   -obb | -noobb        include the app's expansion files (default: -noobb)
#   -shared | -noshared  include SD card contents (default: -noshared)
#   -all                 include all installed apps
#   -system | -nosystem  include system apps (default: -system)
```

An `.ab` file is not a tar. It has a small header followed by zlib-compressed tar data, which is why extracting it takes the `dd`/`openssl` trick on the [static analysis](static-analysis.md) page. The device will ask for a password on screen — a backup with a password is encrypted, an empty one is not.

## WSL plus MEmu

Running ADB from WSL against an emulator installed on Windows is fiddly: WSL has its own network namespace, and the Windows `adb.exe` and the Linux `adb` are different daemons. The fix is to use one daemon — the Windows one — and point at it.

```bash
# Check which DNS/WSL gateway is in use (useful when the emulator's
# network is in a different subnet)
cat /etc/resolv.conf | grep nameserver

# Drop any inherited ADB socket setting so the client uses the default
unset ADB_SERVER_SOCKET

# Call the Windows adb.exe directly through the mounted drive
/mnt/d/Program\ Files/Microvirt/MEmu/adb.exe devices

# Make it permanent with an alias in the shell profile
echo 'alias adbwin="/mnt/d/Program\ Files/Microvirt/MEmu/adb.exe"' >> ~/.bashrc
source ~/.bashrc

# Now use it from anywhere
adbwin devices
adbwin shell
```

```text
# Windows path to WSL path, for reference:
#   C:\  ->  /mnt/c/
#   D:\  ->  /mnt/d/
```

## MobSF

MobSF does the boring first pass for you — unzips the APK, reads the manifest, flags insecure permissions and storage, and produces a report you can work from.

```bash
# Run it straight from a Python install (waits on all interfaces, port 8000)
python -m waitress --listen=0.0.0.0:8000 mobsf.MobSF.wsgi:application

# Or run the official image in Docker — no Python setup, and it survives
# a messy host environment
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Feed MobSF both the static APK and a dynamic session against an emulator it can drive — the dynamic side needs a rooted emulator with the MobSF agent installed, which the container handles. Its output is a starting point, not a report: the findings still have to be reproduced by hand.

## Next

- [Intercepting traffic](proxy-certificates.md) — get HTTPS into Burp before you test anything network-facing.
- [Static analysis](static-analysis.md) — read the APK.
- [Dynamic analysis](dynamic-analysis.md) — run it and watch.
