---
title: "Insecure IPC & exported components"
description: "How exported Android components (activities, services, receivers, providers) with no permission check become an attack surface — with a worked content-provider example and remediation."
tags:
  - Android
  - Vulnerabilities
  - IPC
  - Exported Components
---

# Insecure IPC & exported components

## Explanation

Android apps are made of [components](../components.md) — activities, services, broadcast receivers and content providers — that the system can start through **intents**. A component is reachable by other apps when it is **exported**: either `android:exported="true"`, or (on older `targetSdk` levels) simply because it declares an `intent-filter`.

The vulnerability is an exported component **with no permission guarding it**. The developer assumed only their own code would call it, so the component trusts its caller — but on the device, "the caller" can be any installed app, or you from `adb`. This is the single largest source of Android-specific bugs, and maps to **OWASP Mobile M4 (insufficient input/output validation)** and **M8 (security misconfiguration)**.

## Exploitation

An unprivileged app (or `adb`) can:

- **Launch an exported activity** directly — skipping the login screen that normally precedes it (authentication bypass).
- **Start an exported service** — triggering privileged background work.
- **Send a broadcast** an exported receiver acts on — firing a sensitive action (reset, config change, payment) with attacker-chosen extras.
- **Query/insert into an exported content provider** — reading or writing data, or injecting SQL and path traversal.

The common thread: the component acts on data it received without checking **who** sent it or **what** they sent.

## Steps

```bash
# 1. Decode the manifest and list exported components
apktool d app.apk -o app_decoded
grep -nE '<activity|<service|<receiver|<provider|exported="true"|android:permission' \
  app_decoded/AndroidManifest.xml

# 2. Or read the live package record
adb shell dumpsys package <package> | grep -iE "Activity|Service|Receiver|Provider|exported|permission"

# 3. The rule to apply to each hit:
#    exported="true" AND no android:permission  ->  reachable by anything on the device
```

For the per-component exploitation workflow, see **Go deeper** below.

## Remediation

- Set `android:exported="false"` on every component that does not need to be reached by other apps (and since Android 12 the flag is **mandatory** when an `intent-filter` is present — set it explicitly).
- Where a component must be shared, protect it with `android:permission` and a **signature-level** permission so only the same developer's apps can call it.
- **Validate every input** a component receives (intent extras, provider selection, URIs) and never make a security decision based on the caller being "trusted."
- For providers, set `android:readPermission`/`android:writePermission`, use parameterised queries, and scope `grant-uri-permission` paths tightly.

## Example

A content provider exported with no permission leaks its whole table.

**Vulnerable** (`AndroidManifest.xml`):

```xml
<provider
    android:name=".UserProvider"
    android:authorities="<authority>"
    android:exported="true" />   <!-- no readPermission, no permission -->
```

**Exploit** — any app, or `adb`, reads every row:

```bash
adb shell content query --uri content://<authority>/users
# Row: _id=1, username=admin, token=eyJhbGciOi...   <- full table, no auth
```

**Fixed** — not exported, or guarded by a signature permission and parameterised internally:

```xml
<permission android:name="<package>.permission.READ_USERS"
            android:protectionLevel="signature" />

<provider
    android:name=".UserProvider"
    android:authorities="<authority>"
    android:exported="false"
    android:readPermission="<package>.permission.READ_USERS" />
```

!!! tip "Go deeper"
    Each component has a full exploitation walkthrough:
    [Exported activities](../exploit-activities.md) ·
    [Services &amp; broadcast receivers](../exploit-services-receivers.md) ·
    [Content providers](../exploit-content-providers.md) ·
    [Deep links &amp; intents](../exploit-deeplinks.md).
