---
title: "App components"
description: "The four Android app components, intents, the manifest and WebViews — what each one is, how apps use it, and why each one matters for security."
tags:
  - Android
  - Fundamentals
  - Components
  - IPC
---

# App components

An Android app is not one program — it is a set of **components** the system can start independently, glued together by **intents** and declared in the **manifest**. Understanding each component is the whole game: exploitation (covered later) is just *reaching a component from outside the app that was meant to be internal*.

There are **four** component types, plus the manifest and intents that tie them together.

## The four components

### 1. Activity — a screen

An **Activity** is a single UI screen (a login page, a settings screen, a profile view). The system manages them as a back-stack.

- **How apps use it:** each screen the user sees is an activity; the app navigates between them with intents.
- **Why it matters:** if an activity is **exported**, any app on the device can launch it directly — skipping whatever normally comes before it. The classic result is an **authentication bypass**: launching the screen that normally sits *behind* the login.

### 2. Service — background work

A **Service** performs long-running work without a UI (syncing, playing audio, uploading).

- **How apps use it:** started explicitly to do a job, often continuing after the user leaves the app.
- **Why it matters:** an **exported service with no permission check** can be invoked by any app to trigger privileged work the developer assumed only their own code would call.

### 3. BroadcastReceiver — reacting to events

A **BroadcastReceiver** listens for system or app events (boot completed, connectivity change, a custom app action) and reacts.

- **How apps use it:** to respond to things happening on the device or inside the app.
- **Why it matters:** an **exported receiver** that accepts an *implicit* broadcast can be triggered by anything on the device. If it performs a sensitive action (apply a config, cancel an order, reset state) from attacker-controlled extras, that is high severity.

### 4. ContentProvider — shared structured data

A **ContentProvider** exposes structured data (usually SQLite-backed) to other apps through `content://` URIs, with `query`, `insert`, `update` and `delete` operations. The client side that talks to it is the **ContentResolver** (and, from a shell, `adb shell content`).

- **How apps use it:** to share data between apps in a controlled way (contacts, media, an app's own exported data).
- **Why it matters:** missing read/write permissions leak **whole tables**; queries built by string concatenation give **SQL injection**; file-backed providers with weak path handling give **path traversal**.

| Component | One-line role | Primary attack angle |
| :--- | :--- | :--- |
| Activity | A UI screen | Exported → launch it directly → auth bypass |
| Service | Background job | Exported → invoke privileged work |
| BroadcastReceiver | Event handler | Exported → fire a sensitive action with crafted extras |
| ContentProvider | Shared data store | Missing permission → data leak; string queries → SQLi; path handling → traversal |

## Intents — the glue

An **Intent** is a message object that asks a component to do something. Components are started *by* intents, which is exactly why components are reachable from outside.

- **Explicit intent** — names the exact target component and package. Internal, lower risk (still worth checking for redirection bugs).
- **Implicit intent** — describes an *action* (e.g. "view this URL") and lets the system pick a handler. Multiple apps can claim the same action, which is how **intent hijacking** and overlay/Strandhogg-style attacks work.
- **Intent resolution** — the process that decides which component handles an implicit intent. The winner is chosen by **intent-filter priority**, so a malicious app can register a higher priority than the legitimate handler.

!!! note "Deep links are intents"
    A deep link (`myapp://host/path`) is just a URL that resolves to an intent with an `intent-filter`. A link in a browser, email or another app can therefore reach an internal component — carrying attacker-controlled parameters.

## WebViews — a browser inside the app

A **WebView** embeds web content inside a native screen. It is not a component type, but it is a major attack surface because it mixes web and native trust:

- `setJavaScriptEnabled(true)` makes injected HTML executable (XSS).
- `addJavascriptInterface(...)` exposes Java objects to JavaScript — potential **RCE** if the WebView can be made to load attacker content.
- `setAllowUniversalAccessFromFileURLs(true)` lets a `file://` page read other local files — **local file theft**.

## The manifest — where it is all declared

`AndroidManifest.xml` declares every component, its `intent-filter`s, the permissions it requires, and app-wide flags. It is the **first file you read**, because the entire attack surface is spelled out here. The attributes worth finding first:

| Attribute | Meaning | Risk when set |
| :--- | :--- | :--- |
| `android:exported="true"` | The component is reachable by other apps | With no `android:permission`, anything on the device can invoke it |
| `android:permission` | A permission required to use the component | *Absence* on an exported component is the red flag |
| `android:debuggable="true"` | A debugger may attach | Memory inspection and check-bypass without root |
| `android:allowBackup="true"` | The OS may back up app data | `adb backup` extracts private data without root |
| `android:networkSecurityConfig` | Points at network rules XML | Often allows cleartext or defines pinning |
| `uses-permission` | A permission the app requests | Over-broad permissions widen impact |
| `intent-filter` | Which implicit intents / schemes a component accepts | Declares the deep links and actions you can fire |

```bash
# Decode the manifest and read the exported components + filters
apktool d app.apk -o app_decoded
grep -nE 'exported="true"|<activity|<service|<receiver|<provider|intent-filter|android:scheme' \
  app_decoded/AndroidManifest.xml
```

!!! warning "Implicit export"
    A component with an `intent-filter` is implicitly exported on older `targetSdk` levels even without `exported="true"`. Since Android 12 (API 31) the flag is mandatory, but you will still meet older apps where a filter alone means "reachable."

## Where this leads

You now know what each component is and why it is exposed. The **[Exploiting components](exploit-activities.md)** pages show how to actually drive each one from `adb` — launch an exported activity, fire a broadcast, query a provider, follow a deep link into a WebView — and what turns a reachable component into a reported finding.
