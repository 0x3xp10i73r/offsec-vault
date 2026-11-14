---
title: "WebView vulnerabilities"
description: "Why WebViews mix web and native trust — JavaScript injection, addJavascriptInterface exposure, file access and open navigation — with a worked example and the hardened configuration."
tags:
  - Android
  - Vulnerabilities
  - WebView
  - Client-side
---

# WebView vulnerabilities

## Explanation

A **WebView** is a browser engine embedded inside a native screen. It becomes dangerous when it mixes two trust domains: untrusted web content and the native app's privileges. The risky surface is entirely in how the app **configures** the WebView and what content it is allowed to load. The common mistakes:

- `setJavaScriptEnabled(true)` — scripts run, so any attacker-controlled HTML that reaches the WebView executes as the page (**XSS**).
- `addJavascriptInterface(obj, "name")` — exposes a native Java/Kotlin object to page JavaScript. If attacker content can load, it can call those methods.
- `setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs(true)` — a `file://` page can read other local files (**local file theft**).
- `shouldOverrideUrlLoading()` returning `false` for any URL — the WebView navigates wherever it is told, so a deep link can point it at attacker or `file://` content.

Maps to **OWASP Mobile M4 (insufficient input/output validation)**.

## Exploitation

An attacker needs to get **content they control** into the WebView — usually by a [deep link](insecure-deeplinks.md) that passes a `url` parameter the app loads, a man-in-the-middle on a cleartext page, or stored content rendered in the WebView. Once their HTML/JS runs inside the WebView:

- With JavaScript enabled → **XSS** in the app's web context (steal tokens held in the page, hit in-app endpoints).
- With an exposed interface → call the bridged native methods the app trusted its own pages to call.
- With file access → read the app's private files from a `file://` origin and exfiltrate them.

## Steps

```bash
# 1. Find WebView configuration in decompiled code
jadx -d app_src app.apk
grep -rnE "setJavaScriptEnabled|addJavascriptInterface|AllowUniversalAccess|AllowFileAccess|shouldOverrideUrlLoading|loadUrl" app_src

# 2. Find the entry point: an intent-filter / deep link whose parameter is loaded
grep -rnE "getIntent|getData|loadUrl" app_src

# 3. Drive the WebView at content you control through the app's own scheme
adb shell am start -a android.intent.action.VIEW \
  -d "<scheme>://web?url=file:///data/data/<package>/shared_prefs/secrets.xml"
```

## Remediation

- Keep `setJavaScriptEnabled(false)` unless the feature genuinely needs scripting.
- **Only load trusted, app-controlled URLs.** Validate any URL that comes from an intent/deep link against an allow-list; never load an attacker-supplied `url` parameter.
- Avoid `addJavascriptInterface`; if a bridge is required, annotate methods with `@JavascriptInterface`, expose the minimum, and only on pages you fully control (API 17+ limits exposure to annotated methods, but the design risk remains).
- Disable file access: `setAllowFileAccessFromFileURLs(false)`, `setAllowUniversalAccessFromFileURLs(false)`, and `setAllowFileAccess(false)` where possible.
- Implement `shouldOverrideUrlLoading()` to block navigation outside your allow-list.

## Example

**Vulnerable** — scripting on, a native bridge exposed, and the URL comes from an intent:

```java
WebSettings s = webView.getSettings();
s.setJavaScriptEnabled(true);
s.setAllowUniversalAccessFromFileURLs(true);
webView.addJavascriptInterface(new AppBridge(), "bridge"); // AppBridge has native helpers
String url = getIntent().getData().getQueryParameter("url"); // attacker-controlled
webView.loadUrl(url);
```

**Exploit** — a deep link points the WebView at a local file (or attacker page):

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "<scheme>://web?url=file:///data/data/<package>/shared_prefs/auth.xml"
# The file renders; with universal file access, injected JS can read it and
# reach window.bridge.* native methods.
```

**Fixed** — no scripting/bridge unless required, file access off, and the URL allow-listed:

```java
WebSettings s = webView.getSettings();
s.setJavaScriptEnabled(false);
s.setAllowFileAccessFromFileURLs(false);
s.setAllowUniversalAccessFromFileURLs(false);
s.setAllowFileAccess(false);

String url = getIntent().getData().getQueryParameter("url");
if (url != null && ALLOWED_HOSTS.contains(Uri.parse(url).getHost())) {
    webView.loadUrl(url);
}
```

!!! tip "Go deeper"
    The hands-on exploitation workflow (the `addJavascriptInterface` chain and `file://` theft) is on [Exploiting WebViews](../exploit-webviews.md). The usual entry point is a bad [deep link](insecure-deeplinks.md).
