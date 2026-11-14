---
title: "Android vulnerabilities"
description: "Every Android app vulnerability class in depth — explanation, exploitation, steps, remediation and a worked example for each, mapped to the OWASP Mobile Top 10."
tags:
  - Android
  - Vulnerabilities
  - OWASP
---

# Android vulnerabilities

This is the **vulnerability-class reference** for Android apps. The [pentesting pages](../pentesting-intro.md) are organised by *how you test* (static, dynamic, traffic); this section is organised by *what goes wrong*. Every page follows the same shape:

**Explanation → Exploitation → Steps → Remediation → Example.**

If you are new, read the [fundamentals](../what-is-android.md) and [components](../components.md) first — several of these classes assume you know what an exported component or a WebView is.

!!! danger "Authorised testing only"
    Exploit only apps that are in scope with written permission, or your own lab builds.

## The classes

<div class="grid cards" markdown>

-   :material-database-lock:{ .lg .middle } __Data at rest & on screen__

    ---

    - [Insecure data storage](insecure-data-storage.md)
    - [Sensitive data leakage](sensitive-data-leakage.md) — logs, clipboard, screenshots
    - [Insecure configuration](insecure-configuration.md) — `debuggable`, `allowBackup`, cleartext, backend

-   :material-key-variant:{ .lg .middle } __Crypto, secrets & auth__

    ---

    - [Insufficient cryptography](insufficient-cryptography.md)
    - [Hardcoded secrets & credentials](hardcoded-secrets.md)
    - [Insecure authentication &amp; authorization](insecure-authentication.md)
    - [Biometric / local-auth bypass](biometric-bypass.md)

-   :material-lan-connect:{ .lg .middle } __Network & data handling__

    ---

    - [Insecure communication](insecure-communication.md) — cleartext, TLS, pinning bypass
    - [Insecure deserialization](insecure-deserialization.md)

-   :material-shield-off:{ .lg .middle } __Platform & binary__

    ---

    - [Insufficient binary protection](insufficient-binary-protection.md) — reversing, tamper & root detection
    - [Task hijacking (StrandHogg)](task-hijacking.md)

-   :material-transit-connection-variant:{ .lg .middle } __Components & client-side__

    ---

    - [Insecure IPC &amp; exported components](insecure-ipc.md)
    - [WebView vulnerabilities](webview-vulnerabilities.md)
    - [Insecure deep links &amp; intents](insecure-deeplinks.md)

</div>

## Mapped to the OWASP Mobile Top 10

| OWASP Mobile (2024) | Covered by |
| :--- | :--- |
| M1 Improper credential usage | [Hardcoded secrets](hardcoded-secrets.md), [Insecure authentication](insecure-authentication.md) |
| M2 Inadequate supply chain | [Insecure configuration](insecure-configuration.md) (SDK/backend) |
| M3 Insecure authentication/authorization | [Insecure authentication](insecure-authentication.md), [Biometric bypass](biometric-bypass.md) |
| M4 Insufficient input/output validation | [Insecure IPC](insecure-ipc.md), [WebViews](webview-vulnerabilities.md), [Deep links](insecure-deeplinks.md), [Deserialization](insecure-deserialization.md) |
| M5 Insecure communication | [Insecure communication](insecure-communication.md) |
| M6 Inadequate privacy controls | [Sensitive data leakage](sensitive-data-leakage.md) |
| M7 Insufficient binary protections | [Insufficient binary protection](insufficient-binary-protection.md) |
| M8 Security misconfiguration | [Insecure configuration](insecure-configuration.md), [Task hijacking](task-hijacking.md) |
| M9 Insecure data storage | [Insecure data storage](insecure-data-storage.md) |
| M10 Insufficient cryptography | [Insufficient cryptography](insufficient-cryptography.md) |
