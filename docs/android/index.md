---
title: "Android"
description: "A zero-to-hero Android security path: the platform and its components, the pentesting methodology, how each component is exploited, and the deep-dive notes."
tags:
  - Android
  - Mobile
  - Pentesting
---

# Android security — start here

This section is a **zero-to-hero path** for Android application security. It starts with what Android *is* and the components an app is built from, explains what Android pentesting actually involves, then shows how each component is exploited — and ends with the deep-dive notes (static, dynamic, traffic, Frida and the full checklist).

Work top to bottom the first time; after that, jump straight to the page you need.

!!! danger "Authorised testing only"
    Everything here is for apps that are **in scope** with **written permission**, or your own lab builds. Test on a device or emulator you control, and reset it afterward.

<div class="grid cards" markdown>

-   :material-android:{ .lg .middle } __1 · Android fundamentals__

    ---

    What the platform is and how an app is put together.

    - [What is Android?](what-is-android.md)
    - [APK structure &amp; signing](apk-structure.md)
    - [App components](components.md)

-   :material-clipboard-search:{ .lg .middle } __2 · Android pentesting__

    ---

    The methodology and the lab plumbing.

    - [What is Android pentesting?](pentesting-intro.md)
    - [Lab setup &amp; ADB](setup-adb.md)
    - [Intercepting traffic](proxy-certificates.md)
    - [Static analysis](static-analysis.md)
    - [Dynamic analysis](dynamic-analysis.md)

-   :material-target:{ .lg .middle } __3 · Exploiting components__

    ---

    Driving each exposed component from outside the app.

    - [Exported activities](exploit-activities.md)
    - [Services &amp; broadcast receivers](exploit-services-receivers.md)
    - [Content providers](exploit-content-providers.md)
    - [Deep links &amp; intents](exploit-deeplinks.md)
    - [WebViews](exploit-webviews.md)

-   :material-trophy:{ .lg .middle } __4 · Going further__

    ---

    Instrumentation, reference and the working checklist.

    - [Frida](frida.md)
    - [Testing checklist](checklist.md)
    - [Tools &amp; references](tools.md)
    - [Glossary](glossary.md)
    - [iOS &amp; cross-platform](ios-cross-platform.md)

</div>

## The path in one line

**Learn the platform → learn what each component is → learn the methodology → exploit each component → go deep with the notes.** If you only read three pages first, read [What is Android?](what-is-android.md), [App components](components.md) and [What is Android pentesting?](pentesting-intro.md) — everything else builds on those.
