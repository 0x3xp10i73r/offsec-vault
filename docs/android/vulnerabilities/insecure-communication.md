---
title: "Insecure communication"
description: "Cleartext HTTP, TrustManager and HostnameVerifier implementations that accept everything, and how certificate pinning is configured, bypassed and done properly."
tags:
  - Android
  - TLS
  - Certificate Pinning
  - Network Security Config
---

# Insecure communication

!!! note "What this page is doing"
    Insecure communication covers three separate failures that get conflated: traffic sent in the clear, TLS validation that has been disabled or weakened, and pinning that is either absent or trivially bypassable. Each needs a different fix, and a passing Burp session does not by itself tell you which one you are looking at.

## Explanation

Android apps talk to a backend, and three things can go wrong between the socket and the server:

- **Cleartext HTTP.** The request is sent unencrypted — `http://` instead of `https://`, or a WebView that loads mixed content. Anything on the same network segment reads or modifies it.
- **Disabled TLS validation.** The app implements its own `X509TrustManager` or `HostnameVerifier` to "fix" a certificate problem during development, and it ships that way. A `checkServerTrusted()` that never throws accepts any certificate from any CA, including one generated on the spot by an interception proxy.
- **Certificate pinning gaps.** Pinning is supposed to stop exactly the attack above: even with a trusted CA in the chain, the app refuses to talk unless the server's certificate (or its public key) matches a value baked into the app. The finding here is not "no pinning" by itself — it's pinning that can be bypassed at runtime because nothing in the app detects or resists instrumentation, or pinning that was implemented but silently disabled by a debug flag.

On API 24+ (`targetSdkVersion >= 24`), the platform already trusts only system CAs by default, which blocks a plain Burp-in-the-user-store attack. That default gets undone three ways: `android:usesCleartextTraffic="true"` in the manifest, a `network_security_config.xml` with `<trust-anchors><certificates src="user"/>`, or an app-level `TrustManager` that bypasses the platform check entirely.

## Exploitation

With a trusted CA problem or an all-trusting `TrustManager`, the path is the standard proxy setup described on the [certificate installation page](../proxy-certificates.md):

1. Install the interception proxy's CA (user store if the app will take it, system store otherwise).
2. Point the device at the proxy.
3. Request anything that previously used TLS. If the custom `TrustManager` is doing nothing, the request appears in the proxy with no warning — the app never noticed the certificate came from an unknown CA.

If the request does **not** appear and `adb logcat` shows `SSLPeerUnverifiedException` or `Certificate pinning failure`, pinning is active and needs its own bypass before the traffic is visible at all.

## Steps

```bash
# 1. Confirm cleartext traffic is permitted at the manifest/config level
apktool d target.apk -o target_src
grep -n "usesCleartextTraffic" target_src/AndroidManifest.xml
cat target_src/res/xml/network_security_config.xml 2>/dev/null

# 2. Decompile and look for a custom TrustManager or HostnameVerifier
jadx -d target_jadx target.apk
grep -rniE "X509TrustManager|HostnameVerifier|checkServerTrusted" target_jadx/sources/ | head -20

# 3. Install the proxy CA and point the device at Burp (system store for
#    targetSdkVersion >= 24; see proxy-certificates.md for the full procedure)
adb push burpca-cert-der.crt /sdcard/
adb shell settings put global http_proxy <burp_host>:8080

# 4. Reproduce a request and watch Burp. No certificate warning in logcat and
#    the request lands in Burp => validation is broken, not just absent
adb logcat | grep -iE "trust anchor|SSLHandshake|CertPath"

# 5. If the request never reaches Burp, pinning is active. Check which class
#    is enforcing it, then unpin with objection
objection --gadget <package> explore
# inside objection:
#   android sslpinning disable

# 6. Or the same bypass as a standalone Frida script, which also covers
#    hand-rolled pinning that objection's generic hook misses
frida -U -f <package> -l ssl-unpinning.js --no-pause
```

```javascript
// ssl-unpinning.js — forces the default TrustManager path to accept
// anything, independent of what the app's own TrustManager does
Java.perform(function () {
    var TrustManager = Java.registerClass({
        name: "org.wooyun.AllTrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function () {},
            checkServerTrusted: function () {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    ).implementation = function (keyManager, trustManagers, secureRandom) {
        console.log("[*] SSLContext.init() intercepted — installing all-trusting TrustManager");
        this.init(keyManager, [TrustManager.$new()], secureRandom);
    };
});
```

## Remediation

- Remove `android:usesCleartextTraffic="true"` and any `network_security_config.xml` entry that trusts `src="user"` in a release build. Set a `base-config` with `cleartextTrafficPermitted="false"`.
- Never implement a custom `X509TrustManager` or `HostnameVerifier` that accepts everything, even temporarily — code paths guarded by a `BuildConfig.DEBUG` check still ship in release builds often enough to be a standing risk. Use the platform's default `TrustManagerFactory` unless there is a specific reason not to.
- Pin at the SPKI (public key) level, not the leaf certificate, and configure it through `network_security_config.xml` rather than a hand-written `CertificatePinner`, so a certificate rotation on the server does not require an app update.
- Pinning alone does not stop Frida or objection on a rooted or instrumented device — add root/tamper detection (see [Insufficient binary protections](insufficient-binary-protection.md)) as defense in depth, and treat pinning as raising the cost of interception, not eliminating it.
- Monitor for `SSLHandshakeException`/pin-mismatch reports from production: a sudden spike is as often a legitimate certificate rotation gone wrong as it is an attack, but both deserve a look.

## Example

**Vulnerable — accepts any certificate from any CA:**

```java
// Written to work around a staging certificate issue, then shipped
public class UnsafeTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // intentionally empty — no exception means "trusted"
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // intentionally empty
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[]{};
    }
}

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, new TrustManager[]{ new UnsafeTrustManager() }, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
```

**Exploit — intercepted traffic, from the attacker/tester side:**

```bash
# No pinning and a TrustManager that accepts everything: a plain proxy
# CA install is enough, no Frida needed
adb shell settings put global http_proxy 10.10.10.117:8080
# In Burp: the request body, including auth headers, is fully visible —
# the app never checked that Burp's generated CA was untrusted
```

**Fix — default validation, with SPKI pinning configured declaratively:**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2026-12-31">
            <pin digest="SHA-256">base64EncodedPrimarySpkiHash=</pin>
            <!-- backup pin for planned key rotation -->
            <pin digest="SHA-256">base64EncodedBackupSpkiHash=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

```java
// No custom TrustManager at all — let the platform validate the chain
// and the network_security_config enforce the pin
URL url = new URL("https://api.example.com/v1/profile");
HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
conn.connect();
```
