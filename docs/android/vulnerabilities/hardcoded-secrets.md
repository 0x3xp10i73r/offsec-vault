---
title: "Hardcoded secrets & credentials"
description: "API keys, tokens and secrets shipped in Android code, strings.xml, BuildConfig and native .so files — finding them with jadx, grep, apkleaks and strings, and the server-side fix."
tags:
  - Android
  - Static Analysis
  - Secrets
  - OWASP Mobile Top 10
---

# Hardcoded secrets & credentials

!!! note "What this page is doing"
    This is OWASP Mobile Top 10 **M1 — Improper credential usage**, narrowed to the static case: a secret that should only ever exist server-side is shipped inside the APK, where it is readable by anyone who downloads the app. The finding is not "we found a string" — it is what that string lets an attacker do against the backend.

## Explanation

Anything compiled into an APK is recoverable. There is no client-side secret storage that survives a determined reverse engineer — obfuscation and native code slow the process down but do not change the outcome. Secrets end up shipped in predictable places:

| Location | Why it happens |
| :--- | :--- |
| Java/Kotlin source (decompiled) | A constant dropped in during development and never removed |
| `res/values/strings.xml` | Developers assume resources are "less visible" than code; they are not |
| `BuildConfig` fields | CI injects a key at build time via `buildConfigField`, baking it into every build variant |
| Native `.so` libraries | Developers assume native code is harder to read; `strings` defeats this in seconds |
| `assets/` config files (`.json`, `.properties`, `google-services.json`) | Treated as "just config," not recognised as a secret-bearing file |

Typical contents: cloud provider API keys (Google Maps, Firebase, AWS), payment or analytics SDK keys, OAuth client secrets, hardcoded basic-auth credentials for internal APIs, signing or encryption keys (covered separately under [insufficient cryptography](insufficient-cryptography.md)), and third-party service tokens with wide scopes.

The underlying mistake is architectural: anything the app needs to *prove* (an identity, a scope, a rate limit) has to be enforced by a server that the client cannot read or forge. A key embedded in the client is not proof of anything — it is just a value, and an attacker holds an identical copy the moment they have the APK.

## Exploitation

1. Obtain the secret — decompile, grep, or run an automated scanner against the APK.
2. Identify what the secret is for (cloud API, backend auth, third-party SDK) and what it is scoped to.
3. Use the secret directly against the service it authenticates to, exactly as the legitimate app would — there is usually no way for the service to tell the difference.
4. Assess impact by what the key's permissions allow: read/write access to a cloud backend, unrestricted use of a billed API, or access to another tenant's data if the key is shared across customers.

## Steps

1. Decompile the APK to Java and unpack the resources:

    ```bash
    jadx -d out_jadx vulnerable-app.apk
    apktool d vulnerable-app.apk -o out_apktool
    ```

2. Run the standard secret greps across the decompiled tree — these four catch most findings on their own:

    ```bash
    grep -Ri "apikey" out_jadx out_apktool
    grep -Ri "secret" out_jadx out_apktool
    grep -Ri "token" out_jadx out_apktool
    grep -Ri "password" out_jadx out_apktool
    ```

3. Check `strings.xml` and `BuildConfig` specifically — these are the two most common dumping grounds:

    ```bash
    cat out_apktool/res/values/strings.xml | grep -iE 'key|secret|token'
    grep -Rn "public static final String" out_jadx --include=BuildConfig.java
    ```

4. Run `apkleaks` for an automated pass — it ships regex rules for the common cloud providers and SDKs and is a good first triage before manual grepping:

    ```bash
    pip3 install apkleaks
    apkleaks -f vulnerable-app.apk -o apkleaks-report.txt
    cat apkleaks-report.txt
    ```

5. Check native libraries — secrets in C/C++ survive as plain strings in the compiled `.so`:

    ```bash
    unzip -o vulnerable-app.apk -d apk_unzipped
    strings apk_unzipped/lib/arm64-v8a/libnative.so | grep -E "[A-Za-z0-9_-]{32,}"
    ```

6. Once a candidate key is found, confirm it is live and scoped broadly before reporting it — test it against the service's API directly (read-only calls only, in an authorised engagement):

    ```bash
    curl --silent "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=<found_key>"
    ```

7. If the key is restricted (by referrer, package name, or IP), note the restriction in the report — it changes the severity but a weak or missing restriction on a cloud key is still a finding worth escalating.

## Remediation

- **Never ship secrets in the client.** Anything that must stay secret (API keys that bill, write, or expose PII; OAuth client secrets; signing keys) belongs on a server the attacker cannot read.
- **Proxy third-party calls through your own backend.** The app talks to your API with a user-scoped session token; your backend holds the real third-party key and makes the call server-side.
- **Restrict keys at the provider** when a client-side key is unavoidable (e.g. a Maps SDK key that must ship in the app) — restrict by Android package name + SHA-1 signing certificate, and scope the key to only the APIs it needs.
- **Rotate immediately** any key found during testing or discovered in a public repository — assume it is already compromised.
- **Keep CI-injected secrets out of version control and out of the final binary** where the build does not strictly need them client-side; prefer build-time secrets that are consumed by the backend pipeline, not baked into `BuildConfig`.

## Example

**Vulnerable: a cloud API key hardcoded and found in decompiled code**

```java
// com/example/vulnerableapp/network/ApiClient.java (decompiled with jadx)
public class ApiClient {
    // Shipped in every install, readable by anyone with the APK
    private static final String CLOUD_API_KEY = "AIzaSyD4-REDACTED-EXAMPLE-KEY-9f8e7d6c5b";

    public static Response callBackend(String endpoint) {
        String url = "https://api.cloudprovider.example.com/" + endpoint
                + "?key=" + CLOUD_API_KEY;
        return httpClient.get(url);
    }
}
```

```xml
<!-- res/values/strings.xml — the same key, also left here for "configuration" -->
<string name="cloud_api_key">AIzaSyD4-REDACTED-EXAMPLE-KEY-9f8e7d6c5b</string>
```

**Found and confirmed with the triage steps above**

```bash
grep -Ri "apikey" out_jadx
# out_jadx/sources/com/example/vulnerableapp/network/ApiClient.java:
#   private static final String CLOUD_API_KEY = "AIzaSyD4-REDACTED-EXAMPLE-KEY-9f8e7d6c5b";

apkleaks -f vulnerable-app.apk -o apkleaks-report.txt
# [+] Google API Key => AIzaSyD4-REDACTED-EXAMPLE-KEY-9f8e7d6c5b
```

**Impact**

The key is unrestricted and scoped to billed, data-returning endpoints. Anyone who downloads the app from the store extracts the same key and can run unlimited requests against the provider on the developer's billing account, or — depending on the provider's permission model — read backend data the key was never meant to expose to end users.

**Fix: server-side proxy, no client secret**

```java
// Client: no secret, just the app's own session token against our own API
public class ApiClient {
    public static Response callBackend(String endpoint, String sessionToken) {
        String url = "https://api.ourapp.example.com/" + endpoint;
        return httpClient.get(url, "Authorization: Bearer " + sessionToken);
    }
}
```

```javascript
// Backend (Node/Express): holds the real provider key, never sent to the client
app.get('/geocode', requireAuthenticatedSession, async (req, res) => {
  const providerResponse = await fetch(
    `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(req.query.address)}&key=${process.env.CLOUD_API_KEY}`
  );
  const data = await providerResponse.json();
  res.json(data);
});
```

```bash
# At the provider: restrict the (now server-only) key to the backend's
# static egress IP range and to only the geocoding API it actually uses
gcloud alpha services api-keys update <KEY_ID> \
  --allowed-ips=203.0.113.0/24 \
  --api-target=service=geocoding-backend.googleapis.com
```

The client now holds only a session token scoped to the logged-in user and revocable server-side; the provider key never leaves the backend, and even if it did, it would be rejected outside the backend's IP range.
