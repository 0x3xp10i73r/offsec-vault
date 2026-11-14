---
title: "Insecure data storage"
description: "Plaintext secrets in SharedPreferences, SQLite, internal and external files, cache and Keystore misuse on Android — how to pull them off a device and how to store them properly."
tags:
  - Android
  - Data Storage
  - SharedPreferences
  - SQLite
  - Keystore
  - OWASP MASVS
---

# Insecure data storage

!!! danger "Authorised testing only"
    Run these steps only against apps that are in scope with written permission, or your own lab builds on a device or emulator you control.

## Explanation

Every Android app gets a private sandbox at `/data/data/<package>/` (also reachable as `/data/user/0/<package>/`). The kernel enforces it with a per-app UID, so other apps cannot read it. Developers often treat that as a guarantee and write secrets into it in plaintext: session tokens, passwords, API keys, PII, cached API responses.

The sandbox is only one layer, and it fails in several common ways:

- **Root, or a debuggable app.** Anyone with root, or `run-as` access to a `debuggable` build, reads everything.
- **Backups.** `allowBackup="true"` copies app data off the device (see [Insecure configuration](insecure-configuration.md)).
- **External storage.** Files in `/sdcard/` or `getExternalFilesDir()` are not protected by the app sandbox. Older targets (and any app with `MANAGE_EXTERNAL_STORAGE`) expose them to other apps.
- **Lost or stolen devices.** Without full protection, plaintext on disk is the data.
- **Keystore misuse.** Keys are hardcoded, derived from a constant, or stored next to the data they protect, so "encryption" adds nothing.

Where the data lives:

| Location | Path | Typical mistake |
|----------|------|-----------------|
| SharedPreferences | `shared_prefs/*.xml` | Token or password stored as plain string |
| SQLite | `databases/*.db` | Unencrypted DB with PII, chat, credentials |
| Internal files | `files/` | JSON or text dumps of user data |
| Cache | `cache/` | Cached responses, images of documents |
| External storage | `/sdcard/Android/data/<package>/` | World-readable exports, logs, PDFs |
| Keystore | system Keystore | Hardcoded key, or key material written to disk |

## Exploitation

An attacker with any of the access paths above reads the data directly:

1. **Physical or rooted access.** Pull the app directory with `adb` and read the XML and DB files.
2. **Debuggable build.** `run-as <package>` gives a shell as the app UID with no root.
3. **Backup extraction.** Pull a backup if `allowBackup` is on.
4. **Another app or malware.** Read world-readable files, or external storage on older Android versions.
5. **Token replay.** A stolen session token is replayed against the API, giving account takeover without the password.

Weak "encryption" does not stop this. A key hardcoded in the APK is recovered with `jadx` in minutes, and the attacker decrypts the data offline.

## Steps

1. **Identify the package and install the app on a lab device.**

    ```bash
    adb shell pm list packages | grep -i <keyword>
    adb shell pm path <package>
    ```

2. **Exercise the app.** Log in, use features that handle sensitive data, then background the app, so the data is written to disk.

3. **Check whether the app is debuggable (no root needed).**

    ```bash
    adb shell run-as <package> ls -la /data/data/<package>/
    ```

    If this fails with `package not debuggable`, use root (step 4) or a rooted emulator.

4. **Pull the sandbox with root.**

    ```bash
    adb root                       # emulator / userdebug builds
    adb shell ls -R /data/data/<package>/
    adb pull /data/data/<package>/ ./<package>-data/
    # Physical rooted device
    adb shell "su -c 'cp -r /data/data/<package> /sdcard/loot && chmod -R 777 /sdcard/loot'"
    adb pull /sdcard/loot ./<package>-data/
    ```

5. **Read SharedPreferences.**

    ```bash
    adb shell run-as <package> cat shared_prefs/<name>.xml
    grep -riE "token|password|secret|api[_-]?key|auth|session" ./<package>-data/shared_prefs/
    ```

6. **Inspect SQLite databases.**

    ```bash
    adb shell run-as <package> ls databases/
    adb exec-out run-as <package> cat databases/<name>.db > <name>.db
    sqlite3 <name>.db ".tables"
    sqlite3 <name>.db "SELECT * FROM users;"
    file <name>.db    # "SQLite 3.x" means unencrypted; random data suggests SQLCipher
    ```

7. **Check internal files, cache and external storage.**

    ```bash
    adb shell run-as <package> ls -R files/ cache/
    adb shell ls -laR /sdcard/Android/data/<package>/
    adb shell ls -la /sdcard/ | grep -i <keyword>
    ```

8. **Review Keystore usage statically.**

    ```bash
    jadx -d out/ app.apk
    grep -rnE "SecretKeySpec|getInstance\(\"AES|KeyStore|MasterKey|DES|MD5" out/sources/
    ```

    Red flags: `new SecretKeySpec("hardcodedkey".getBytes(), "AES")`, ECB mode, a static IV, keys in `strings.xml` or `BuildConfig`, or a key generated without `setUserAuthenticationRequired` for high-value data.

9. **Use dynamic confirmation.** Hook `SharedPreferences$Editor.putString` with [Frida](../frida.md) to see what the app writes at runtime.

!!! tip "Document the finding"
    Record the file path, the exact key, and whether recovery needed root, `run-as`, or a backup. Severity depends on that access path.

## Remediation

- **Do not store secrets you can avoid storing.** Keep short-lived access tokens in memory and refresh them.
- **Use `EncryptedSharedPreferences` and `EncryptedFile`** (Jetpack Security) backed by a Keystore `MasterKey`.
- **Encrypt databases** with SQLCipher or Room plus SQLCipher, with the passphrase protected by the Keystore.
- **Use the Android Keystore** with non-exportable keys. Never hardcode keys, and never write key material to disk. Use AES-GCM with a random IV per message; avoid ECB.
- **Require user authentication** for high-value keys (`setUserAuthenticationRequired(true)`, biometrics).
- **Keep files in internal storage** (`MODE_PRIVATE`). Avoid external storage for anything sensitive; use scoped storage.
- **Do not cache sensitive responses.** Set `Cache-Control: no-store` and clear caches on logout.
- **Disable backups** of sensitive data (`allowBackup="false"` or backup rules) and ship with `debuggable` off.
- **Wipe on logout.** Delete preferences, DB rows and cache.

## Example

### Vulnerable code

A login handler stores the session token in plaintext SharedPreferences.

```kotlin
class AuthStore(private val context: Context) {
    fun saveSession(token: String, username: String) {
        context.getSharedPreferences("session", Context.MODE_PRIVATE)
            .edit()
            .putString("auth_token", token)
            .putString("username", username)
            .apply()
    }
}
```

### Exploit

On a lab device with a debuggable build (or root), read the token straight off disk.

```bash
adb shell run-as <package> cat shared_prefs/session.xml
```

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</string>
    <string name="username">alice</string>
</map>
```

Replay the stolen token against the API from a lab host:

```bash
curl -s https://<api-host>/api/me -H "Authorization: Bearer <stolen-token>"
```

!!! failure "Result"
    The API returns the victim's profile. Anyone with access to the file owns the session, with no password needed.

### Fixed version

```kotlin
class AuthStore(private val context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "session_secure",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveSession(token: String) {
        prefs.edit().putString("auth_token", token).apply()
    }

    fun clear() = prefs.edit().clear().apply()
}
```

```bash
# Re-test: the file now contains only ciphertext
adb shell run-as <package> cat shared_prefs/session_secure.xml
```

!!! success "Verified"
    Keys and values are encrypted. The master key lives in the hardware-backed Keystore and is not extractable, so a copied file is useless without the device. Pair this with `allowBackup="false"` and a short token lifetime.
