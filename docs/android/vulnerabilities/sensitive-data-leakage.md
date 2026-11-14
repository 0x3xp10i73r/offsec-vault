---
title: "Sensitive data leakage"
description: "How Android apps leak secrets through logcat, the clipboard, screenshots and the recents screen, keyboard caches and notifications — with capture steps and fixes."
tags:
  - Android
  - Data Leakage
  - Logcat
  - Clipboard
  - FLAG_SECURE
  - OWASP MASVS
---

# Sensitive data leakage

!!! danger "Authorised testing only"
    Capture logs, clipboard contents and screenshots only from in-scope apps or your own lab builds, using test accounts.

## Explanation

Data leakage happens when sensitive data leaves the context where it was meant to live, without anyone attacking the storage layer. The data escapes through side channels the OS provides for convenience:

| Channel | How it leaks |
|---------|--------------|
| **Logcat** | `Log.d/i/e` or `System.out.println` writes tokens, passwords, request bodies. Before Android 4.1 any app could read logs; today `adb`, bug reports and some privileged apps can. |
| **Clipboard** | Copying a password or OTP puts it in a shared buffer that other apps (foreground or via accessibility) can read, and that cloud clipboards may sync. |
| **Screenshots / recents** | Without `FLAG_SECURE`, the OS stores a thumbnail of the screen in the recents list, and screen recording or screenshots capture it. |
| **Keyboard cache** | Third-party keyboards and autocorrect learn text typed into fields that lack the right input type. |
| **Notifications** | Message content or OTPs shown on the lock screen, readable by anyone nearby or by notification-listener apps. |

The cause is almost always the same: debug code or convenience features shipped to production, and sensitive fields treated like ordinary UI.

## Exploitation

- **Logcat.** An attacker with physical access, a USB-debugging session, or a bug report reads credentials and tokens from logs. Malware with `READ_LOGS` (granted via `adb` or on older/rooted devices) does the same.
- **Clipboard sniffing.** A background app or accessibility service monitors clipboard changes and captures copied secrets.
- **Shoulder surfing and screen capture.** Recents thumbnails, screenshots and screen-sharing sessions expose account balances, messages and PINs.
- **Keyboard learning.** Sensitive strings end up in a keyboard's dictionary or cloud-synced suggestions.
- **Lock-screen notifications.** OTPs and message bodies are read without unlocking the device.

A leaked token in a log is as good as a stolen session: replay it against the API.

## Steps

1. **Capture logcat while using the app.**

    ```bash
    adb shell pidof <package>
    adb logcat -c                                   # clear the buffer
    adb logcat --pid=$(adb shell pidof <package>)   # follow just this app
    # Log in, register, reset a password, make a payment, then search
    adb logcat -d | grep -iE "token|password|passwd|secret|bearer|authorization|otp|session|cookie"
    ```

2. **Find the log calls in code.**

    ```bash
    jadx -d out/ app.apk
    grep -rnE "Log\.(d|i|v|w|e)\(|System\.out\.print|printStackTrace|Timber\." out/sources/ | grep -iE "token|pass|auth|key"
    ```

3. **Check whether logs are stripped in release.** Look for ProGuard or R8 rules such as `-assumenosideeffects class android.util.Log`.

    ```bash
    apktool d app.apk -o app-src
    grep -rn "assumenosideeffects" app-src/ 2>/dev/null
    ```

4. **Test the clipboard.** Copy a sensitive field in the app (password, OTP, account number), then read the clipboard.

    ```bash
    # Android 10+ blocks background reads. Use a foreground helper app or Frida on the lab device
    adb shell service call clipboard 2 i32 1 i32 0 2>/dev/null
    # Frida: hook ClipboardManager.setPrimaryClip and print ClipData
    frida -U -f <package> -l clip-hook.js
    ```

    Also check whether password fields allow copy, and whether `ClipDescription.EXTRA_IS_SENSITIVE` is set (Android 13+).

5. **Test screenshots and recents.**

    ```bash
    # Open a sensitive screen (login, balance, card), then capture
    adb exec-out screencap -p > screen.png
    # Press the recents button and check whether the screen thumbnail is visible
    ```

    A black or blank capture, or a "Can't take screenshot due to security policy" message, means `FLAG_SECURE` is set. Confirm statically:

    ```bash
    grep -rn "FLAG_SECURE" out/sources/
    ```

6. **Check keyboard cache behaviour.** In `jadx` or the layout XML, inspect `inputType` on sensitive `EditText` fields.

    ```bash
    grep -rnE "inputType" app-src/res/layout/ | grep -iE "pass|pin|otp|card"
    ```

    Fields without `textPassword`/`numberPassword` or `textNoSuggestions` may be cached by the keyboard.

7. **Check notifications.** Trigger a message or OTP with the device locked and read the lock screen. Review `NotificationCompat.Builder` for `setVisibility(VISIBILITY_PRIVATE)` and a redacted public version.

    ```bash
    adb shell dumpsys notification --noredact | grep -iE "otp|code|token" | head
    ```

## Remediation

- **Logging.** Never log secrets, PII or full request/response bodies. Strip `Log.*` in release builds with R8 `-assumenosideeffects`, or use a `Timber` tree that plants nothing in release. Do not rely on `BuildConfig.DEBUG` checks alone, since the strings still ship in the APK.
- **Clipboard.** Do not place secrets on the clipboard. If copying is needed, mark it sensitive (`EXTRA_IS_SENSITIVE`), clear it after a short timeout, and disable copy/paste on password fields.
- **Screenshots and recents.** Set `FLAG_SECURE` on windows showing sensitive content. Use `setRecentsScreenshotEnabled(false)` (API 33+) for recents.
- **Keyboard.** Use `textPassword`, `numberPassword` or `textNoSuggestions|textVisiblePassword` input types, and `importantForAutofill="no"` where appropriate.
- **Notifications.** Use `VISIBILITY_PRIVATE` with a redacted public version, and never put OTPs or full message bodies in the notification text.
- **Review third-party SDKs.** Analytics and crash reporters can log or upload the same data.

## Example

### Vulnerable code

A login flow logs the token and the request, and the screen has no protection.

```kotlin
class LoginActivity : AppCompatActivity() {
    private fun onLoginSuccess(user: String, token: String) {
        Log.d("LoginActivity", "Login OK user=$user token=$token")
        startActivity(Intent(this, AccountActivity::class.java))
    }
}

class AccountActivity : AppCompatActivity() {
    private fun copyAccountNumber(number: String) {
        val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("acct", number))
    }
}
```

### Exploit

From a lab host with USB debugging enabled, read the token live while the user logs in.

```bash
adb logcat -c
adb logcat -s LoginActivity:D
```

```text
D/LoginActivity: Login OK user=alice token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

```bash
curl -s https://<api-host>/api/accounts -H "Authorization: Bearer <leaked-token>"
```

!!! failure "Result"
    The token from the log authenticates as the victim. The account screen can also be captured with `adb exec-out screencap -p`, and the copied account number is readable from the clipboard.

### Fixed version

```kotlin
class LoginActivity : AppCompatActivity() {
    private fun onLoginSuccess(user: String) {
        // No secrets in logs. Keep messages generic.
        if (BuildConfig.DEBUG) Log.d("LoginActivity", "Login OK")
        startActivity(Intent(this, AccountActivity::class.java))
    }
}

class AccountActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Blocks screenshots, screen recording and recents thumbnails
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
    }

    private fun copyAccountNumber(number: String) {
        val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("acct", number).apply {
            description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        cm.setPrimaryClip(clip)
        Handler(Looper.getMainLooper()).postDelayed({ cm.clearPrimaryClip() }, 30_000)
    }
}
```

Strip the remaining log calls from release builds in `proguard-rules.pro`:

```text
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
}
```

!!! success "Verified"
    `adb logcat` shows no token, `screencap` returns a blank or blocked image on the account screen, and the copied value is flagged sensitive and cleared after 30 seconds.
