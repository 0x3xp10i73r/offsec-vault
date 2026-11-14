---
title: "Insufficient cryptography"
description: "ECB mode, hardcoded and derived keys, static IVs, weak hashing and insecure randomness in Android apps — finding them statically, decrypting offline, and the authenticated-crypto fix."
tags:
  - Android
  - Cryptography
  - Static Analysis
  - OWASP Mobile Top 10
---

# Insufficient cryptography

!!! note "What this page is doing"
    This is OWASP Mobile Top 10 **M10 — Insufficient cryptography**. The pattern across every case here is the same: the app does *something* that looks like encryption, but the key, the mode, or the randomness behind it is predictable enough that the "protection" can be reversed by anyone holding the APK. The goal of testing this class is to show that the ciphertext is not actually secret.

## Explanation

Cryptography on Android fails in a small number of predictable ways, almost always from developers treating encryption as a checkbox rather than a design problem:

- **ECB mode** — `AES/ECB/PKCS5Padding` encrypts each 16-byte block independently with no IV. Identical plaintext blocks produce identical ciphertext blocks, which leaks structure and, combined with a fixed key, makes the cipher trivially reversible.
- **Hardcoded or derived keys** — the key is a string constant, built from `BuildConfig` values, a package name, or some other value that is in or reconstructable from the APK.
- **Static IVs** — an initialization vector reused across every encryption call defeats the purpose of having one. For CBC it enables plaintext-recovery attacks; for GCM a reused nonce is a catastrophic failure that can expose the key.
- **Weak hashing** — `MD5` and `SHA-1` for anything security-relevant (password storage, integrity checks, token generation). Both are broken for collision resistance, and neither is a password hash in the first place.
- **Insecure randomness** — `java.util.Random` instead of `java.security.SecureRandom` for keys, IVs, tokens, or password-reset codes. `Random` is a deterministic PRNG seeded (often) from the clock; its output sequence can be predicted or brute-forced.
- **Keys stored next to ciphertext** — the key lives in `SharedPreferences`, a resource file, or a sibling field in the same serialized blob as the data it encrypts. Wherever the ciphertext is, the key travels with it.

Any one of these turns "encrypted" into "encoded." The fix for all of them is the same direction of travel: authenticated encryption (AES-GCM), a random IV/nonce per operation, `SecureRandom` everywhere randomness is needed, and key material that never leaves the Android Keystore.

## Exploitation

The attack is almost always offline, once the key is recovered:

1. Identify that data is "encrypted" (base64 blobs, binary blobs in a database or `SharedPreferences`, `=` padding suggesting a block cipher).
2. Decompile the APK and find the `Cipher.getInstance(...)` call to learn the algorithm and mode.
3. Find the key — usually a string constant, sometimes derived with a predictable KDF or hardcoded salt.
4. Reproduce the decryption offline with that key, independent of the app and the server.

If the IV is also static or absent (as it is for ECB), step 4 needs nothing else. No device, no root, no running app required — the APK alone is enough.

## Steps

1. Decompile the APK to readable Java with `jadx`, and unpack resources with `apktool`:

    ```bash
    jadx -d out_jadx vulnerable-app.apk
    apktool d vulnerable-app.apk -o out_apktool
    ```

2. Grep for the crypto API surface across the decompiled source:

    ```bash
    grep -Rnw out_jadx -e 'Cipher.getInstance' -e 'SecretKeySpec' \
      -e 'IvParameterSpec' -e 'MessageDigest' -e 'new Random('
    ```

3. Confirm the mode and padding directly in the match — `AES/ECB/...` and `AES/CBC/...` with no accompanying `SecureRandom` call are both worth flagging immediately.

4. Look for the key material near the crypto call, and in resources:

    ```bash
    grep -Rni -e 'key' -e 'iv' -e 'seed' out_apktool/res/values/strings.xml
    grep -Rnw out_jadx -e 'private static final String KEY' -e 'getBytes()'
    ```

5. If the key is derived rather than literal, trace the derivation (e.g. `MessageDigest.getInstance("MD5")` over a package name or a build constant) — a deterministic derivation from public values is equivalent to a hardcoded key.

6. Confirm at runtime with Frida if the key is assembled dynamically and static tracing does not resolve it fully:

    ```javascript
    Java.perform(function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (data) {
            console.log('[Cipher.doFinal] input: ' + bytesToHex(data));
            var result = this.doFinal(data);
            console.log('[Cipher.doFinal] output: ' + bytesToHex(result));
            return result;
        };
    });
    ```

    ```bash
    frida -U -f com.example.vulnerableapp -l hook_cipher.js --no-pause
    ```

7. With the algorithm, mode, and key confirmed, reproduce the decryption outside the app (Python/`openssl`) to prove the ciphertext is reversible without any device or server access.

## Remediation

- Use **authenticated encryption** — `AES/GCM/NoPadding` — never `ECB`, and never `CBC` without a separate MAC (prefer GCM over CBC+HMAC entirely).
- Generate a **random IV/nonce per encryption operation** with `SecureRandom`, and store it alongside the ciphertext (an IV is not secret — a key is).
- Generate and store keys in the **Android Keystore** (`AndroidKeyStore` provider) so the key material never exists as extractable bytes in the app's memory or storage, and can be bound to biometric/device-credential auth if appropriate.
- Replace `MD5`/`SHA-1` with `SHA-256` or `SHA-3` for integrity, and a dedicated password hash (`Argon2`, `bcrypt`, `scrypt`, or `PBKDF2WithHmacSHA256` with a high iteration count) for credentials — never a general-purpose hash for passwords.
- Replace every `java.util.Random` used for security purposes with `java.security.SecureRandom`.
- Never persist a key in `SharedPreferences`, a resource file, or next to the ciphertext it protects.

## Example

**Vulnerable: ECB mode with a hardcoded key**

```java
public class InsecureCrypto {
    // Hardcoded key, reused across every install of the app
    private static final String KEY = "0123456789abcdef";

    public static byte[] encrypt(byte[] plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes("UTF-8"), "AES");
        // ECB: no IV at all, identical blocks -> identical ciphertext
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext);
    }
}
```

**Exploit: decrypt offline, no device needed**

```bash
# Extracted from the decompiled source: fixed key, fixed mode.
# The ciphertext (base64) is pulled from SharedPreferences or a DB column.
echo -n "<base64-ciphertext>" | base64 -d > ct.bin

openssl enc -d -aes-128-ecb \
  -K 30313233343536373839616263646566 \
  -in ct.bin -out plaintext.bin

cat plaintext.bin
```

```python
# Equivalent reproduction in Python, for when the data needs further processing
from Crypto.Cipher import AES
import base64

key = b"0123456789abcdef"
ciphertext = base64.b64decode("<base64-ciphertext>")

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

**Fixed: AES-GCM with a Keystore-backed key**

```kotlin
object SecureCrypto {
    private const val KEYSTORE_ALIAS = "app_data_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true) // forces a fresh IV every call
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    // Returns iv || ciphertext-with-tag, so each call is independently decryptable
    fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv // random per call, generated by the provider
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    fun decrypt(ivAndCiphertext: ByteArray): ByteArray {
        val iv = ivAndCiphertext.copyOfRange(0, 12)
        val ciphertext = ivAndCiphertext.copyOfRange(12, ivAndCiphertext.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE, getOrCreateKey(),
            GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        )
        return cipher.doFinal(ciphertext)
    }
}
```

The key never leaves the Keystore as raw bytes, GCM authenticates the ciphertext (tamper attempts fail decryption instead of silently succeeding as they would under ECB/CBC), and a fresh random IV per call removes the pattern-leakage and nonce-reuse problems entirely.
