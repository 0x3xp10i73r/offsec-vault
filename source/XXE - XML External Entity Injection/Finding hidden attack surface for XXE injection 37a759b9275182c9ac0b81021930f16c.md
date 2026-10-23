# Finding hidden attack surface for XXE injection

**Hidden XXE Attack Surfaces**

**Beyond Obvious XML Inputs:**

- Not all XXE vulnerabilities are in explicit XML requests
- Attack surface can exist where XML is processed server-side

---

**XInclude Attacks**

**Use Case:** When you control only part of data inserted into server-side XML documents.

**How It Works:**

- XInclude allows XML documents to be built from sub-documents
- Can include external files/URLs in XML
- Works without controlling the entire XML structure

**Attack Example:**

```xml
<foo xmlns:xi="<http://www.w3.org/2001/XInclude>">
    <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Requirements:**

1. **XInclude namespace declaration:** `xmlns:xi="<http://www.w3.org/2001/XInclude>"`
2. **`xi:include` element:** Specifies file to include
3. **`parse="text"`:** Treat included content as text (not XML)
4. **`href` attribute:** Points to target file/URL

---

**Common Scenarios for XInclude:**

1. **Client data → Back-end SOAP requests**
    - User input embedded into SOAP XML server-side
    - Cannot modify DOCTYPE but can inject XInclude
2. **Form fields → XML processing**
    - Form values inserted into XML templates
    - Single field control sufficient for attack
3. **API parameters → XML generation**
    - Parameters transformed into XML structures
    - Partial control enables XInclude injection

---

**Advantages Over Classic XXE:**

- **No DOCTYPE needed** – Works within any XML element
- **Partial control sufficient** – Only need one injectable field
- **Bypasses DTD restrictions** – Uses XInclude namespace instead

**Limitations:**

- Requires XML parser to support XInclude
- May need to trigger XML parsing of injected content
- Different syntax than traditional XXE

---

**Detection Strategy:**

1. Identify points where user data might be XML-encoded
2. Test parameters that could end up in XML structures
3. Look for XML-like processing in application flow
4. Try XInclude payloads in all user-controllable inputs