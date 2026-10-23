# XXE attacks via modified content type

**XXE via Content-Type Manipulation**

**Core Concept:** Convert regular requests to XML format to expose XXE vulnerabilities.

**Standard Request (HTML Form):**

```
POST /endpoint
Content-Type: application/x-www-form-urlencoded

param1=value1&param2=value2
```

**XML Version (Same Functionality):**

```
POST /endpoint
Content-Type: text/xml  ← Changed

<?xml version="1.0"?>
<param1>value1</param1>
<param2>value2</param2>
```

---

**How It Works:**

1. **Many applications accept multiple content types**
    - HTML forms default to `application/x-www-form-urlencoded`
    - But backend may also parse `text/xml` or `application/xml`
2. **Same data, different format**
    - Parameters become XML elements
    - Values become element content
3. **If XML parsing occurs → XXE attack surface opens**

---

**Testing Methodology:**

1. **Identify POST endpoints** that accept user data
2. **Change Content-Type** to `text/xml` or `application/xml`
3. **Convert parameters** to XML structure:
    - `name=value` → `<name>value</name>`
4. **Add XXE payload** in DOCTYPE
5. **Check if XML is parsed** (error messages, behavior changes)

---

**Example Attack Flow:**

**Original:**

```
POST /update
Content-Type: application/x-www-form-urlencoded

userId=123&name=test

```

**Modified for XXE:**

```
POST /update
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<userId>123</userId>
<name>&xxe;</name>

```

---

**Detection Tips:**

- Look for **error messages** indicating XML parsing
- Monitor for **different behavior** with XML vs form encoding
- Try various XML content types:
    - `text/xml`
    - `application/xml`
    - `application/xhtml+xml`

---

**Why This Works:**

- Backend often uses **generic parsers** handling multiple formats
- Legacy code may expect XML from older clients
- API endpoints might accept both JSON and XML
- Poor input validation on content-type headers