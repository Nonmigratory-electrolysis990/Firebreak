# XML Security

## DO

- **Disable external entity processing** in every XML parser you use — this is the XXE vulnerability, and it's enabled by default in most parsers.
```python
# Python defusedxml
from defusedxml.ElementTree import parse
tree = parse("data.xml")  # XXE-safe by default
```
```java
// Java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
- **Disable DTD processing entirely** when DTDs are not required — this prevents entity expansion attacks (billion laughs).
- **Use JSON instead of XML** for APIs when possible — JSON has no entity processing, no DTDs, and a smaller attack surface.
- **Use `defusedxml`** (Python), `libxml_disable_entity_loader(true)` (PHP < 8.0), or `XMLConstants.FEATURE_SECURE_PROCESSING` (Java).
- **Limit XML document size** and nesting depth — prevent denial of service from deeply nested elements or large documents.
- **Validate XML against a strict schema** (XSD) before processing to reject unexpected structures.

## DON'T

- Use Python's `xml.etree.ElementTree` with untrusted input without `defusedxml` — it's vulnerable to XXE and entity expansion.
- Parse XML from file uploads, SOAP endpoints, or SVG files without disabling external entities.
- Use `XMLReader` or `SAXParser` in Java with default settings — external entities are enabled by default.
- Allow XSLT processing on user-supplied XML — XSLT can read files and make network requests.
- Forget SVG files are XML — uploaded SVG files can contain XXE payloads. Parse and sanitize them.
- Return raw XML parsing errors to users — error messages can leak file contents or internal paths.

## Common AI Mistakes

- Using `xml.etree.ElementTree.parse()` in Python without switching to `defusedxml` — the standard library parser is vulnerable.
- Setting only `external-general-entities` to false in Java but forgetting `external-parameter-entities` and doctype declarations.
- Generating SOAP clients that accept arbitrary XML responses without secure parser configuration.
- Accepting SVG uploads and serving them directly without sanitization — embedded JavaScript and XXE payloads execute in browsers.
- Configuring one XML parser securely but using a different parser instance elsewhere with default (insecure) settings.
- Suggesting `lxml.etree.parse()` without `resolve_entities=False` and `no_network=True`.
