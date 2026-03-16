# Deserialization Security

## DO

- **Use JSON for data interchange** — it has no native code execution semantics. Pair with schema validation (Zod, JSON Schema, Pydantic).
- **Use safe serialization formats** — Protocol Buffers, MessagePack, FlatBuffers, or CBOR. These have defined schemas and no arbitrary object instantiation.
- **Validate and type-check after deserialization** — even with JSON, validate the structure matches expected types before use.
- **Isolate deserialization** in a sandboxed process with minimal privileges if native deserialization is unavoidable.
- **Sign serialized data** (HMAC-SHA256) if it must be stored client-side or transmitted — verify the signature before deserializing.
- **Maintain an allowlist of permitted classes** if using Java `ObjectInputStream` — override `resolveClass()` to reject unexpected types.

## DON'T

- Use Python `pickle` or `shelve` with untrusted data — `pickle.loads()` executes arbitrary code by design.
```python
# NEVER do this with user input
data = pickle.loads(request.body)  # Remote code execution
```
- Use Java native serialization (`ObjectInputStream`) with untrusted input — deserialization gadget chains enable RCE.
- Use PHP `unserialize()` on user input — object injection leads to RCE via `__wakeup()` and `__destruct()` magic methods.
- Use Ruby `Marshal.load()` with untrusted data — same class of vulnerability as pickle.
- Use YAML `yaml.load()` (Python) without `Loader=SafeLoader` — YAML supports arbitrary Python object instantiation by default.
- Trust serialized objects from cookies, hidden form fields, or URL parameters — these are fully attacker-controlled.
- Use `eval()`, `Function()`, or `vm.runInNewContext()` to "deserialize" JSON — use `JSON.parse()`.

## Common AI Mistakes

- Using `yaml.load(data)` in Python without specifying `Loader=yaml.SafeLoader` — the default `FullLoader` still allows some dangerous types.
- Suggesting `pickle` for caching or session storage without noting the RCE risk from untrusted sources.
- Generating Java code that reads `ObjectInputStream` from HTTP request bodies.
- Using `eval(json_string)` in JavaScript instead of `JSON.parse()` "because it handles more formats."
- Implementing session storage with serialized Python objects in cookies.
- Suggesting `jsonpickle` as a "safe" alternative to pickle — it still instantiates arbitrary objects.
