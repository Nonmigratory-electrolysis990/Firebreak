# Path Traversal Prevention

## DO

- **Canonicalize then verify** — resolve the full path (`os.path.realpath()`, `Path.canonicalize()`, `fs.realpathSync()`) and confirm it starts with the intended base directory.
```python
base = os.path.realpath("/uploads")
target = os.path.realpath(os.path.join(base, user_filename))
if not target.startswith(base + os.sep):
    raise ValueError("Path traversal detected")
```
- **Use a chroot or scoped filesystem** — confine the process so `../../etc/passwd` resolves inside the jail.
- **Allowlist file extensions** — if users upload images, accept only `.jpg`, `.png`, `.gif`, `.webp`. Check after canonicalization.
- **Generate server-side filenames** — store files with UUIDs or hashes, map to original names in a database. Never use user-supplied filenames directly on disk.
- **Strip or reject path separators** — reject any input containing `/`, `\`, `..`, `%2e`, `%2f`, null bytes (`%00`).
- **Set restrictive filesystem permissions** — the web server process should only have read access to the document root, write access only to upload directories.

## DON'T

- Use user input directly in `open()`, `readFile()`, `include()`, `require()`, or `sendFile()` without validation.
- Strip `../` once and assume safety — `....//` becomes `../` after single-pass removal. Always canonicalize instead.
- Trust file extension from the request — check the extension after canonicalization, not from the original user string.
- Assume your framework handles it — many static file servers have had path traversal CVEs (Express `serve-static`, Spring `ResourceHttpRequestHandler`).
- Use relative paths in file operations — always resolve to absolute paths against a known base directory.
- Allow null bytes in filenames — languages like PHP historically truncated at null bytes, making `image.php%00.jpg` load as PHP.

## Common AI Mistakes

- Joining paths without canonicalization: `path.join("/uploads", userFile)` does NOT prevent `../` traversal in Node.js.
- Checking `if (!filename.includes(".."))` instead of canonicalizing — misses encoded variants (`%2e%2e`, `..%c0%af`).
- Generating file download endpoints that pass `req.params.filename` directly to `res.sendFile()`.
- Using `os.path.join(base, user_input)` in Python without `realpath()` — `os.path.join("/uploads", "/etc/passwd")` returns `/etc/passwd`.
- Stripping `../` in a loop but not handling `..\/` on Windows or URL-encoded sequences.
- Creating static file serving with `express.static(path.join(__dirname, req.params.dir))`.
