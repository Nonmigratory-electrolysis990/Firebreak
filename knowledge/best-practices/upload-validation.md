# Upload Validation Security

## DO

- **Validate file type by magic bytes** (file signature), not just extension or MIME type. Extensions and Content-Type headers are trivially spoofed.
- **Sanitize filenames** — strip path traversal sequences (`../`, `..\\`), null bytes, and special characters. Generate a random filename server-side; never use the original.
- **Enforce size limits** at multiple layers: reverse proxy (nginx `client_max_body_size`), application middleware, and storage quota per user.
- **Store uploads outside the webroot** or in a dedicated object storage (S3, GCS) with no direct execution permissions.
- **Serve uploaded files from a separate domain** (e.g., `uploads.example.com`) to isolate cookies and prevent XSS on the main domain.
- **Scan uploads with antivirus/malware detection** (ClamAV, VirusTotal API) before making them accessible. Quarantine until scanned.
- **Set `Content-Disposition: attachment`** on download responses to prevent browser rendering of malicious files.
- **Limit allowed file types** to an explicit allowlist. Reject everything not on the list.

```python
MAGIC_BYTES = {
    b'\x89PNG': 'image/png',
    b'\xff\xd8\xff': 'image/jpeg',
    b'%PDF': 'application/pdf',
}
def validate_magic(file_bytes: bytes) -> str | None:
    for magic, mime in MAGIC_BYTES.items():
        if file_bytes.startswith(magic):
            return mime
    return None  # Reject unknown types
```

## DON'T

- Trust `Content-Type` from the client. It's a user-controlled header, trivially changed with curl or Burp.
- Store files with the user-provided filename. `../../etc/passwd` or `shell.php.jpg` are classic attacks.
- Serve uploads from the same origin as your application — uploaded HTML/SVG will execute JavaScript in your domain's context.
- Allow executable file types (.php, .jsp, .exe, .sh, .bat) unless explicitly required and sandboxed.
- Skip size validation — a 10GB upload can DoS your server's disk and memory.
- Write uploads to a temp directory without cleanup — orphaned temp files fill disks.

## Common AI Mistakes

- Checking `file.mimetype === 'image/png'` (client-provided) instead of reading the file's magic bytes.
- Using `path.join(uploadDir, req.file.originalname)` — path traversal via filename.
- Storing uploads in `/public/uploads/` where they're directly accessible and executable by the web server.
- Not setting a max file size, allowing the default (unlimited in Express/multer without config).
- Serving user uploads inline (`Content-Disposition: inline`) allowing HTML uploads to execute as pages.
- Forgetting to handle the case where the upload directory doesn't exist, crashing the server.
