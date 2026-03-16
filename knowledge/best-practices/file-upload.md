# Secure File Upload

## DO

- **Validate MIME type via magic bytes**, not just the file extension. Use a library (file-type in Node, python-magic in Python).
- **Set a size limit** (10MB is reasonable for most apps). Enforce server-side, not just client-side.
- **Rename files with UUID**: `crypto.randomUUID() + extension`. Never use the original filename in the storage path.
- **Store outside the webroot** or in a separate storage service (S3, Supabase Storage) with restricted access.
- **Set Content-Disposition: attachment** when serving user uploads to prevent browser execution.
- **Scan for malware** (ClamAV) if accepting files from untrusted users.
- **Use signed URLs** for access control instead of public bucket URLs.

## DON'T

- Trust the file extension — `malware.exe` renamed to `cute-cat.jpg` is still an executable.
- Use the original filename in the storage path — it enables path traversal (`../../etc/passwd`).
- Store uploads in a publicly accessible directory without access control.
- Allow SVG uploads without sanitization — SVGs can contain JavaScript.
- Skip virus scanning for files that will be shared with other users.

## Common AI Mistakes

- Validating only the Content-Type header (trivially spoofed) instead of magic bytes.
- Using `path.join(uploadDir, req.file.originalname)` — direct path traversal vector.
- Making the S3/storage bucket public "for simplicity."
- Not setting a file size limit, enabling denial-of-service via giant uploads.
