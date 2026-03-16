# Image Processing Security

## DO

- **Transcode all uploads** to a safe format (e.g., re-encode to PNG/JPEG via a library). This strips embedded scripts, metadata, and polyglot payloads.
- **Strip EXIF/metadata** before storing or serving. EXIF contains GPS coordinates, device info, and sometimes thumbnail images of cropped content.
- **Enforce dimension limits** (e.g., max 10,000 x 10,000 pixels). Decompression bombs use small file sizes with enormous pixel dimensions to exhaust memory.
- **Process images in a sandboxed environment** — container, subprocess with memory/CPU limits, or a dedicated service. Never process in the main web process.
- **Validate SVGs as XML** and strip all `<script>`, `<foreignObject>`, `on*` event attributes, and `xlink:href` to non-image targets. Or reject SVGs entirely.
- **Use maintained libraries** (sharp, libvips, Pillow) and keep them updated. ImageMagick has a history of critical CVEs.
- **Set resource limits** on your image processing library (memory, time, file size). In ImageMagick, use a restrictive `policy.xml`.
- **Serve processed images with correct `Content-Type`** headers. Never let the browser guess via content sniffing.

## DON'T

- Pass user-uploaded filenames or URLs directly to ImageMagick/GraphicsMagick command line. This enables command injection and SSRF.
- Allow SVG uploads without sanitization. SVGs are XML documents that can contain JavaScript, external entity references, and SSRF payloads.
- Trust the file extension to determine processing pipeline. A `.jpg` file can contain a PNG, SVG, or exploit payload.
- Process images synchronously in the HTTP request handler — use a background queue.
- Serve original uploads alongside processed versions. Only serve the transcoded output.
- Allow unbounded image dimensions — a 100,000 x 100,000 pixel PNG requires ~40GB of RAM to decode.

## Common AI Mistakes

- Using `ImageMagick` `convert` with `system()` or `exec()` and interpolating the filename: `exec(\`convert ${filename} output.png\`)`.
- Accepting SVG uploads and rendering them in `<img>` tags without sanitization — SVG XSS still fires in some contexts.
- Not setting memory limits on sharp/Pillow, allowing decompression bombs to OOM the server.
- Forgetting to strip EXIF data, leaking user GPS coordinates in served images.
- Using ImageMagick without a restrictive `policy.xml`, leaving all coders and delegates enabled (ImageTragick CVE-2016-3714).
- Allowing URL-based image input (`convert https://...`) without SSRF protection — attackers fetch internal services.
