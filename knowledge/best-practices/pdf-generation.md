# PDF Generation Security

## DO

- **Sanitize all user data** before embedding in HTML templates for PDF generation. Apply context-appropriate escaping (HTML entity encoding).
- **Restrict network access** in the PDF renderer. Disable external resource loading or allowlist specific domains. This prevents SSRF via `<img src="http://169.254.169.254/...">`.
- **Use a sandboxed renderer** — run headless Chrome/Puppeteer/wkhtmltopdf in a container with no network access to internal services, limited filesystem, and restricted memory.
- **Disable JavaScript execution** in the PDF renderer if not needed. `wkhtmltopdf --disable-javascript`, Puppeteer `page.setJavaScriptEnabled(false)`.
- **Set resource limits** — timeout (30 seconds max), memory cap, and CPU limits on the rendering process.
- **Validate template inputs** — reject HTML tags in user data fields that should be plain text. Use a templating engine with auto-escaping (Jinja2, Handlebars).
- **Generate PDFs server-side only**. Never let the client control the full HTML template — only provide data fields.
- **Log PDF generation events** with the template used, user ID, and data fields (not the full content) for audit.

## DON'T

- Pass raw user input into HTML templates without escaping. `<script>` tags and CSS `url()` values execute in the renderer.
- Allow user-controlled URLs in `<link>`, `<img>`, `<iframe>`, or CSS `url()` within the PDF template. Each is an SSRF vector.
- Run wkhtmltopdf/Puppeteer with access to the cloud metadata endpoint (169.254.169.254). Use network policies to block it.
- Use `innerHTML` or raw string concatenation to build PDF templates with user data.
- Allow user-uploaded HTML to be rendered as PDF — this is arbitrary code execution in the renderer.
- Ignore the renderer's exit code or stderr — crashes may indicate exploitation attempts.

## Common AI Mistakes

- Building HTML with template literals: `` `<h1>${userName}</h1>` `` — direct XSS into the PDF renderer, leading to SSRF.
- Not blocking internal network access, allowing `<img src="http://metadata.google.internal/...">` to leak cloud credentials.
- Using wkhtmltopdf with default settings (JavaScript enabled, network unrestricted, no timeout).
- Trusting that PDF output is "safe" because it's a file — PDFs can contain JavaScript that executes in viewers.
- Letting users provide arbitrary CSS, enabling `@import url('http://internal-service/')` SSRF.
- Not setting `--no-stop-slow-scripts` timeout, allowing infinite loops to hang the renderer.
