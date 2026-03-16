# Third-Party Script Security

## DO

- **Use Subresource Integrity (SRI)** on all externally hosted scripts: `<script src="..." integrity="sha384-..." crossorigin="anonymous">`. This prevents tampered CDN responses from executing.
- **Load third-party scripts in sandboxed iframes** when they don't need DOM access. Use `sandbox="allow-scripts"` without `allow-same-origin`.
- **Configure Content Security Policy** with specific `script-src` directives. List exact CDN hostnames instead of wildcards.
- **Validate `postMessage` origin** in every message handler: `if (event.origin !== 'https://trusted.com') return`. Never process messages from any origin.
- **Audit third-party scripts quarterly** — check for new network requests, DOM access patterns, and data exfiltration. Use browser DevTools Network tab or a tool like Feroot.
- **Self-host critical scripts** (analytics, payment forms) after verifying their integrity. This eliminates CDN compromise as a vector.
- **Use `async` or `defer`** on third-party scripts to prevent render blocking, and load non-critical scripts after user interaction.

## DON'T

- Load scripts from CDNs without SRI hashes — a compromised CDN serves malicious code to all your users.
- Use `postMessage('*')` as the target origin. Always specify the exact expected origin.
- Grant `allow-same-origin` in sandbox iframes for untrusted content — it negates the sandbox.
- Trust third-party scripts to handle their own security. They have full DOM and cookie access once loaded.
- Add Google Tag Manager or similar tag managers without reviewing all injected tags — anyone with GTM access can inject arbitrary scripts.
- Load scripts over HTTP — a network attacker can modify them in transit.

## Common AI Mistakes

- Adding `<script src="https://cdn.example.com/lib.js">` without `integrity` or `crossorigin` attributes.
- Implementing `postMessage` listeners with `window.addEventListener('message', handler)` and no origin check.
- Setting CSP `script-src 'unsafe-inline' 'unsafe-eval' *` to "make third-party scripts work."
- Trusting CDN URLs as inherently safe because they're from well-known providers.
- Loading analytics scripts synchronously in `<head>`, blocking rendering and creating a single point of failure.
