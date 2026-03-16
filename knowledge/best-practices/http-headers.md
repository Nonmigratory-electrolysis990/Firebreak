# HTTP Security Headers

## DO

- **Set `Strict-Transport-Security`** — `max-age=63072000; includeSubDomains; preload` forces HTTPS for 2 years, including subdomains. Submit to the HSTS preload list.
- **Deploy Content-Security-Policy** — start with `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`. Loosen per-directive as needed.
- **Set `X-Content-Type-Options: nosniff`** — prevents browsers from MIME-sniffing responses away from the declared `Content-Type`. A JavaScript file served as `text/plain` won't execute.
- **Set `X-Frame-Options: DENY`** (or `SAMEORIGIN`) to prevent clickjacking. Prefer CSP `frame-ancestors 'none'` which supersedes it.
- **Set `Referrer-Policy: strict-origin-when-cross-origin`** — sends origin (not full URL) on cross-origin requests, full URL on same-origin. Prevents leaking paths and query parameters.
- **Set `Permissions-Policy`** to disable unused browser APIs — `camera=(), microphone=(), geolocation=(), payment=()`.
- **Set `Cross-Origin-Opener-Policy: same-origin`** and `Cross-Origin-Embedder-Policy: require-corp` to enable cross-origin isolation and prevent Spectre-class attacks.

## DON'T

- Set `X-XSS-Protection` — it's deprecated, removed from modern browsers, and in `mode=block` can introduce information leaks. Remove it entirely.
- Deploy CSP in report-only mode permanently — `Content-Security-Policy-Report-Only` is for testing. Graduate to enforcing mode.
- Set `Access-Control-Allow-Origin: *` on authenticated endpoints — this allows any site to read the response. Use specific origins.
- Forget to set headers on error pages, redirects, and API responses — not just on your main HTML pages.
- Use `X-Frame-Options: ALLOW-FROM` — it's not supported in modern browsers. Use CSP `frame-ancestors` instead.
- Set `Referrer-Policy: no-referrer` globally — it breaks OAuth flows and analytics. Use `strict-origin-when-cross-origin` as a balanced default.

## Common AI Mistakes

- Including `X-XSS-Protection: 1; mode=block` as a "security header" — it's actively harmful in modern browsers.
- Setting CSP with `'unsafe-inline'` and `'unsafe-eval'` to avoid breakage — this disables the primary protections CSP provides.
- Adding security headers only in the application code but not on the reverse proxy — static assets, error pages, and redirects are unprotected.
- Generating a permissive CSP to "get it working" and never tightening it.
- Setting `Permissions-Policy` syntax as `Feature-Policy` — the header was renamed; `Feature-Policy` is deprecated.
- Recommending `CORS` headers as security headers — CORS loosens the same-origin policy, it doesn't add security.
