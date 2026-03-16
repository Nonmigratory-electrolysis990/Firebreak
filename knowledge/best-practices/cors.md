# CORS Configuration

## DO

- **Set specific allowed origins**: `Access-Control-Allow-Origin: https://myapp.com`. List each allowed domain explicitly.
- **Validate the Origin header** against an allowlist on the server before reflecting it.
- **Use `credentials: true`** only when cookies/auth headers are needed, and never with `origin: *`.
- **Restrict allowed methods** to what you actually use (GET, POST) — don't allow PUT/DELETE if unused.
- **Restrict allowed headers** — only list headers your frontend actually sends.
- **Cache preflight responses** with `Access-Control-Max-Age` (e.g., 86400 for 24h) to reduce OPTIONS requests.

## DON'T

- Set `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — this allows any site to make authenticated requests.
- Reflect the Origin header without validation — `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` with no allowlist is equivalent to `*`.
- Allow all methods and all headers "to be safe" — this maximizes attack surface.
- Forget that CORS is enforced by the browser, not the server — API tools like curl ignore CORS entirely. CORS protects users, not the API.

## Common AI Mistakes

- Using `cors()` with no options (Express) — this defaults to `origin: *`.
- Reflecting the Origin header directly without checking against an allowlist.
- Setting `credentials: true` with `origin: '*'` — browsers block this, so the dev removes the credential requirement instead of fixing CORS.
