# CSRF Protection

## DO

- **Set `SameSite=Strict` or `SameSite=Lax`** on all session cookies. `Lax` blocks cross-origin POST/PUT/DELETE; `Strict` blocks all cross-origin requests including navigation.
- **Use synchronizer token pattern** — generate a cryptographically random CSRF token per session, embed in forms, validate server-side on every state-changing request.
- **Implement double-submit cookies** as an alternative — set a random value in a cookie AND a request header/body field; the server checks they match.
- **Require custom headers** (`X-Requested-With`, `X-CSRF-Token`) on API endpoints — browsers block cross-origin custom headers without CORS preflight approval.
- **Use framework CSRF middleware** — Django (`CsrfViewMiddleware`), Rails (`protect_from_forgery`), Express (`csurf` replacement: `csrf-csrf`), Spring Security CSRF filter.
- **Validate `Origin` and `Referer` headers** as a defense-in-depth check on state-changing requests.
- **Re-authenticate for sensitive actions** (password change, email change, payment) regardless of CSRF token validity.

## DON'T

- Rely solely on `SameSite=Lax` — it allows GET requests cross-origin, so GET endpoints that modify state are still vulnerable.
- Use predictable CSRF tokens (session ID, timestamp, sequential counters). Tokens must be cryptographically random, at least 128 bits.
- Skip CSRF protection on JSON APIs — `Content-Type: application/json` can be set via `fetch()` from a malicious page if CORS is misconfigured.
- Validate CSRF tokens only on some routes — protect every POST, PUT, PATCH, DELETE endpoint.
- Use GET requests for state-changing operations (logout, delete, transfer) — GET requests bypass most CSRF defenses.
- Leak CSRF tokens in URLs — they end up in logs, Referer headers, and browser history.
- Disable CSRF protection in frameworks "because the frontend uses JWT" — if cookies carry the JWT, CSRF applies.

## Common AI Mistakes

- Omitting CSRF protection entirely in Next.js API routes because "it's a SPA."
- Using the deprecated `csurf` npm package (CVE-2024-29041) instead of maintained alternatives.
- Generating a single CSRF token at app startup instead of per-session or per-request.
- Implementing CSRF tokens in the frontend but forgetting to validate them on the server.
- Storing CSRF tokens in `localStorage` and sending them via header — this works but only if cookies aren't used for auth (if they are, CSRF is already the threat).
- Setting `SameSite=None` to "fix CORS issues" — this completely disables SameSite CSRF protection.
