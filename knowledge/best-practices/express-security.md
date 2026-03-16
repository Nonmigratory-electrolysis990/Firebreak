# Express Security

## DO

- **Use Helmet** (`app.use(helmet())`) as the first middleware. It sets 11 security headers including CSP, HSTS, and X-Content-Type-Options.
- **Validate all input** with a schema library (Zod, Joi, express-validator). Validate params, query, body, and headers — not just body.
- **Rate limit aggressively** with `express-rate-limit`. Apply stricter limits on auth endpoints (5 req/min login, 2 req/min password reset).
- **Configure sessions securely**: `httpOnly: true`, `secure: true`, `sameSite: 'strict'`, `maxAge` under 24 hours, and use a production store (Redis, not MemoryStore).
- **Return generic error messages** in production. Use a centralized error handler that logs the real error server-side and sends `{ error: "Something went wrong" }` to the client.
- **Force HTTPS** in production with `app.set('trust proxy', 1)` behind a reverse proxy, and redirect HTTP to HTTPS.
- **Disable `x-powered-by`** — Helmet does this, but if not using Helmet: `app.disable('x-powered-by')`.

## DON'T

- Use `body-parser` without size limits. Set `app.use(express.json({ limit: '100kb' }))` to prevent payload DoS.
- Pass user input directly into database queries. Use parameterized queries even with ORMs.
- Send stack traces to the client in production (`app.use((err, req, res, next) => res.status(500).json({ stack: err.stack }))`).
- Use `cors({ origin: '*' })` in production. Whitelist specific origins.
- Store sessions in the default `MemoryStore` — it leaks memory and doesn't survive restarts.
- Trust `req.ip` without configuring `trust proxy` correctly behind a load balancer.
- Use synchronous `fs` operations in request handlers — they block the event loop and enable DoS.

## Common AI Mistakes

- Adding `cors()` with no options (defaults to `origin: '*'`) and calling it "configured."
- Creating a login route that returns `{ error: "User not found" }` vs `{ error: "Wrong password" }` — this leaks user enumeration.
- Setting `express.json()` with no size limit, allowing multi-GB payloads.
- Writing error middleware that sends `err.message` directly to the client, leaking internal paths and SQL errors.
- Using `app.use(helmet())` but then overriding CSP with `contentSecurityPolicy: false` because inline scripts break.
