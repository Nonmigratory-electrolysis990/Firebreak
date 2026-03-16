# JAMstack Security

## DO

- **Keep secrets out of static builds**. Environment variables used at build time are baked into the HTML/JS output. Only use public, non-sensitive values in build-time config.
- **Authenticate API routes and serverless functions individually**. Each function (`/api/checkout`, `/api/admin`) must verify auth — there's no shared middleware by default.
- **Validate and sanitize user input in serverless functions**. Treat every function as a standalone API endpoint with its own validation.
- **Configure CDN security headers**: CSP, X-Frame-Options, HSTS, X-Content-Type-Options. Set them in `_headers` (Netlify), `vercel.json`, or Cloudflare Page Rules.
- **Use signed/short-lived URLs** for accessing private content from storage (S3, Cloudflare R2). Don't make buckets public.
- **Implement rate limiting on API routes**. Use platform-level rate limiting (Vercel, Netlify) or edge middleware to prevent abuse.
- **Audit third-party scripts**. Static sites often embed analytics, chat widgets, and tracking pixels — each is a potential XSS vector.

## DON'T

- Put API keys, database URLs, or secrets in `gatsby-config.js`, `nuxt.config.ts`, or `astro.config.mjs` build config. They end up in the client bundle.
- Assume static sites are inherently secure because "there's no server." API routes, form handlers, and third-party services are all attack vectors.
- Use client-side JavaScript for access control on premium content. The HTML/JS is fully readable — server-side gating is required.
- Skip authentication on serverless functions because "only the frontend calls them." Anyone can call them directly.
- Serve user-uploaded content from the same domain as your static site. Use a separate domain or CDN origin to prevent cookie theft and stored XSS.
- Use `dangerouslySetInnerHTML`, `v-html`, `{@html}`, or equivalent to render CMS content without sanitization.
- Disable CSP because a third-party widget requires `unsafe-inline`. Use nonce-based CSP instead.

## Common AI Mistakes

- Setting `STRIPE_SECRET_KEY` in the build environment and referencing it in a Gatsby page component — it's bundled into the static output.
- Creating a `/api/delete-user` serverless function with no authentication because "only the admin page links to it."
- Building a paywall with `{isPremium ? <Content /> : <Paywall />}` — the content is in the JavaScript bundle regardless.
- Using `fetch('/api/data')` in static HTML without realizing the API route has no auth, making all data publicly accessible.
- Configuring a Netlify site with no `_headers` file, serving the site with zero security headers.
