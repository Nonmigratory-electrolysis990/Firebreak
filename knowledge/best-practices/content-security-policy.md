# Content Security Policy

## DO

- **Use nonce-based CSP** as the primary strategy. Generate a cryptographic random nonce per request, apply it to `<script nonce="...">` tags, and set `script-src 'nonce-{value}'`.
- **Add `'strict-dynamic'`** to allow nonce-trusted scripts to load their dependencies. This makes CSP compatible with bundlers and dynamic script loading.
- **Start with report-only mode** (`Content-Security-Policy-Report-Only`) to identify violations before enforcing. Analyze reports, fix violations, then switch to enforced mode.
- **Set `report-uri` or `report-to`** directives to collect violation reports. Use a service (report-uri.com, Sentry CSP) to aggregate and alert on violations.
- **Restrict `default-src 'self'`** as a fallback. Every directive not explicitly set inherits from `default-src`.
- **Block inline styles** with `style-src 'nonce-{value}'` or `'self'` — inline styles can be used for data exfiltration via CSS injection.
- **Set `frame-ancestors 'none'`** (or specific origins) to prevent clickjacking. This replaces the `X-Frame-Options` header.
- **Upgrade insecure requests** with `upgrade-insecure-requests` to auto-convert HTTP resource URLs to HTTPS.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{random}' 'strict-dynamic';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: https:;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
  report-uri /csp-report;
```

## DON'T

- Use `'unsafe-inline'` for scripts. This disables CSP's XSS protection entirely — any injected script runs.
- Use `'unsafe-eval'` unless absolutely required (some frameworks need it, but investigate alternatives first).
- Allowlist entire CDN domains (`script-src cdn.jsdelivr.net`). Any package on that CDN can now execute scripts on your page.
- Set CSP once and forget it. Review the policy when adding new third-party scripts, analytics, or features.
- Use `*` in any directive. `default-src *` is effectively no CSP.
- Rely on CSP alone for XSS prevention. CSP is defense-in-depth — output encoding is the primary defense.
- Ignore violation reports. Unexpected violations may indicate injection attempts.

## Common AI Mistakes

- Setting `script-src 'self' 'unsafe-inline' 'unsafe-eval'` — this disables all meaningful protection.
- Forgetting to generate a unique nonce per request — reusing the same nonce across requests allows attackers to predict it.
- Adding `script-src https:` which allows scripts from any HTTPS origin, not just your own.
- Not including `base-uri 'self'` — `<base>` tag injection can redirect all relative URLs to an attacker's domain.
- Skipping `form-action 'self'` — injected forms can POST credentials to external servers.
- Deploying CSP in enforcement mode without a report-only testing phase, breaking the application for all users.
