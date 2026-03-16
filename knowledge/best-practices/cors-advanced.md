# Advanced CORS Security

## DO

- **Cache preflight responses** with `Access-Control-Max-Age` (e.g., 86400 seconds). Uncached preflights add latency to every cross-origin request.
- **Validate origins against an allowlist** dynamically. Reflect only matching origins in `Access-Control-Allow-Origin` — never echo the `Origin` header blindly.
- **Be explicit with `Access-Control-Allow-Headers`** and `Access-Control-Allow-Methods`. List only the headers and methods your API actually uses.
- **Use `credentials: 'include'`** only when cookies or auth headers must cross origins. This tightens CORS: wildcards are forbidden, and the origin must be explicit.
- **Validate subdomain patterns carefully** — `*.example.com` in your allowlist logic must not match `evil-example.com`. Use exact suffix matching with a leading dot.
- **Set `Vary: Origin`** on responses when the CORS headers change based on the request origin. Without it, CDNs cache one origin's response for all origins.

## DON'T

- Set `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Browsers block this, but misconfigurations in proxies can bypass it.
- Reflect the `Origin` header directly as the `Access-Control-Allow-Origin` value without validation — this is equivalent to allowing all origins.
- Allow the `null` origin — it's sent from sandboxed iframes, `data:` URLs, and redirects. Attackers use it to bypass origin checks.
- Forget `Vary: Origin` — CDNs and proxies will serve a cached CORS response for `origin-a.com` to requests from `origin-b.com`.
- Use regex for origin validation without anchoring — `/example\.com/` matches `attacker-example.com`.
- Set `Access-Control-Max-Age` to 0 for debugging and forget to increase it for production.

## Common AI Mistakes

- Setting `origin: true` or `origin: '*'` in cors middleware config, allowing all origins.
- Implementing origin checking with `origin.includes('example.com')` which matches `evil-example.com`.
- Forgetting to handle `null` origin — accepting it because "it's not a real domain."
- Omitting `Vary: Origin` header, causing CDN cache poisoning across origins.
- Using regex `/.*.example.com/` without anchoring, matching `attacker.evil.example.com.malicious.com`.
