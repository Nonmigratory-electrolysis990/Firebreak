# Cache Security

## DO

- **Set `Cache-Control: no-store`** on all responses containing sensitive data — authentication pages, account details, financial data, PII.
```
Cache-Control: no-store
```
- **Use `Cache-Control: private`** for user-specific content — prevents shared caches (CDNs, proxies) from storing personalized responses while allowing browser caching.
- **Set `Vary` header correctly** — `Vary: Cookie, Authorization, Accept-Encoding` ensures caches distinguish between different users and content types.
- **Use cache keys that include authentication state** — CDNs must not serve authenticated user responses to anonymous users or vice versa.
- **Implement cache purging** for content updates — stale cached content with a security fix still serves the vulnerable version.
- **Use `Cache-Control: no-cache`** (revalidate every request) for content that changes frequently but is not sensitive.
- **Sign or hash cached objects** to detect tampering in distributed cache systems (Redis, Memcached).

## DON'T

- Cache responses containing `Set-Cookie` headers in shared caches — a CDN serving cached `Set-Cookie` assigns one user's session to another.
- Use `Pragma: no-cache` as your only caching directive — it's HTTP/1.0 and ignored by modern caches. Use `Cache-Control`.
- Cache error pages that contain sensitive information — a 500 error with a stack trace cached by a CDN is visible to everyone.
- Cache API responses with user-specific data at the CDN level without per-user cache keys.
- Use predictable cache keys that can be poisoned — if the cache key is just the URL path, headers like `X-Forwarded-Host` can poison the cache for all users.
- Set long `max-age` on mutable resources — if the content changes, users see stale (potentially insecure) versions until the cache expires.
- Cache authentication tokens, CSRF tokens, or nonces — these must be unique per request/session.

## Common AI Mistakes

- Setting `Cache-Control: max-age=3600` on API responses that return user-specific data.
- Omitting `Cache-Control` headers entirely — browsers and proxies apply their own heuristic caching, which may cache sensitive responses.
- Using CDN caching with `Vary: *` — this effectively disables caching. Use specific header names in `Vary`.
- Configuring Cloudflare/Fastly to cache "everything" without excluding authenticated routes.
- Caching GraphQL POST responses at the CDN level — different POST bodies return different data, but the URL is the same.
- Not including `no-store` on logout responses — the post-logout page should not be cached, or the back button shows the logged-in state.
