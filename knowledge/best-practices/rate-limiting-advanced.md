# Advanced Rate Limiting

## DO

- **Use sliding window counters** instead of fixed windows. Fixed windows allow burst traffic at window boundaries (2x the limit).
- **Implement token bucket** for APIs that need burst tolerance — it allows short bursts while enforcing average rate.
- **Rate limit per authenticated user** for logged-in endpoints. Per-IP alone fails behind NAT/corporate proxies (thousands of users share one IP).
- **Use distributed rate limiting** (Redis + Lua atomic scripts, or a dedicated service) when running multiple app instances. Local in-memory counters don't work behind a load balancer.
- **Apply different limits per endpoint** — login gets 5/min, search gets 30/min, read endpoints get 100/min. One-size-fits-all limits are either too strict or too loose.
- **Return `Retry-After` header** with `429` responses so clients know when to retry.
- **Rate limit by API key** for third-party integrations, separate from user-level limits.

## DON'T

- Use only per-IP rate limiting for authenticated APIs — legitimate users behind NAT get blocked while attackers use distributed IPs.
- Implement rate limiting only in application code without a reverse proxy layer. Application-level limits can be overwhelmed before they trigger.
- Use fixed-window counters for security-critical endpoints (login, password reset). Attackers can double their attempts at window boundaries.
- Store rate limit state in local memory when running multiple instances — each instance tracks independently, multiplying the effective limit.
- Set identical rate limits for all endpoints. Auth endpoints need much stricter limits than read endpoints.
- Forget to rate limit WebSocket message frequency — connection-level limits alone aren't enough.

## Common AI Mistakes

- Implementing rate limiting with in-memory `Map()` in a Node.js app behind a 3-instance load balancer (3x the intended limit).
- Using `express-rate-limit` defaults without configuring a Redis store for multi-instance deployments.
- Rate limiting only `POST /login` but not `POST /forgot-password` or `POST /verify-otp`.
- Setting a single global rate limit (`100 req/min`) instead of per-endpoint limits.
- Not including `Retry-After` header in 429 responses, causing clients to retry immediately in tight loops.
