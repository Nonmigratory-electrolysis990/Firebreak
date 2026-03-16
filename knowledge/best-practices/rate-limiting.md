# Rate Limiting

## DO

- **Apply rate limits at multiple layers**: reverse proxy (nginx/Caddy), application middleware, and per-endpoint.
- **Use different limits for different endpoints**: login (5/min), API (100/min), file upload (10/min).
- **Rate limit by user ID** for authenticated endpoints, **by IP** for unauthenticated ones.
- **Return `429 Too Many Requests`** with a `Retry-After` header so clients know when to retry.
- **Use sliding window or token bucket** algorithms — fixed windows have burst issues at window boundaries.
- **Rate limit failed auth attempts aggressively**: 5 failures → lock for 15 minutes or require CAPTCHA.

## DON'T

- Skip rate limiting on login/signup — these are the #1 brute-force target.
- Rate limit only by IP — shared IPs (corporate NAT, VPNs) will block legitimate users.
- Return detailed error messages on rate limit ("You've made 97 of 100 requests") — this helps attackers calibrate.
- Implement rate limiting only in the frontend — attackers bypass the frontend entirely.
- Forget to rate limit password reset and email verification endpoints — these are used for email bombing.

## Common AI Mistakes

- Not implementing rate limiting at all — AI-generated apps almost never include it.
- Using in-memory rate limiting that resets on server restart and doesn't work with multiple instances.
- Setting limits too high to be effective (10,000 req/min on login).
