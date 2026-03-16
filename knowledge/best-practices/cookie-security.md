# Cookie Security

## DO

- **Set `HttpOnly`** on all session and authentication cookies — prevents JavaScript from reading them, neutralizing XSS token theft.
- **Set `Secure`** on all cookies in production — ensures they are only sent over HTTPS, never in plaintext.
- **Set `SameSite=Strict`** for session cookies (or `Lax` if cross-site navigation with sessions is required). This blocks CSRF by default.
- **Use `__Host-` prefix** for session cookies — `__Host-SessionId=abc` requires `Secure`, no `Domain`, and `Path=/`. Prevents subdomain and path confusion attacks.
```
Set-Cookie: __Host-SessionId=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```
- **Set `Max-Age` or `Expires`** explicitly — avoid session cookies that persist indefinitely. 1-24 hours for session cookies; shorter for sensitive operations.
- **Scope `Path`** narrowly when possible — a cookie at `Path=/api` is not sent to `/public` routes.
- **Encrypt cookie values** if they contain any user data — even with `HttpOnly`, cookies are visible in server logs and proxies.

## DON'T

- Store sensitive data in cookies without encryption — cookies are sent in headers visible to proxies, load balancers, and logging.
- Use `SameSite=None` without `Secure` — browsers reject `SameSite=None` without `Secure`. But more importantly, `None` disables CSRF protection.
- Set `Domain=.example.com` on session cookies unless necessary — this makes them available to all subdomains, any of which could be compromised.
- Create cookies without `HttpOnly` for session tokens — no legitimate frontend code needs to read the session cookie.
- Use `document.cookie` to manage authentication state — this indicates `HttpOnly` is not set.
- Set `Max-Age` to years for session tokens — long-lived cookies are stolen credentials waiting to be exploited.
- Share cookies between HTTP and HTTPS by omitting `Secure` — a network MITM on HTTP steals them.

## Common AI Mistakes

- Setting cookies with `res.cookie("session", token)` using Express defaults — no `HttpOnly`, no `Secure`, no `SameSite`.
- Using `__Secure-` prefix but forgetting that `__Host-` is strictly stronger (also requires `Path=/` and no `Domain`).
- Setting `SameSite=None` to "fix" third-party integrations without understanding the CSRF implications.
- Generating authentication code that stores JWTs in cookies without `HttpOnly` because "the frontend needs to read the expiry."
- Creating cookies with `Domain` set to a parent domain, exposing them to every subdomain including user-controlled ones.
- Using `session.cookie.secure = false` in development and deploying it to production unchanged.
