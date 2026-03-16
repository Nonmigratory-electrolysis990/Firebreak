# IP Allowlisting Security

## DO

- **Configure trusted proxy settings** in your framework (`trust proxy` in Express, `SECURE_PROXY_SSL_HEADER` in Django). Without this, `X-Forwarded-For` is trivially spoofable.
- **Extract the client IP from the correct position** in `X-Forwarded-For`. The rightmost IP added by your trusted proxy is the real client IP, not the leftmost.
- **Support IPv6** in your allowlist. Many cloud providers use IPv6 by default. Normalize addresses before comparison.
- **Use CIDR notation** for ranges instead of individual IPs. Corporate networks and VPNs have dynamic IPs within a range.
- **Combine IP allowlisting with authentication** — IP restrictions are a defense layer, not a replacement for auth.
- **Log blocked requests** with the attempted IP, requested path, and timestamp for incident investigation.
- **Review allowlists regularly** — remove stale entries when employees leave or vendors change IPs.

## DON'T

- Trust `X-Forwarded-For` without configuring trusted proxies — any client can set this header.
- Use IP allowlisting as the sole authentication mechanism for sensitive endpoints.
- Hardcode IP allowlists in application code. Use environment variables or a configuration service for runtime updates.
- Forget that VPN and proxy users share IPs — allowlisting one VPN exit node may grant access to all its users.
- Block by IP without providing clear error messages — users behind corporate proxies won't know why they can't connect.
- Compare IPv4 and IPv6 without normalization (e.g., `::ffff:192.168.1.1` vs `192.168.1.1`).

## Common AI Mistakes

- Reading `req.headers['x-forwarded-for']` directly without trusted proxy configuration.
- Taking the first (leftmost) IP from `X-Forwarded-For` — this is client-controlled and spoofable.
- Implementing allowlists with string comparison instead of CIDR range checking.
- Ignoring IPv6 entirely, breaking access for IPv6-only clients.
- Putting IP allowlist logic in frontend code where it can be bypassed.
