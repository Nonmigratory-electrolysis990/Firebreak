# SSRF Prevention

## DO

- **Allowlist destination hosts/URLs** — maintain an explicit list of permitted external domains. Reject everything else.
- **Block private/internal IP ranges** — reject `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254` (cloud metadata), `::1`, `fd00::/8`, and `0.0.0.0`.
- **Resolve DNS before validation** — resolve the hostname, then check the resolved IP against the blocklist. This prevents DNS rebinding where a domain resolves to `127.0.0.1`.
- **Disable HTTP redirects** or re-validate the destination after each redirect — attackers use redirects to bypass URL validation.
- **Block cloud metadata endpoints** explicitly — AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254`. Use IMDSv2 on AWS (requires token header).
- **Run URL-fetching services in isolated networks** — use a dedicated subnet with no access to internal services or metadata endpoints.
- **Validate URL scheme** — allow only `https://` (and `http://` if required). Block `file://`, `gopher://`, `dict://`, `ftp://`.

## DON'T

- Parse URLs with regex — URL parsers handle encoding, Unicode, and edge cases that regex misses. Use `new URL()` (JS), `urllib.parse` (Python), `java.net.URI`.
- Trust user-supplied URLs for webhooks, image imports, or link previews without validation — these are the most common SSRF entry points.
- Check the hostname string without resolving DNS — `http://spoofed.attacker.com` can resolve to `127.0.0.1`.
- Allow URL shorteners or redirectors — `bit.ly/xyz` can redirect to internal services.
- Blocklist only `localhost` and `127.0.0.1` — there are dozens of bypasses: `0x7f000001`, `2130706433`, `127.0.0.1.nip.io`, `[::]`, `0`.
- Return raw responses from internal services to the user — even if the request is blocked, error messages may leak internal topology.

## Common AI Mistakes

- Validating the URL string but not the resolved IP — `http://evil.com` that DNS-resolves to `169.254.169.254` bypasses string checks.
- Using `urlparse` to check the hostname but not handling `http://user@internal-host:80@evil.com` parser confusion.
- Implementing SSRF protection in middleware but using a different HTTP client elsewhere that bypasses it.
- Suggesting `requests.get(url, allow_redirects=False)` without also validating the initial URL.
- Blocking `169.254.169.254` but not `[::ffff:169.254.169.254]` (IPv4-mapped IPv6 address).
- Generating webhook-handling code that fetches any user-provided URL without any SSRF protection.
