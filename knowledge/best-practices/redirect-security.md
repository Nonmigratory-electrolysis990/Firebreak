# Redirect Security

## DO

- **Allowlist permitted redirect destinations** — maintain an explicit list of domains or URL prefixes that are valid redirect targets.
```python
ALLOWED_REDIRECTS = ["https://app.example.com", "https://docs.example.com"]
target = request.args.get("next")
if not any(target.startswith(prefix) for prefix in ALLOWED_REDIRECTS):
    target = "/"
return redirect(target)
```
- **Use relative paths** for internal redirects — `/dashboard` instead of `https://example.com/dashboard` eliminates host manipulation.
- **Validate the full URL** — parse with a URL library, check the scheme (`https` only), host, and path. String prefix checking alone is insufficient.
- **Remove or encode user input from redirect URLs** — parameters in the redirect target can be manipulated for phishing.
- **Show an interstitial page** for external redirects — "You are leaving our site. Continue to [url]?" gives users a chance to verify the destination.
- **Log redirect targets** for security monitoring — unusual redirect destinations indicate exploitation attempts.

## DON'T

- Use user input directly in `Location` headers — `redirect(request.params.url)` is an open redirect.
- Check only the hostname prefix — `https://example.com.evil.com` starts with `https://example.com` but is a different domain.
- Allow `//evil.com` as a redirect target — protocol-relative URLs redirect to the attacker's domain.
- Use `javascript:` or `data:` scheme redirects — these execute code in the user's browser.
- Trust `Referer` header for post-login redirects — it's trivially spoofed and may be absent.
- Encode the redirect URL in a way that bypasses validation — double encoding, Unicode normalization, and case manipulation can defeat naive checks.
- Chain redirects through your domain — `example.com/redirect?url=example.com/redirect?url=evil.com` bypasses single-hop validation.

## Common AI Mistakes

- Generating post-login redirects with `redirect(req.query.next)` without any validation — textbook open redirect.
- Checking `url.startsWith("https://example.com")` — this matches `https://example.com.evil.com`.
- Using `new URL(userUrl).hostname === "example.com"` without checking the protocol — `javascript://example.com/%0aalert(1)` passes the hostname check.
- Implementing OAuth callback URLs that accept any `redirect_uri` parameter.
- Building "link shortener" or "go" services that redirect to arbitrary URLs without an allowlist or interstitial.
- Suggesting `encodeURIComponent()` on the redirect target — encoding prevents parameter injection but not open redirects.
