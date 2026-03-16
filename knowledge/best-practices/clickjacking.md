# Clickjacking Prevention

## DO

- **Set `Content-Security-Policy: frame-ancestors 'none'`** to prevent your site from being framed by any origin. Use `frame-ancestors 'self'` if same-origin framing is needed.
- **Set `X-Frame-Options: DENY`** as a fallback for older browsers that don't support CSP `frame-ancestors`.
```
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
```
- **Set `SameSite=Strict`** on session cookies — even if framed, cookies won't be sent cross-origin, making clickjacking attacks ineffective for authenticated actions.
- **Add frame-busting JavaScript** as a defense-in-depth layer — detect if `window.top !== window.self` and break out or hide content.
```javascript
if (window.top !== window.self) {
  document.body.style.display = "none";
  window.top.location = window.self.location;
}
```
- **Apply framing restrictions on all pages** — not just the login page. Any authenticated action can be a clickjacking target.
- **Use confirmation dialogs for destructive actions** — a framed page can click a button but cannot interact with a browser-native dialog.

## DON'T

- Use `X-Frame-Options: ALLOW-FROM` — it's not supported by Chrome or Safari. Use CSP `frame-ancestors` with specific origins instead.
- Set `frame-ancestors` or `X-Frame-Options` only on the homepage — every page that performs actions needs protection.
- Rely solely on JavaScript frame-busting — it can be bypassed with `sandbox` attribute on the iframe (`<iframe sandbox>`), which blocks scripts.
- Forget API responses — browsers don't frame API responses, but the headers should still be set for defense-in-depth.
- Use `frame-ancestors *` — this explicitly allows all origins to frame your site.
- Assume SPAs are immune — React/Vue/Angular apps are equally frameable if headers are not set.

## Common AI Mistakes

- Omitting `X-Frame-Options` and `frame-ancestors` entirely from application security headers.
- Setting `X-Frame-Options: SAMEORIGIN` when the intent is to block all framing — use `DENY` if no legitimate framing exists.
- Implementing frame-busting JavaScript without the `display: none` fallback — the content is visible for a moment before the script executes.
- Generating CSP headers with `frame-ancestors` inside `<meta>` tags — `frame-ancestors` is ignored in meta tags, it must be an HTTP header.
- Configuring framing protection on the frontend framework (helmet.js, Django middleware) but not on the reverse proxy — static assets and error pages are unprotected.
- Using `sandbox` attribute on iframes they control and expecting it to prevent clickjacking on external sites — `sandbox` restricts the framed content, not the framing.
