# XSS Prevention

## DO

- **Context-encode all output** — HTML-encode for HTML body, JS-encode for script contexts, URL-encode for href attributes. Use a library like OWASP Java Encoder or `he` (Node.js).
- **Deploy Content Security Policy** with `script-src 'self'`. Start strict, loosen only with `'nonce-<random>'` per request — never `'unsafe-inline'`.
- **Sanitize HTML input** with DOMPurify (browser/Node) or Bleach (Python). Configure allowlists for tags and attributes explicitly.
- **Enable Trusted Types** via CSP `require-trusted-types-for 'script'` to block DOM XSS sinks (`innerHTML`, `document.write`, `eval`).
- **Use framework auto-escaping** — React's JSX, Vue's `{{ }}`, Angular's template binding all escape by default. Keep them on.
- **Set `HttpOnly` on session cookies** so XSS cannot steal session tokens even if it fires.
- **Validate and sanitize URL schemes** — reject `javascript:`, `data:`, and `vbscript:` in any user-supplied URL before rendering in `href` or `src`.

## DON'T

- Use `dangerouslySetInnerHTML` (React), `v-html` (Vue), or `[innerHTML]` (Angular) with user input. These bypass auto-escaping entirely.
- Build HTML strings via concatenation — `"<div>" + userInput + "</div>"` is an injection vector regardless of language.
- Rely solely on input validation (blocklisting `<script>`) — there are hundreds of bypass vectors (`<img onerror>`, `<svg onload>`, CSS `expression()`).
- Use CSP with `'unsafe-inline'` and `'unsafe-eval'` — this effectively disables CSP protection against XSS.
- Forget `src`/`href` attributes — `<a href="javascript:alert(1)">` is XSS without any `<script>` tag.
- Assume server-side rendering is safe — reflected XSS in SSR frameworks (Next.js, Nuxt) is the same vulnerability class.
- Sanitize once on input then trust forever — data flows change, re-encode on output.

## Common AI Mistakes

- Suggesting `DOMPurify.sanitize(input)` then immediately assigning to `innerHTML` without understanding that this IS the correct pattern — but applying DOMPurify then also encoding breaks the output.
- Generating React code with `dangerouslySetInnerHTML={{ __html: userComment }}` for "rich text" without any sanitization step.
- Writing CSP headers with `script-src 'self' 'unsafe-inline'` — the `'unsafe-inline'` negates the entire policy.
- Recommending `encodeURIComponent()` for HTML context — it's for URL parameters, not HTML body encoding.
- Creating a "sanitize" function that only strips `<script>` tags, missing event handlers (`onerror`, `onload`, `onfocus`).
- Using `.textContent` for reading but `.innerHTML` for writing — mixing safe reads with unsafe writes.
