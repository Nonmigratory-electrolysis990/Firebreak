# Vue Security

## DO

- **Use `{{ }}` interpolation** for rendering user content. Vue's template syntax auto-escapes HTML by default.
- **Sanitize before using `v-html`** — use DOMPurify: `v-html="DOMPurify.sanitize(userContent)"`. Never bind unsanitized user input.
- **Implement route guards** with `router.beforeEach()` for auth checks. Verify tokens server-side on every API call — client guards are UX only.
- **Prefix client env vars** with `VITE_` (Vite) or `VUE_APP_` (Vue CLI). Only prefixed vars are bundled into the client.
- **Set CSP headers** on your server. Avoid `'unsafe-eval'` — Vue 3's compiler doesn't need it at runtime if you use pre-compiled templates.
- **Validate all props and API responses** with runtime type checking. Use Zod or Valibot for structured validation.
- **Use `rel="noopener noreferrer"`** on external links with `target="_blank"` to prevent reverse tabnapping.

## DON'T

- Use `v-html` with user-provided content without sanitization. It renders raw HTML and enables stored XSS.
- Compile user-provided strings as Vue templates at runtime (`new Vue({ template: userInput })`) — this is template injection leading to RCE in SSR.
- Store secrets in `VITE_` or `VUE_APP_` env vars. Everything prefixed is shipped to the browser.
- Disable Vue's built-in XSS protections by rendering user input through render functions with `innerHTML`.
- Trust `$route.params` or `$route.query` without validation — these are user-controlled.
- Use `eval()` or `new Function()` to dynamically execute user-provided code in Vue applications.
- Serve your Vue SPA without security headers (CSP, X-Frame-Options, HSTS).

## Common AI Mistakes

- Using `v-html="userBio"` to "preserve HTML formatting" from user profiles — direct stored XSS.
- Building a "secure" auth guard in `router.beforeEach()` that only checks `localStorage` for a token.
- Storing `VITE_STRIPE_SECRET_KEY` in `.env` and shipping it to the browser.
- Creating a dynamic component loader that compiles user-provided template strings: `<component :is="{ template: userInput }" />`.
- Using `v-on` with dynamic event names from user input, enabling arbitrary event handler injection.
