# Svelte Security

## DO

- **Rely on Svelte's default escaping** — `{variable}` in templates auto-escapes HTML. Use this for all user-generated content.
- **Sanitize before using `{@html}`** — use DOMPurify: `{@html DOMPurify.sanitize(userContent)}`. The `@html` directive renders raw HTML.
- **Authenticate in SvelteKit `hooks.server.ts`** — use the `handle` hook to validate sessions on every request before any load function runs.
- **Validate in `+page.server.ts` load functions**. Server load functions run on the server — verify auth and authorization here, not in `+page.svelte`.
- **Use SvelteKit form actions** for mutations. They include CSRF protection by default and work without JavaScript.
- **Keep secrets in `$env/static/private`** or `$env/dynamic/private`. Only `$env/static/public` and `$env/dynamic/public` are exposed to the client.
- **Validate form action input** on the server. Use Zod or Valibot in `+page.server.ts` action handlers.

## DON'T

- Use `{@html userInput}` without sanitization. It renders arbitrary HTML including `<script>` tags.
- Import from `$env/static/private` in client-side code — SvelteKit will error, but don't try to work around it.
- Skip auth checks in API routes (`+server.ts`). Middleware (`hooks.server.ts`) handles it globally, but verify your hook covers all paths.
- Trust `event.params` or `event.url.searchParams` without validation. URL parameters are user-controlled.
- Use `eval()` or dynamic `<svelte:component>` resolution with user input.
- Return sensitive data from load functions that the client doesn't need — SvelteKit serializes load data into the HTML payload.
- Disable SvelteKit's built-in CSRF protection (`csrf.checkOrigin` in `svelte.config.js`) without an alternative.

## Common AI Mistakes

- Using `{@html post.body}` to render user-submitted blog content without any sanitization.
- Building auth by checking a cookie in `+layout.ts` (universal load, runs on client) instead of `+layout.server.ts` (server load).
- Returning `{ user: { email, passwordHash, ... } }` from a load function because "it's server-side" — load data is serialized to the client.
- Skipping validation in form actions and passing `formData.get('email')` directly to database queries.
- Putting `DATABASE_URL` in `$env/static/public` because "the load function needs it."
