# Next.js Security

## DO

- **Authenticate in middleware** (`middleware.ts`) to block unauthenticated requests before they reach any route. Match paths explicitly with `config.matcher`.
- **Validate auth in every Server Action** — Server Actions are public HTTP endpoints. Check the session at the top of each action, not just in the calling component.
- **Use `cookies()` or `headers()`** in server components to read auth state. Never trust client-side props for access control decisions.
- **Keep secrets in server-only code**. Use the `server-only` package to poison any module that touches secrets if accidentally imported client-side.
- **Protect API routes individually**. Every `route.ts` handler must verify auth — middleware alone is not sufficient if matchers are misconfigured.
- **Set CSRF protection on Server Actions** — Next.js 14+ checks the `Origin` header automatically, but verify `serverActions.allowedOrigins` in `next.config.js` for custom domains.
- **Prefix public env vars with `NEXT_PUBLIC_`** — only these are bundled client-side. Anything without the prefix stays server-only.

## DON'T

- Use `getServerSideProps` auth checks as your only guard — API routes and Server Actions bypass page-level checks entirely.
- Put API keys or database URLs in `NEXT_PUBLIC_` env vars. The client bundle is fully readable.
- Return full user objects from Server Actions. Return only the fields the client needs.
- Use `redirect()` in a try/catch inside Server Actions — `redirect()` throws internally, and catching it silently swallows the redirect.
- Skip `revalidatePath`/`revalidateTag` after mutations — stale cached data can leak information a user should no longer see.
- Disable the built-in `X-Frame-Options` or CSP headers without understanding clickjacking risks.
- Trust `searchParams` or `params` without validation — these are user-controlled input.

## Common AI Mistakes

- Creating a `withAuth` HOC for pages but leaving `/api/*` routes completely unprotected.
- Putting `DATABASE_URL` in `.env.local` with a `NEXT_PUBLIC_` prefix "so the client can connect directly."
- Writing Server Actions that accept a `userId` parameter from the client instead of reading it from the session.
- Using `fetch('/api/...')` in server components instead of calling the database directly — adds latency and a new attack surface.
- Placing auth logic in `layout.tsx` and assuming it protects all nested pages (layouts don't re-render on navigation).
