# React Security

## DO

- **Rely on JSX auto-escaping** for rendering user content. JSX escapes strings by default, preventing most XSS.
- **Sanitize HTML before using `dangerouslySetInnerHTML`** — use DOMPurify: `{ __html: DOMPurify.sanitize(userHtml) }`. Never pass unsanitized input.
- **Implement auth guards at the route level** using a wrapper component that checks auth state and redirects. But treat client-side guards as UX, not security.
- **Prefix client-exposed env vars** with `REACT_APP_` (CRA) or `NEXT_PUBLIC_` (Next.js). Only these are bundled into the client build.
- **Validate all data from APIs** on the client. Don't assume API responses are safe to render — a compromised or third-party API can inject malicious content.
- **Use `integrity` attributes** on third-party scripts (`<script src="..." integrity="sha384-...">`). Subresource Integrity prevents CDN tampering.
- **Set CSP headers** on the server to restrict script sources. Use `nonce`-based CSP for inline scripts if needed.

## DON'T

- Use `dangerouslySetInnerHTML={{ __html: userInput }}` without sanitization. The name is a warning — heed it.
- Store JWTs or sensitive tokens in `localStorage`. Any XSS vulnerability gives attackers full access. Use httpOnly cookies.
- Put API secrets, database credentials, or private keys in `REACT_APP_` env vars. The entire bundle is public.
- Use `eval()`, `new Function()`, or `javascript:` URLs with user input. All enable arbitrary code execution.
- Trust URL parameters (from `useSearchParams` or `useParams`) without validation. They are user-controlled input.
- Load third-party scripts from untrusted CDNs without SRI hashes.
- Assume `useEffect` auth checks protect data — the component renders before the effect runs.

## Common AI Mistakes

- Building an "auth guard" that only checks `localStorage.getItem('token')` — any user can set this value.
- Using `dangerouslySetInnerHTML` to render Markdown without sanitization because "React handles it."
- Storing `API_SECRET` in `.env` as `REACT_APP_API_SECRET` and assuming it's hidden from users.
- Creating `<a href={userProvidedUrl}>` without validating the protocol — allows `javascript:alert(1)` links.
- Writing `useEffect(() => { if (!user) navigate('/login') }, [])` and assuming the protected page content never renders.
