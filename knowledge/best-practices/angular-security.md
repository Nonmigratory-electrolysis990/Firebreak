# Angular Security

## DO

- **Trust Angular's built-in sanitization**. Angular auto-sanitizes values bound to `innerHTML`, `src`, `href`, and `style`. Don't bypass it unless absolutely necessary.
- **Use `DomSanitizer` methods correctly**. If you must bypass sanitization, use `bypassSecurityTrustHtml()` only on content you've sanitized server-side or with DOMPurify first.
- **Implement HTTP interceptors** for auth. Attach tokens in an interceptor so every request is authenticated, and handle 401 responses centrally.
- **Enable strict mode** (`"strict": true` in `tsconfig.json`). It catches null/undefined bugs that can lead to logic flaws in auth checks.
- **Set CSP headers** server-side. Angular's AOT compiler eliminates the need for `'unsafe-eval'`. Avoid JIT compilation in production.
- **Use route guards** (`CanActivate`, `CanActivateChild`) for protected routes. Verify the token server-side in the guard, not just its existence.
- **Validate all API responses** with TypeScript interfaces and runtime validation. Don't trust that backend responses match expected shapes.

## DON'T

- Call `bypassSecurityTrustHtml()` on user-provided content. This disables Angular's XSS protection entirely for that binding.
- Use `ElementRef.nativeElement.innerHTML = userInput` — this bypasses Angular's sanitizer completely.
- Compile user input as Angular templates at runtime. Template injection in Angular SSR can lead to code execution.
- Store tokens in `localStorage` and read them in interceptors without checking expiry. Add expiry validation.
- Use JIT compilation in production — it requires `'unsafe-eval'` in CSP and increases attack surface.
- Disable `HttpClient` XSRF protection (`HttpClientXsrfModule`) without implementing an alternative.
- Trust `ActivatedRoute` params without validation. URL parameters are user-controlled input.

## Common AI Mistakes

- Using `bypassSecurityTrustHtml(userComment)` to render rich text comments — direct XSS.
- Writing an auth guard that returns `!!localStorage.getItem('token')` without verifying the token is valid or unexpired.
- Disabling Angular's XSRF module because "we use JWTs" — then storing JWTs in localStorage where XSS can steal them.
- Using `[innerHTML]="userContent"` and then calling `bypassSecurityTrustHtml()` because "Angular was stripping my HTML."
- Building dynamic components from user-provided template strings using the compiler API.
