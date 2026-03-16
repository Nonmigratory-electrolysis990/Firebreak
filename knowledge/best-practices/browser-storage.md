# Browser Storage Security

## DO

- **Use httpOnly cookies** for auth tokens. They're inaccessible to JavaScript, which prevents XSS-based token theft.
- **Encrypt sensitive data** before storing in `localStorage` or `IndexedDB` using the Web Crypto API (`SubtleCrypto`). Derive keys from user-specific secrets.
- **Use `sessionStorage`** for data that should not persist across tabs or after the tab closes (e.g., CSRF tokens, wizard state).
- **Set storage quotas and validate data** read from storage — treat it as untrusted input. Malicious extensions or XSS can modify stored values.
- **Clear sensitive storage on logout** — explicitly remove auth-related data from all storage mechanisms.
- **Use IndexedDB for structured data** that needs indexing. It has better storage limits and supports transactions.
- **Prefer `SameSite=Strict` cookies** over custom storage for anything auth-related.

## DON'T

- Store JWTs, API keys, or session tokens in `localStorage` — any XSS vulnerability gives the attacker full read access.
- Store unencrypted PII (email, address, phone) in `localStorage` — it persists indefinitely and survives browser restarts.
- Use `localStorage` as a cross-tab communication channel for sensitive data. Use `BroadcastChannel` with message validation instead.
- Store secrets in `sessionStorage` thinking it's "more secure" — it's still accessible to XSS within the same tab.
- Rely on browser storage as the source of truth for permissions or roles — always verify server-side.
- Use `document.cookie` to read/write cookies in JavaScript when httpOnly cookies would work.

## Common AI Mistakes

- Storing JWTs in `localStorage` with `localStorage.setItem('token', jwt)` — the #1 most common insecure pattern.
- Building auth flows that check `localStorage` for a token and skip server-side validation.
- Using `localStorage` for cart data containing full payment details.
- Not clearing storage on logout: `localStorage.removeItem('token')` but forgetting IndexedDB, sessionStorage, and cookies.
- Reading roles/permissions from localStorage to render admin UI without server-side verification.
