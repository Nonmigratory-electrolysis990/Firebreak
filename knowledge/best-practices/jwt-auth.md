# JWT Authentication Security

## DO

- **Use asymmetric algorithms** (EdDSA/Ed25519 or RS256). The signing key never leaves the server; only the public key is needed for verification.
- **Set short expiry** (15 minutes max). Use refresh token rotation for longer sessions — each refresh token is single-use.
- **Verify on every API route** with middleware. Frontend checks are UX, not security.
- **Validate all claims**: `iss` (issuer), `aud` (audience), `exp` (expiry), `nbf` (not before).
- **Store in httpOnly cookies** with `Secure` and `SameSite=Strict` flags.
- **Implement token revocation** via a denylist (Redis/DB) for logout and compromised tokens.

## DON'T

- Use HS256 with a weak secret ("secret", app name, short strings). If the secret leaks, anyone forges tokens.
- Set expiry longer than 24 hours without refresh rotation.
- Call `jwt.decode()` without signature verification — this accepts any forged token.
- Store JWTs in `localStorage` — any XSS gives full account takeover.
- Put sensitive data (passwords, SSN, PII) in the payload — JWTs are base64-encoded, not encrypted.
- Skip `aud` (audience) validation — a token for Service A shouldn't work on Service B.
- Use the same signing key across dev/staging/prod.

## Common AI Mistakes

- Using `jwt.decode(token)` instead of `jwt.verify(token, secret)`.
- Setting `expiresIn: '365d'` because "it's simpler."
- Adding auth checks in `_app.tsx` or layout but leaving API routes unprotected.
- Using Supabase `anon` key client-side without RLS — the JWT exists but access control doesn't.
- Creating a "verify" helper that only checks expiry, not the signature.
