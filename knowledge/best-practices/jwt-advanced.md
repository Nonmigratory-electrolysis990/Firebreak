# Advanced JWT Security

## DO

- **Use JWE (JSON Web Encryption)** when the token payload contains sensitive claims that must not be readable by clients or intermediaries. Use `A256GCM` or `A256CBC-HS512` for content encryption.
- **Implement key rotation** with JWK Sets (JWKS). Publish keys at a `/.well-known/jwks.json` endpoint with `kid` (Key ID) in each token header to select the correct verification key.
- **Include `kid` in the JWT header** so verifiers can look up the correct key from the JWKS. This enables zero-downtime key rotation.
- **Set up a token denylist** (Redis or database) for revocation. Check the denylist on every request. Index by `jti` (JWT ID) claim.
- **Use short-lived tokens with refresh rotation** instead of long-lived tokens with revocation-only. Revocation is an emergency mechanism, not a session management strategy.
- **Verify the `alg` header server-side** — explicitly specify allowed algorithms. Never let the token dictate which algorithm to use.
- **Separate signing keys per service** — a token signed by Service A shouldn't verify on Service B. Use distinct `iss` and `aud` claims enforced per-service.

## DON'T

- Accept `"alg": "none"` — this bypasses signature verification entirely. Always reject unsigned tokens.
- Use a single static signing key with no rotation plan. Compromised keys can't be revoked without breaking all active tokens.
- Confuse JWS (signed) with JWE (encrypted). Signing proves integrity; encryption protects confidentiality. Use both when needed.
- Store revocation state only in local memory — it won't sync across instances. Use a shared store.
- Put the JWKS endpoint behind authentication — verifiers (including third-party services) need public access to your public keys.
- Embed large data in JWTs (user profiles, permissions lists). Keep tokens small; look up details server-side.

## Common AI Mistakes

- Using `jwt.decode()` (no verification) instead of `jwt.verify()` with explicit algorithm and key.
- Not including `kid` in JWT headers, making key rotation impossible without breaking existing tokens.
- Implementing revocation with an in-memory Set that resets on server restart.
- Generating JWKS endpoints that expose private keys instead of only public keys.
- Setting `algorithms: ['HS256', 'RS256', 'none']` in verification options, allowing algorithm confusion attacks.
