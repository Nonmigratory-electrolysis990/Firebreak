# Token Refresh Security

## DO

- **Rotate refresh tokens on every use** — issue a new refresh token with each access token refresh. Invalidate the old one immediately.
- **Implement token family detection** — if a previously-used refresh token is presented, revoke the entire token family (all descendants). This detects token theft.
- **Store refresh tokens server-side** in a database with `user_id`, `family_id`, `created_at`, and `revoked` columns. Never rely on client-side-only validation.
- **Set absolute expiry** on refresh tokens (7-30 days). Even with rotation, tokens shouldn't live forever.
- **Add a short grace period** (5-10 seconds) for concurrent requests — if two requests use the same refresh token simultaneously, don't immediately flag it as theft.
- **Bind refresh tokens to device/fingerprint** (IP range, User-Agent hash). Reject refresh attempts from drastically different contexts.
- **Revoke all tokens on password change** or account compromise detection.

## DON'T

- Issue refresh tokens that never expire — stolen tokens grant permanent access.
- Reuse the same refresh token across multiple refreshes. This makes theft detection impossible.
- Store refresh tokens in `localStorage` or `sessionStorage`. Use httpOnly cookies or secure native storage.
- Skip token family tracking. Without it, you can't detect or respond to token theft.
- Allow refresh tokens to work across different client applications or origins.
- Use the access token as the refresh token or vice versa.

## Common AI Mistakes

- Implementing refresh without rotation — same refresh token used for the lifetime of the session.
- Storing refresh tokens in `localStorage` alongside access tokens, negating the security benefit.
- Not implementing revocation — refresh tokens remain valid even after logout or password reset.
- Generating refresh tokens with `Math.random()` instead of `crypto.randomBytes()`.
- Skipping the grace period for concurrent requests, causing false-positive token theft detection on every navigation.
