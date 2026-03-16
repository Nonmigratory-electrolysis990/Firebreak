# Single Sign-On (SSO) Security

## DO

- **Use OIDC (OpenID Connect) over SAML** for new implementations. OIDC is simpler and less prone to XML signature wrapping attacks.
- **Validate the `state` parameter** in OAuth/OIDC flows to prevent CSRF. Generate a cryptographically random value, store in session, verify on callback.
- **Verify the `nonce` claim** in the ID token matches what you sent in the auth request to prevent replay attacks.
- **Implement account linking carefully** — require email verification on both the SSO provider and your app before linking. An attacker can register a matching email on a provider.
- **Propagate logout** to all relying parties. Use OIDC Back-Channel Logout or SAML SLO. Invalidate all local sessions on logout.
- **Validate SAML assertions fully**: signature, issuer, audience, timestamps (`NotBefore`/`NotOnOrAfter`), and `InResponseTo`.
- **Use short-lived sessions** after SSO login. Don't let a session last indefinitely just because the IdP session is active.

## DON'T

- Accept unsigned or partially signed SAML assertions. Require both response and assertion signatures.
- Link accounts by email alone without verification — this enables account takeover via "Sign in with X."
- Skip `aud` (audience) validation on ID tokens — a token issued for App A shouldn't authenticate on App B.
- Implement your own SAML parser — use a well-maintained library. XML signature verification is notoriously fragile.
- Trust the IdP's session timeout as your session timeout. Enforce your own.
- Use the `sub` claim from different IdPs interchangeably — each provider's `sub` is only unique within that provider.

## Common AI Mistakes

- Omitting `state` parameter in OAuth flows, leaving the app vulnerable to CSRF.
- Linking SSO accounts by matching email addresses without verifying email ownership.
- Parsing SAML XML manually instead of using a battle-tested library (xml-crypto, onelogin).
- Not implementing logout propagation — user logs out of IdP but remains logged into the app.
- Using the `email` claim as a stable user identifier instead of `sub`.
