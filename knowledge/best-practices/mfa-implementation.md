# Multi-Factor Authentication Implementation

## DO

- **Support TOTP (RFC 6238) as the baseline** using 6-digit codes with 30-second windows. Allow a 1-step clock skew tolerance.
- **Offer WebAuthn/FIDO2** as the strongest option. Hardware keys are phishing-resistant — TOTP is not.
- **Generate backup codes** (8–10 codes, 8+ alphanumeric characters each) at enrollment. Hash them (bcrypt) and store only hashes. Show them exactly once.
- **Enforce MFA on sensitive operations** (password change, email change, payment, admin actions) even if the session is already MFA-verified.
- **Rate limit MFA code attempts** — lock after 5 failures for 15 minutes. Alert the user via email on lockout.
- **Encrypt TOTP secrets at rest** using envelope encryption. The secret is the equivalent of a password.
- **Require MFA re-enrollment** after recovery, not just re-login. The old TOTP secret should be rotated.
- **Implement recovery flow** that requires identity verification (backup codes, support ticket with ID verification) — not just email.

## DON'T

- Use SMS as MFA if avoidable. SIM-swapping makes SMS the weakest second factor. If required, treat it as low-assurance.
- Accept TOTP codes older than 1 step window (90 seconds total). Wider windows increase brute-force surface.
- Store TOTP secrets in plaintext in the database alongside the user record.
- Skip MFA on API keys or service accounts — enforce it at key creation time.
- Allow MFA disable without re-authentication and a cooling-off period.
- Log TOTP codes or backup codes in application logs.
- Use a shared TOTP secret across multiple users or environments.

## Common AI Mistakes

- Implementing TOTP with `Math.floor(Date.now() / 30000)` manually instead of a vetted library (otplib, pyotp).
- Storing backup codes in plaintext because "they're only shown once."
- Skipping rate limiting on the MFA verification endpoint — 6-digit codes are brute-forceable (1M combinations).
- Not binding the TOTP enrollment to the authenticated session — allowing enrollment CSRF.
- Generating WebAuthn challenges that aren't bound to the session or user, enabling relay attacks.
- Treating MFA as optional for admin accounts.
