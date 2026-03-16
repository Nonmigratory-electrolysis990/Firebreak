# Password Reset Security

## DO

- **Generate cryptographically random tokens** (min 32 bytes, `crypto.randomBytes(32)` or equivalent). Hash the token (SHA-256) before storing it in the database — only compare hashes.
- **Set short expiry** (15–30 minutes max). Delete the token immediately after successful use.
- **Rate limit reset requests** per email and per IP. 3 requests per email per hour. Use exponential backoff on failures.
- **Return the same response regardless of whether the email exists**. "If an account exists, you'll receive an email" — never confirm or deny account existence.
- **Verify email ownership before allowing password change**. The token in the email IS the verification — don't skip it.
- **Invalidate all existing sessions** after a successful password reset. The user may be resetting because of compromise.
- **Log all reset attempts** (request, success, failure) with IP and user-agent for incident investigation.
- **Use a separate token table** with `(hashed_token, user_id, expires_at, used_at)` columns.

## DON'T

- Use sequential or predictable tokens (UUIDs v1, timestamps, user ID + hash).
- Store plaintext reset tokens in the database — if the DB leaks, every pending reset is compromised.
- Send the new password in an email. Ever.
- Allow unlimited reset requests — attackers use this for email bombing.
- Include the old password or username in the reset URL query string.
- Let reset tokens survive a password change — one token, one use.
- Redirect to a password form that doesn't re-validate the token server-side on submission.

## Common AI Mistakes

- Generating tokens with `Math.random()` or `uuid.v4()` instead of cryptographic randomness.
- Storing the raw token in the DB and comparing with `===` instead of hashing first.
- Responding with "No account found" vs "Reset email sent" — leaking user enumeration.
- Setting token expiry to 24 hours or longer "for convenience."
- Forgetting to invalidate the token after use, allowing replay.
- Building a reset flow that only checks the token on the GET (form load) but not on the POST (submission).
