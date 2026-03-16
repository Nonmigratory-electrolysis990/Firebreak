# WebAuthn and Passkeys Security

## DO

- **Use server-side challenge generation** with cryptographically random values (32+ bytes). Store the challenge in the session and verify it in the response.
- **Verify the `origin`** in the `clientDataJSON` matches your exact domain. This prevents phishing sites from relaying authentication ceremonies.
- **Verify the `rpId`** (Relying Party ID) in the authenticator data matches your domain.
- **Store the credential public key and counter** server-side. On each authentication, verify the counter is strictly greater than the stored value to detect cloned authenticators.
- **Support resident keys (discoverable credentials)** for passwordless flows. Set `requireResidentKey: true` and `residentKey: "required"` in creation options.
- **Use `userVerification: "preferred"` or `"required"`** to ensure biometric/PIN verification on the authenticator.
- **Allow multiple credentials per account** so users can register backup keys and multiple devices.

## DON'T

- Generate challenges client-side — they must be unpredictable server-generated values to prevent replay attacks.
- Skip origin verification in `clientDataJSON` — without it, a phishing site can relay the ceremony.
- Ignore the sign counter — cloned authenticators reuse the same counter, and you'll miss the theft.
- Require attestation unless you have specific compliance needs. Most apps should use `attestation: "none"` — it simplifies the flow and avoids privacy concerns.
- Store only one credential per user. If they lose that authenticator, they're locked out.
- Implement WebAuthn without a fallback recovery mechanism (recovery codes, verified email reset).

## Common AI Mistakes

- Using `Math.random()` for challenge generation instead of `crypto.getRandomValues()`.
- Skipping server-side verification of `clientDataJSON` and `authenticatorData` — trusting the client response as-is.
- Not storing or checking the credential counter, making cloned key detection impossible.
- Implementing registration but not providing a way to register additional credentials or recover access.
- Setting `userVerification: "discouraged"` for convenience, allowing authentication without biometric/PIN.
