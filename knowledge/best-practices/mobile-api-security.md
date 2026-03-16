# Mobile API Security

## DO

- **Implement certificate pinning** against your server's leaf or intermediate certificate. Use TrustKit (iOS), OkHttp CertificatePinner (Android), or platform-native APIs.
- **Store tokens in platform-secure storage** — iOS Keychain or Android Keystore/EncryptedSharedPreferences. Never use `UserDefaults`, `SharedPreferences`, or `AsyncStorage`.
- **Implement token refresh** with short-lived access tokens (15 min) and rotating refresh tokens. Revoke the entire token family if a refresh token is reused.
- **Use biometric auth as a second factor**, not as the only factor. Biometrics unlock a key in secure storage — they don't replace server-side authentication.
- **Implement jailbreak/root detection** to warn users or restrict sensitive operations. Use libraries like IOSSecuritySuite or RootBeer. Treat detection as defense-in-depth, not a hard gate.
- **Validate API responses** on the client. Don't trust that the server always returns expected shapes — a MITM or compromised server can inject malicious payloads.
- **Use attestation APIs** (Apple App Attest, Google Play Integrity) to verify requests come from a legitimate, unmodified app.

## DON'T

- Embed API secrets in the app binary. Decompilation tools (jadx, Hopper) extract strings in minutes. Use server-side proxy patterns.
- Disable SSL verification for debugging and forget to re-enable it: `trustAllCerts`, `NSAllowsArbitraryLoads`, `android:usesCleartextTraffic="true"`.
- Store refresh tokens in plain text storage. A rooted/jailbroken device exposes all non-secure storage.
- Implement auth only on the client side. Every API endpoint must independently validate the auth token.
- Log sensitive data (tokens, passwords, PII) in mobile app logs — crash reporting tools and logcat/Console capture everything.
- Use symmetric encryption with hardcoded keys in the app for "protecting" local data. The key is extractable.
- Ship debug builds to production — they often have verbose logging, disabled pinning, and development endpoints.

## Common AI Mistakes

- Storing `API_KEY` as a constant in the app: `const API_KEY = "sk-live-..."` — trivially extractable.
- Using `AsyncStorage.setItem('authToken', token)` in React Native — it's unencrypted plain text on both platforms.
- Implementing certificate pinning but adding a bypass "for development" that's still active in release builds.
- Building biometric login that sets `isAuthenticated = true` in local state without any server-side session.
- Disabling SSL verification in OkHttp with a custom `TrustManager` that accepts all certificates.
