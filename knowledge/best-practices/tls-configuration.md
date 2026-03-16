# TLS Configuration

## DO

- **Use TLS 1.3 exclusively** when possible. If TLS 1.2 is required for compatibility, disable 1.0 and 1.1 — they have known vulnerabilities (BEAST, POODLE).
- **Restrict cipher suites** — TLS 1.3 only uses AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305). For TLS 1.2, use only ECDHE key exchange with AES-GCM.
```nginx
# Nginx
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
```
- **Enable HSTS preload** — `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` and submit to `hstspreload.org`.
- **Use OCSP stapling** — the server fetches and caches OCSP responses, reducing client-side latency and privacy leaks.
- **Automate certificate renewal** — use Let's Encrypt with certbot or ACME clients. Set renewal at 30 days before expiry.
- **Use separate certificates per service** — compromise of one certificate doesn't affect others.
- **Generate ECDSA certificates** (P-256 or P-384) — they're faster and smaller than RSA. If RSA is needed, use 2048-bit minimum (4096-bit preferred).

## DON'T

- Enable TLS 1.0 or 1.1 — they've been deprecated since 2020 (RFC 8996). All modern browsers require 1.2+.
- Use CBC mode cipher suites with TLS 1.2 — they're vulnerable to padding oracle attacks. Use GCM only.
- Use self-signed certificates in production — they train users to ignore certificate warnings and break certificate validation.
- Disable certificate validation in HTTP clients (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`) — this enables MITM attacks.
- Pin public keys (HPKP) — it's deprecated and can permanently brick your site if you lose the key. Use CAA records instead.
- Use wildcard certificates for unrelated services — a compromise exposes all services under the wildcard.
- Store private keys in source control, container images, or world-readable files.

## Common AI Mistakes

- Setting `rejectUnauthorized: false` in Node.js HTTPS requests "to fix SSL errors" — this disables all certificate validation.
- Using `verify=False` in Python requests "for development" and shipping it to production.
- Generating TLS configs that include `TLSv1` and `TLSv1.1` for "broad compatibility."
- Recommending certificate pinning (HPKP) — it's been removed from browsers and is actively dangerous.
- Using RSA 1024-bit keys in example code — minimum is 2048-bit, recommended is 4096-bit.
- Hardcoding cipher suites from a 2015 blog post — cipher recommendations change. Reference Mozilla's SSL Configuration Generator.
