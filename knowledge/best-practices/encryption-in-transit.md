# Encryption in Transit

## DO

- **Enforce TLS on all connections** — external, internal, and database. There is no "trusted network." Use TLS 1.2 minimum; prefer TLS 1.3.
- **Use mTLS for service-to-service communication**. Both sides present certificates — this authenticates the caller, not just the server.
- **Automate certificate management** with ACME/Let's Encrypt or your cloud provider's certificate manager. Manual certificate management leads to expiry outages.
- **Monitor certificate expiry** with alerting at 30, 14, and 7 days before expiration. Automate renewal.
- **Enable HSTS** (HTTP Strict Transport Security) with `max-age=31536000; includeSubDomains; preload`. Submit to the HSTS preload list.
- **Terminate TLS at the edge** (load balancer, reverse proxy) but re-encrypt to backends. Don't run plaintext HTTP between load balancer and application servers.
- **Pin certificates or public keys** in mobile apps and CLI tools that talk to a specific backend. Certificate pinning prevents MITM with rogue CAs.
- **Disable weak cipher suites**. Remove TLS 1.0/1.1, RC4, 3DES, MD5-based MACs, and export ciphers. Test with `testssl.sh` or SSL Labs.

## DON'T

- Disable TLS certificate verification in production (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`). This is MITM-as-a-feature.
- Use self-signed certificates in production without a private CA infrastructure. If you must, pin them explicitly.
- Serve mixed content — HTTPS pages loading HTTP resources. Browsers block mixed active content and warn on passive content.
- Redirect HTTP to HTTPS without HSTS. The first request is still plaintext and vulnerable to SSL stripping (sslstrip attack).
- Hardcode certificate paths without monitoring expiry. Expired certificates cause sudden outages.
- Use TLS termination at the load balancer and then plaintext HTTP to backends on a shared network. Re-encrypt.

## Common AI Mistakes

- Adding `NODE_TLS_REJECT_UNAUTHORIZED=0` to fix a certificate error instead of properly configuring the CA bundle.
- Configuring HTTPS on the frontend but connecting to the database over plaintext because "it's on the same VPC."
- Not setting HSTS headers, leaving users vulnerable to SSL stripping on their first visit.
- Using `http://` URLs for internal API calls between microservices because "they're behind a firewall."
- Generating self-signed certificates for development and accidentally shipping the same config to production.
- Forgetting to renew certificates because auto-renewal wasn't configured and monitoring wasn't set up.
