# Subdomain Security

## DO

- **Audit DNS records regularly** for dangling entries — check all CNAME, A, and AAAA records for subdomains pointing to deprovisioned services.
- **Automate subdomain takeover detection** — use tools like `subjack`, `nuclei`, or custom scripts that resolve all subdomains and check for claimable responses.
- **Remove DNS records** when decommissioning services — delete the CNAME/A record before (or simultaneously with) removing the service.
- **Scope cookies to specific subdomains** — set `Domain` only when subdomains need the cookie. Without `Domain`, cookies are scoped to the exact hostname only.
```
Set-Cookie: __Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/
```
- **Configure CORS per-subdomain** — `api.example.com` should not blindly trust `*.example.com`. Each subdomain should have its own explicit origin allowlist.
- **Use separate origins for user-generated content** — host UGC on a distinct domain (not a subdomain) to prevent cookie and credential access. GitHub uses `githubusercontent.com`, not `github.com`.
- **Monitor Certificate Transparency logs** — detect unauthorized certificates issued for your subdomains.

## DON'T

- Use wildcard DNS (`*.example.com`) without monitoring — any unclaimed subdomain resolves, enabling subdomain takeover without creating a DNS record.
- Set `Domain=.example.com` on session cookies — every subdomain (including potentially compromised ones) receives the cookie.
- Trust all subdomains in CORS — `Access-Control-Allow-Origin` should not dynamically reflect any `*.example.com` origin without validation.
- Host user-generated content on a subdomain — `ugc.example.com` shares cookies with `app.example.com` if scoped to `.example.com`.
- Assume subdomains are trusted — a compromised or taken-over subdomain can steal cookies, bypass CORS, and phish users.
- Forget about cloud service subdomains — `myapp.azurewebsites.net`, `myapp.herokuapp.com`, and S3 bucket names are all takeover targets.
- Use the same TLS certificate across all subdomains without monitoring — wildcard certs mask which subdomains are active.

## Common AI Mistakes

- Setting `Access-Control-Allow-Origin` to dynamically reflect the `Origin` header if it ends with `.example.com` — this matches `attacker-example.com`.
- Configuring cookies with `Domain=.example.com` for convenience without noting the security implications for subdomain isolation.
- Deploying to cloud platforms and creating CNAME records without documenting the dependency — teardown procedures miss the DNS cleanup.
- Generating CORS middleware that trusts all subdomains: `origin.endsWith('.example.com')` matches malicious domains.
- Not considering subdomain takeover in infrastructure-as-code teardown — Terraform `destroy` removes the service but may leave DNS records in a separate zone.
- Setting up wildcard certificates and wildcard DNS simultaneously — both make takeover easier and harder to detect.
