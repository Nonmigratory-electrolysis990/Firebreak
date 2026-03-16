# DNS Security

## DO

- **Enable DNSSEC** on your authoritative nameservers — cryptographically signs DNS records to prevent spoofing and cache poisoning.
- **Set CAA records** to restrict which Certificate Authorities can issue certificates for your domain — `example.com. CAA 0 issue "letsencrypt.org"`.
- **Audit for subdomain takeover** — scan all DNS records (CNAME, A) for dangling entries pointing to deprovisioned services (Heroku, S3, Azure, GitHub Pages).
```bash
# Check for dangling CNAME
dig +short old-app.example.com CNAME
# If it points to a service you no longer control, delete the record
```
- **Prevent DNS rebinding** — validate `Host` headers on your server, bind services to specific hostnames, and block private IPs in DNS responses from external resolvers.
- **Use short TTLs for sensitive records** during migrations — but use longer TTLs (3600s+) in steady state to reduce lookup latency.
- **Monitor Certificate Transparency logs** — subscribe to CT log notifications for your domain to detect unauthorized certificate issuance.
- **Use dedicated DNS providers** with DDoS protection and anycast — Cloudflare, Route 53, Google Cloud DNS.

## DON'T

- Leave dangling CNAME records — if `blog.example.com` points to a deleted Heroku app, anyone can claim that subdomain and serve content on your domain.
- Use wildcard DNS (`*.example.com`) without understanding the risk — any unclaimed subdomain resolves, enabling takeover and cookie scope attacks.
- Ignore CAA records — without them, any CA can issue a certificate for your domain.
- Use DNS for secret distribution — DNS queries are unencrypted by default and cached by recursive resolvers. Use DNS-over-HTTPS only for client privacy.
- Run your own recursive resolver unless you have expertise — use trusted providers (1.1.1.1, 8.8.8.8) with DNSSEC validation.
- Allow zone transfers (AXFR) to unauthorized IPs — this reveals your entire DNS zone to attackers.

## Common AI Mistakes

- Configuring wildcard DNS (`*.example.com`) as a convenience without noting subdomain takeover risk.
- Not including CAA records in infrastructure-as-code templates — Terraform, CloudFormation, and Pulumi should all define CAA.
- Suggesting `nslookup` for security auditing instead of `dig +dnssec` which shows DNSSEC validation status.
- Ignoring subdomain takeover in deployment teardown procedures — deleting the app but not the DNS record.
- Setting TTL to 0 in production — this overloads DNS infrastructure and increases latency.
- Recommending DNS-based load balancing without considering how DNS caching affects failover timing.
