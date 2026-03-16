# Email Security

## DO

- **Configure SPF** — publish a DNS TXT record specifying which IP addresses/servers can send email for your domain. End with `-all` (hard fail).
```
example.com. TXT "v=spf1 include:_spf.google.com include:sendgrid.net -all"
```
- **Enable DKIM** — sign outgoing emails with a domain-specific key. Publish the public key as a DNS TXT record under `selector._domainkey.example.com`.
- **Deploy DMARC** — `v=DMARC1; p=reject; rua=mailto:dmarc@example.com` tells receiving servers to reject emails that fail both SPF and DKIM, and send aggregate reports.
- **Prevent email header injection** — never include user input in email headers (`To`, `From`, `Subject`, `CC`, `BCC`) without stripping newlines (`\r\n`).
- **Sanitize HTML email templates** — if rendering user input in HTML emails, apply the same XSS prevention rules as web pages. Use a template engine with auto-escaping.
- **Use TLS for SMTP** — configure `STARTTLS` or implicit TLS on port 465 for outbound email. Enforce TLS with MTA-STS.
- **Implement MTA-STS and DANE** for inbound email TLS enforcement — prevents downgrade attacks on mail delivery.

## DON'T

- Use `p=none` in DMARC permanently — it's for monitoring only. Escalate to `p=quarantine` then `p=reject` after reviewing reports.
- Include user-supplied strings in email headers without newline sanitization — `\r\nBCC: attacker@evil.com` injects headers.
- Send sensitive data (passwords, tokens, PII) in email bodies — email is not encrypted end-to-end by default.
- Use SPF with `+all` or `?all` — this effectively disables SPF. Always use `-all` (hard fail) or `~all` (soft fail during transition).
- Allow user-controlled `From` addresses — spoofing the sender domain is a phishing vector.
- Build HTML emails with string concatenation of user input — use template engines with auto-escaping.
- Ignore bounce and complaint rates — high rates get your domain/IP blocklisted.

## Common AI Mistakes

- Generating email-sending code with `nodemailer` that places user input directly into `subject` or `to` fields without sanitization.
- Omitting DMARC entirely while setting up SPF and DKIM — SPF and DKIM without DMARC don't specify what to do on failure.
- Setting SPF with `~all` (soft fail) and never transitioning to `-all` (hard fail).
- Building "contact us" forms that let the user specify the `From` header — this sends email on behalf of the user from your server.
- Creating email templates with `${userMessage}` injected directly into HTML without escaping.
- Not mentioning MTA-STS when configuring email security — SPF/DKIM/DMARC protect authenticity, MTA-STS protects transport.
