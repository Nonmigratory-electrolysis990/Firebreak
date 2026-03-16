# Security Monitoring and Alerting

## DO

- **Track security-specific metrics**: failed login rate, privilege escalation attempts, 401/403 response rate, token revocation frequency, new admin account creation.
- **Set anomaly detection baselines** for normal traffic patterns. Alert on deviations: 10x login failures, unusual API call patterns, requests from new geolocations.
- **Use tiered alerting** — P1 (page immediately): active breach indicators. P2 (Slack/urgent): suspicious patterns. P3 (email/dashboard): informational.
- **Create runbooks** for every alert. Each alert should link to a step-by-step response procedure: what to check, how to verify, when to escalate.
- **Correlate events across services** — a failed login followed by a password reset followed by a successful login from a new IP is a pattern, not three independent events.
- **Retain security logs** for at least 90 days (longer for compliance). Use append-only storage or a SIEM to prevent log tampering.
- **Test your alerting pipeline** regularly. Inject synthetic security events and verify alerts fire and reach the right people.

## DON'T

- Alert on every single failed login — you'll drown in noise. Set thresholds (e.g., 10 failures from same IP in 5 minutes).
- Send all alerts to a shared Slack channel with no escalation policy. Critical alerts get buried.
- Monitor only application errors but not security events. A `200 OK` data exfiltration won't trigger error-based alerts.
- Rely on manual log review for security detection. Automate pattern matching and anomaly detection.
- Store security logs in the same database as application data. A compromised application can delete its own audit trail.
- Create alerts without runbooks — on-call engineers at 3 AM need clear instructions, not guesswork.

## Common AI Mistakes

- Setting up basic health monitoring but no security-specific metrics or alerts.
- Creating alerts for every 4xx response instead of meaningful security patterns.
- Logging security events to `console.log` instead of a structured, tamper-resistant logging service.
- Not implementing alert deduplication, causing hundreds of notifications for a single incident.
- Building dashboards that show current state but no historical trends for anomaly detection.
