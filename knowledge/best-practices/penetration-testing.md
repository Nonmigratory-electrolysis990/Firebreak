# Penetration Testing

## DO

- **Define scope explicitly** before engagement: which systems, endpoints, environments, and attack types are in-scope. Document it in writing.
- **Set rules of engagement** — testing windows, allowed techniques, escalation procedures, emergency contacts, data handling requirements.
- **Test against a staging environment** that mirrors production. Never pentest production without explicit approval, monitoring, and a rollback plan.
- **Require structured reporting** — each finding must include: severity (CVSS), proof of concept, affected component, remediation guidance, and retest criteria.
- **Retest every finding** after remediation. Mark findings as "verified fixed" only after the pentester confirms the fix.
- **Integrate continuous testing** — DAST in CI/CD (OWASP ZAP, Burp Enterprise), annual manual pentests, bug bounty for ongoing coverage.
- **Include business logic testing**. Scanners find injection and XSS. Humans find IDOR, privilege escalation, and payment bypasses.
- **Track findings in a vulnerability management system** with SLAs: critical (48 hours), high (7 days), medium (30 days), low (90 days).

## DON'T

- Run automated scanners against production without coordinating with operations. Scanners generate enormous traffic and can trigger outages.
- Treat the pentest report as confidential-to-developers-only. Share findings with engineering leadership and security team.
- Consider pentesting "done" after one annual test. Threat landscape and code change continuously.
- Test only the web application. Include APIs, mobile apps, infrastructure, cloud configuration, and social engineering where appropriate.
- Skip re-testing — marking a finding as "resolved" based on the developer's word without verification.
- Share raw pentest reports externally (to clients/auditors) without redacting internal infrastructure details and exploit payloads.

## Common AI Mistakes

- Generating a pentest scope that says "all systems" without specifying which hosts, ports, and environments.
- Recommending only automated scanning (OWASP ZAP, Nikto) without manual testing for business logic flaws.
- Creating a remediation plan without retest verification — findings get "closed" without confirming the fix works.
- Not specifying rules of engagement, leading to a pentester accidentally DDoSing production.
- Suggesting a one-time pentest as sufficient, with no plan for continuous or recurring testing.
- Generating a vulnerability report without CVSS scores or severity ratings, making prioritization impossible.
