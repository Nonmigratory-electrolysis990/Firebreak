# Incident Response

## DO

- **Maintain a runbook** with step-by-step procedures for common incidents: credential leak, data breach, DDoS, ransomware, compromised dependency.
- **Rotate all potentially compromised secrets immediately**. Don't wait to determine if they were actually used — rotate first, investigate second.
- **Preserve logs and evidence before taking corrective action**. Snapshot affected systems, export logs to immutable storage. Forensic evidence is destroyed by remediation.
- **Define clear roles**: Incident Commander (decisions), Communications Lead (stakeholder updates), Technical Lead (investigation and remediation).
- **Establish a communication plan** — internal Slack channel, status page updates, customer notification templates, legal/compliance contacts pre-identified.
- **Set severity levels** with defined response times: SEV1 (active breach, all-hands, 15-minute response), SEV2 (potential breach, 1-hour response), SEV3 (vulnerability, 24-hour response).
- **Conduct blameless post-mortems** within 48 hours. Document: what happened, timeline, root cause, what went well, what to improve, action items with owners and deadlines.
- **Practice with tabletop exercises** quarterly. Walk through a scenario without actually executing — test the process, not the systems.
- **Have pre-authorized emergency access** (break-glass accounts) tested and ready. Don't discover access problems during the incident.

## DON'T

- Communicate about active incidents on public Slack channels, email, or social media before the scope is understood.
- Delete or modify logs during investigation. Immutable log storage should be in place before the incident.
- Skip the post-mortem because "it was a small incident." Small incidents reveal systemic issues.
- Blame individuals. Blame incentivizes hiding future incidents.
- Assume one compromised credential means only one system is affected. Assume lateral movement until proven otherwise.
- Wait for legal approval before revoking compromised tokens. Revoke immediately, discuss later.
- Rely on memory during the incident. Write everything down with timestamps in the incident channel.

## Common AI Mistakes

- Generating an incident response plan that's all theory with no concrete runbook steps (who to call, what commands to run, where logs are).
- Not including secret rotation in the response plan — focusing only on "find the vulnerability."
- Creating a post-mortem template that focuses on blame ("Who made the mistake?") instead of systemic improvements.
- Omitting communication templates — teams waste critical time drafting customer notifications during the incident.
- Not specifying where to preserve evidence before remediation begins.
- Skipping severity definitions, so every incident gets the same (slow) response.
