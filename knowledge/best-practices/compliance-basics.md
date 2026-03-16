# Compliance Basics

## DO

- **Classify your data** before choosing a compliance framework. Know what you store: PII, PHI, payment data, children's data. Classification drives requirements.
- **Implement data retention policies** — define how long each data category is kept and automate deletion. GDPR requires purpose limitation; don't store data "just in case."
- **Support data deletion requests** (GDPR Article 17, CCPA). Build a "delete user" flow that removes data from primary DB, backups (or marks for exclusion on restore), logs, analytics, and third-party processors.
- **Maintain a data processing inventory** — what data you collect, where it's stored, who has access, which third parties receive it, and the legal basis for processing.
- **Implement audit logging** for access to sensitive data. SOC 2 and HIPAA both require demonstrating who accessed what and when.
- **Encrypt PHI at rest and in transit** for HIPAA. Use BAAs (Business Associate Agreements) with every vendor that handles PHI.
- **Apply the principle of least privilege** across all compliance frameworks. Only the minimum people and systems should access regulated data.
- **Document everything**. Compliance is about demonstrable controls. If it's not documented, it didn't happen.

## DON'T

- Assume GDPR doesn't apply because you're US-based. If you process data of EU residents, GDPR applies.
- Store health data (HIPAA) or payment data (PCI) in the same database as general application data without encryption and access controls.
- Treat compliance as a one-time checkbox. SOC 2 Type II requires continuous evidence over an observation period.
- Collect data you don't need. Every unnecessary field is a liability — more data means more risk and more compliance burden.
- Rely on your privacy policy alone. The policy must match your actual practices, and practices must be technically enforced.
- Forget about third-party processors. If you send user data to analytics, email, or error-tracking services, they're in scope.
- Skip children's data considerations. COPPA (US) and GDPR Article 8 have strict requirements for under-13/16 data.

## Common AI Mistakes

- Implementing a "delete account" button that only soft-deletes the user record, leaving PII in backups, logs, and analytics.
- Not including third-party services (Sentry, Mixpanel, Intercom) in the data processing inventory.
- Generating a privacy policy that claims "we don't share data" while sending events to a dozen analytics providers.
- Treating SOC 2 as a technical-only exercise, ignoring HR policies, vendor management, and access reviews.
- Building a HIPAA-regulated app without a BAA with the cloud provider (AWS, GCP, Azure all require explicit BAAs).
- Confusing anonymization with pseudonymization — pseudonymized data is still personal data under GDPR.
