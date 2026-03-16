# Data Masking and PII Redaction

## DO

- **Mask PII in logs at the application layer** before writing. Replace emails, SSNs, credit cards, and phone numbers with redacted placeholders (`***@***.com`).
- **Use structured logging** with explicit field definitions. Mark fields as `sensitive` so your logging framework redacts them automatically.
- **Filter API responses** at the serialization layer. Use DTOs/view models that exclude sensitive fields rather than deleting them from the full object.
- **Generate realistic but fake test data** with libraries like Faker. Never copy production data to dev/staging without full anonymization.
- **Implement column-level encryption** for PII in databases. Use envelope encryption so compromise of one key doesn't expose all data.
- **Apply data masking in database views** for support/analytics roles — show `J*** D**` instead of `John Doe`.
- **Define a PII inventory** — know exactly which fields in which tables contain personal data. You can't mask what you haven't identified.

## DON'T

- Log full request/response bodies in production — they frequently contain passwords, tokens, and PII.
- Return full user objects from APIs when only `name` and `avatar` are needed. Over-fetching leaks data.
- Copy production databases to development without anonymization. Even "internal" dev environments get compromised.
- Rely on `JSON.stringify` exclusions for masking — it's fragile and easy to forget new fields.
- Store PII in error tracking services (Sentry, Bugsnag) via unfiltered exception context.
- Use reversible encoding (base64, ROT13) as "masking" — it provides zero protection.

## Common AI Mistakes

- Logging `console.log(req.body)` in middleware, capturing every password and credit card submitted.
- Returning full database rows from API endpoints instead of selecting specific safe columns.
- Generating Sentry/error configs without `beforeSend` hooks to strip PII from error reports.
- Using `SELECT *` in queries that feed API responses, exposing every column including sensitive ones.
- Creating admin dashboards that display full SSNs, credit cards, and passwords in plaintext.
