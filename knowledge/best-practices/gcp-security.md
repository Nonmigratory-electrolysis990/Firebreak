# GCP Security

## DO

- **Follow least-privilege IAM**. Assign predefined roles at the narrowest scope (resource > project > folder > org). Avoid primitive roles (Owner, Editor, Viewer).
- **Enable Cloud Audit Logs** for all services. Enable Data Access logs for sensitive services (BigQuery, Cloud Storage, Cloud SQL).
- **Use VPC Service Controls** to create security perimeters around sensitive data. Prevent data exfiltration even if credentials are compromised.
- **Store secrets in Secret Manager** — not in environment variables, source code, or GCS buckets. Grant `secretmanager.secretAccessor` only to services that need each secret.
- **Enable Cloud Armor** on public-facing load balancers. Configure WAF rules for OWASP Top 10 and set rate limiting policies.
- **Use Workload Identity** for GKE pods instead of service account key files. Keys are long-lived credentials that can leak.
- **Enable organization policies** to restrict public IP creation, enforce uniform bucket access, and disable service account key creation.

## DON'T

- Use primitive roles (Owner, Editor) for service accounts. They grant far more permissions than any service needs.
- Create and download service account key files. Use Workload Identity, default service accounts, or identity federation instead.
- Make Cloud Storage buckets `allUsers` or `allAuthenticatedUsers` readable. Use signed URLs for temporary access.
- Skip enabling VPC Flow Logs — they're essential for network forensics and detecting lateral movement.
- Disable Cloud Audit Logs to reduce costs. Admin Activity logs are free and always on; enable Data Access logs for sensitive services.
- Use the default Compute Engine service account for all workloads — it has Editor role by default.
- Grant `roles/owner` at the organization level. Use it at project level only when absolutely necessary.

## Common AI Mistakes

- Granting `roles/editor` to a Cloud Function's service account because "it needs to access multiple services."
- Creating a service account key, committing `credentials.json` to the repo, and loading it with `GOOGLE_APPLICATION_CREDENTIALS`.
- Setting a GCS bucket to public because "the frontend needs to load assets" — use a CDN or signed URLs.
- Using the default Compute Engine service account for Cloud Functions, giving every function Editor-level access.
- Putting database passwords in Cloud Function environment variables instead of Secret Manager.
