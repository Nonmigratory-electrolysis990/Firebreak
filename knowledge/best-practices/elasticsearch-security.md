# Elasticsearch Security

## DO

- **Enable X-Pack Security** (or OpenSearch Security plugin). Authentication and RBAC are disabled by default — every request has superuser access.
- **Use TLS for all transport and HTTP traffic**. Generate node certificates with `elasticsearch-certutil` and enforce `xpack.security.transport.ssl.enabled: true`.
- **Create role-based users** with minimal index and field-level permissions. Never share the `elastic` superuser account.
- **Place Elasticsearch behind an API gateway** or application layer. Never expose port 9200 or 9300 to the public internet.
- **Sanitize user input in queries** — use parameterized queries or the `match` DSL instead of raw query strings to prevent query injection.
- **Enable audit logging** to track authentication failures, privilege escalations, and index access patterns.
- **Set `action.destructive_requires_name: true`** to prevent accidental wildcard deletions (`DELETE /*`).

## DON'T

- Expose Elasticsearch directly to the internet — unauthenticated clusters are actively scanned and wiped for ransom.
- Use the `elastic` superuser in application code. Create a dedicated service user with read-only or limited write access.
- Accept raw user input in `query_string` or `script` queries — both allow injection.
- Enable `script.inline: true` or `script.stored: true` without strict RBAC — scripts can execute arbitrary code.
- Run Elasticsearch as root. Use the built-in `elasticsearch` user/group.
- Store sensitive data without field-level security or document-level security rules.

## Common AI Mistakes

- Generating `docker-compose.yml` with `discovery.type=single-node` and `xpack.security.enabled=false` for "simplicity."
- Building search endpoints that pass user input directly into `query_string` queries.
- Using `elastic:changeme` as credentials in code examples.
- Suggesting `CORS` headers on Elasticsearch itself instead of routing through an API gateway.
- Ignoring index permissions — granting `*` index access to application users.
