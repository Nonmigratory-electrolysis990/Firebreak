# API Versioning Security

## DO

- **Version via URL path** (`/api/v2/resource`) or `Accept` header. URL path is simplest to enforce in middleware.
- **Apply current security standards to all versions**. When auth is upgraded (e.g., from API keys to OAuth), backport to old versions or deprecate them.
- **Set deprecation headers** on old versions: `Deprecation: true`, `Sunset: <date>`. Return `Warning: 299` with a human-readable message.
- **Enforce rate limiting per version**. Deprecated versions should have stricter limits to encourage migration.
- **Log version usage** to track which clients still call deprecated endpoints. Use this data to plan sunsets.
- **Require the same authentication** across all active versions. Never let v1 use weaker auth than v3.
- **Return 410 Gone** (not 404) for fully retired versions. Include a migration guide URL in the response body.
- **Document breaking security changes** in changelogs with explicit migration steps.

## DON'T

- Keep old API versions alive indefinitely. Each version is attack surface. Set sunset dates and enforce them.
- Maintain weaker validation or auth on legacy versions because "existing clients depend on it."
- Allow version negotiation via query parameter (`?version=1`) — it's easy to tamper and hard to enforce in WAF rules.
- Remove security middleware from old versions to "simplify maintenance."
- Ship a new version without reviewing the security posture of every endpoint that changed.
- Let deprecated versions skip new security features (CSRF protection, input validation, rate limiting).

## Common AI Mistakes

- Creating a v2 API with improved auth but leaving v1 running with the old, weaker auth scheme.
- Never setting a sunset date — generating v1, v2, v3 endpoints that all stay active forever.
- Copying route files for a new version without copying the security middleware registration.
- Using different input validation rules across versions, allowing bypasses on older versions.
- Not testing deprecated versions in CI — security regressions go unnoticed.
- Forgetting to version webhooks and internal service-to-service APIs, only versioning public APIs.
