# Feature Flags Security

## DO

- **Evaluate flags server-side**. The server decides which features are enabled. Send only the results (enabled/disabled) to the client, never the rules or targeting criteria.
- **Authenticate flag management endpoints**. The API that creates, modifies, and deletes flags must require admin authentication and authorization.
- **Audit all flag changes** — who changed what flag, when, old value, new value. Flag changes are effectively deployments and should be tracked like code changes.
- **Use gradual rollout with monitoring**. Roll out to 1%, then 5%, 10%, 50%, 100%. Monitor error rates and performance at each stage. Have a kill switch.
- **Set flag expiry dates**. Temporary flags (experiments, rollouts) should have a removal date. Stale flags accumulate as technical debt and security risk.
- **Restrict flag targeting data**. If flags target by user attributes, ensure those attributes aren't sensitive (don't target by SSN or health status).
- **Implement flag-level permissions**. Not every developer should be able to toggle every flag. Critical flags (payment, auth, security) need elevated permissions.
- **Test both flag states** in CI. If a flag gates behavior, both the on and off paths need test coverage.

## DON'T

- Store secrets in flag values (API keys, tokens, database passwords). Flag systems are not secrets managers.
- Expose flag evaluation rules to the client. Rules like "enable for users in group X" leak internal business logic and user segmentation.
- Use feature flags to gate security controls. If the flag is accidentally disabled, the security control disappears.
- Allow unauthenticated access to the flag management API. This lets attackers toggle features remotely.
- Trust client-side flag overrides in production. Local overrides are for development only — the server must be the authority.
- Leave flags enabled forever without review. Dead flags are dead code — they obscure behavior and increase attack surface.

## Common AI Mistakes

- Sending the full flag configuration (including rules and user targeting) to the frontend JavaScript bundle.
- Creating a `/api/flags` endpoint with no authentication that returns all flag states and their targeting rules.
- Using feature flags to toggle authentication or authorization — disabling the flag disables security.
- Not testing the "flag off" code path, so disabling a flag in an emergency crashes the application.
- Storing database connection strings or API keys as flag values because "it's easy to change them."
- Implementing client-side flag evaluation with all business logic exposed in the JavaScript bundle.
