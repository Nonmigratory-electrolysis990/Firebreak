# RBAC Implementation

## DO

- **Deny by default**. Every route and resource starts inaccessible. Permissions are explicitly granted, never implicitly assumed.
- **Check permissions in middleware/guards**, not in business logic. Authorization happens before the handler runs.
- **Define a clear role hierarchy** (e.g., `viewer < editor < admin < super_admin`). Document which permissions each role inherits.
- **Use permission-based checks, not role-based**. Check `can("edit", "document")` not `role === "admin"`. Roles are permission bundles.
- **Audit every permission change** — who granted what to whom, when, and from which IP.
- **Implement resource-level permissions** where needed. "Editor" on Project A doesn't mean editor on Project B.
- **Re-evaluate permissions on every request**. Don't cache authorization decisions in the session for longer than one request.
- **Use a policy engine** (Casbin, OPA, Cedar, or custom) for complex rules. Inline if-else chains don't scale.

```rust
// Middleware pattern
fn require_permission(permission: &str) -> impl Filter {
    // Extracts user from token, checks permission against policy engine
    // Returns 403 Forbidden if denied — never 404 to hide resources
}
```

## DON'T

- Check roles with string comparisons scattered across handlers (`if user.role == "admin"`). Centralize in one place.
- Return 404 for authorization failures to "hide" resources — use 403. Hiding resources is obscurity, not security.
- Allow users to escalate their own roles without approval from a higher-privileged user.
- Store permissions only client-side (React context, Redux). The server is the authority.
- Forget to check authorization on related resources (user can edit post but also needs permission to edit its comments).
- Skip permission checks on bulk/batch endpoints — each item in the batch needs individual authorization.
- Use a single "admin" boolean. Real systems need granular permissions.

## Common AI Mistakes

- Adding `isAdmin` checks in React components but leaving API routes unprotected.
- Creating roles in a config file but never checking them in middleware.
- Building a role system where any authenticated user can access any resource by changing the ID in the URL (IDOR).
- Implementing RBAC in a `useEffect` hook instead of server-side middleware.
- Granting `*` wildcard permissions to the "admin" role and forgetting to scope super_admin operations.
- Caching role checks in localStorage and trusting them on subsequent requests.
