# GraphQL Security

## DO

- **Disable introspection in production** — introspection exposes your entire schema (types, fields, relationships) to attackers.
```javascript
// Apollo Server
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== "production",
});
```
- **Enforce query depth limiting** — prevent deeply nested queries that cause N+1 explosions. Set max depth to 7-10 levels.
- **Implement query complexity analysis** — assign cost to each field and reject queries exceeding a threshold. Use `graphql-query-complexity` or equivalent.
- **Apply field-level authorization** — check permissions in resolvers, not just at the query entry point. A user query nested inside an admin query bypasses top-level auth.
- **Use persisted queries** (automatic or stored) in production — clients send a query hash, the server looks up the pre-registered query. Blocks arbitrary query construction.
- **Rate limit by query complexity**, not just by request count — one complex query can be more expensive than 1000 simple ones.
- **Disable unused operations** — if your API only uses queries and mutations, explicitly disable subscriptions.

## DON'T

- Expose introspection in production — tools like GraphQL Voyager let attackers map your entire API in seconds.
- Allow unlimited query depth — `{ user { friends { friends { friends { friends { ... } } } } } }` causes exponential DB load.
- Authorize only at the root query level — nested field resolvers must independently verify access.
- Return verbose error messages with stack traces, SQL queries, or internal field names.
- Allow batch queries without limits — attackers can send 1000 queries in a single request to bypass rate limiting.
- Trust client-side query construction — without persisted queries, any authenticated user can craft arbitrary queries against your schema.
- Expose internal IDs (auto-increment) — use UUIDs or opaque identifiers. Sequential IDs enable enumeration.

## Common AI Mistakes

- Leaving `introspection: true` as the default without environment-gating it.
- Implementing auth middleware on REST routes but leaving GraphQL resolvers unprotected.
- Generating resolvers that directly expose database models without field-level access control.
- Creating GraphQL subscriptions over WebSocket without authentication on the connection.
- Not implementing pagination on list fields — `{ users { id email } }` returns every user in the database.
- Using DataLoader for N+1 but not limiting the total number of batched queries per request.
