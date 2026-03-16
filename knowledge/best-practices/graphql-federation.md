# GraphQL Federation Security

## DO

- **Authenticate at the gateway** and propagate verified user context to subgraphs via headers. Subgraphs should never accept raw user tokens directly.
- **Use service-to-service authentication** between the gateway and subgraphs. Use mTLS or signed internal tokens that subgraphs verify.
- **Apply authorization directives** (`@auth`, `@requiresScope`) at the schema level in each subgraph. Don't rely solely on gateway-level auth.
- **Limit query depth and complexity** at the gateway using `depthLimit` and `costAnalysis` plugins. Federated queries can fan out exponentially across subgraphs.
- **Validate the composed supergraph schema** for security issues: exposed internal fields, unprotected mutations, missing auth directives.
- **Rate limit by operation** at the gateway. A single GraphQL request can trigger dozens of subgraph requests via nested resolvers.
- **Use `@inaccessible`** to hide internal-only fields from the public API surface in your composed schema.

## DON'T

- Let subgraphs accept requests from any source. Restrict ingress to the gateway only (network policy + auth).
- Trust headers from the gateway without verification — a compromised gateway or network attacker can forge them.
- Expose the gateway's introspection endpoint in production. Disable it or protect it with authentication.
- Allow unbounded entity resolution — `_entities` queries can be abused to mass-fetch data across subgraphs.
- Share a single database user across subgraphs. Each subgraph should have scoped database permissions.
- Skip authorization in `__resolveReference` — entity references must still check if the requesting user can access the resolved entity.

## Common AI Mistakes

- Implementing auth only at the gateway with no verification in subgraphs — a misconfigured network exposes unauthenticated subgraph APIs.
- Enabling introspection on the gateway and all subgraphs in production.
- Not setting query depth or complexity limits, allowing deeply nested federated queries that overwhelm subgraphs.
- Passing raw JWT tokens to subgraphs instead of verified, minimal user context.
- Using `@external` fields without considering that they bypass the owning subgraph's authorization logic.
