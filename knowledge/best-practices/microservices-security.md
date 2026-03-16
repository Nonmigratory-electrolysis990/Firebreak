# Microservices Security

## DO

- **Use a service mesh** (Istio, Linkerd) for automatic mTLS between services. It encrypts all inter-service traffic without application code changes.
- **Authenticate at the API gateway**. Validate JWTs, rate limit, and enforce CORS at the edge — don't push this to every service.
- **Implement service-to-service auth** with mTLS certificates or signed JWTs scoped to specific services. Never rely on network location alone.
- **Apply authorization per-service**. Even after gateway auth, each service must verify the caller is authorized for the specific operation.
- **Use circuit breakers** (Resilience4j, Polly) to prevent cascading failures. A compromised or degraded service shouldn't take down the entire system.
- **Encrypt sensitive data in transit and at rest** across all service boundaries. Use TLS 1.3 minimum for inter-service communication.
- **Implement distributed tracing** (Jaeger, Zipkin) with correlation IDs. Essential for detecting anomalous patterns and forensic analysis.

## DON'T

- Trust requests from internal services without authentication. A compromised service in the mesh can impersonate any other service.
- Pass user JWTs directly between services without validation at each hop. Validate and re-scope tokens at service boundaries.
- Use shared database access across services. Each service owns its data — cross-service data access goes through authenticated APIs.
- Log full request/response bodies in inter-service calls. They often contain tokens, PII, and sensitive business data.
- Use HTTP between services "because they're in the same VPC." Network segmentation is defense-in-depth, not a substitute for encryption.
- Share secrets or credentials between services. Each service gets its own credentials with minimum required permissions.
- Skip health check authentication. Unauthenticated health endpoints can leak service topology and version information.

## Common AI Mistakes

- Building microservices that communicate over plain HTTP because "they're all in a private network."
- Creating a shared `ServiceAccount` with full database access used by all services.
- Implementing auth only at the API gateway and trusting all internal requests unconditionally.
- Passing the original user JWT through 5 service hops without re-validation, expiry checking, or scope reduction.
- Using a shared secret string for service-to-service auth: `if (req.headers['x-service-key'] === 'internal-secret')`.
