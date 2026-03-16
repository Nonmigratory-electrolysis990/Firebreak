# Zero Trust Architecture

## DO

- **Verify every request** regardless of network location. Internal network requests get the same authentication and authorization as external ones.
- **Implement least-privilege access** for every service, user, and process. Grant the minimum permissions needed for the specific task.
- **Use micro-segmentation** to isolate services at the network level. Service A should not be able to reach Service C's database even if they're in the same VPC.
- **Authenticate service-to-service calls** with mTLS, signed tokens, or workload identity (SPIFFE/SPIRE). Never rely on network location as proof of identity.
- **Continuously validate trust** — don't grant permanent sessions. Re-evaluate access based on device health, user behavior, and context.
- **Encrypt all traffic**, including east-west (service-to-service) traffic within your network. TLS everywhere, not just at the edge.
- **Log and monitor all access decisions** — approved and denied. You can't detect lateral movement without visibility into internal traffic.

## DON'T

- Trust a request because it came from an internal IP or VPN. Compromised internal services have the same network access as legitimate ones.
- Use network perimeter as your primary security control. Once an attacker is inside the perimeter, everything is exposed.
- Grant standing admin access. Use just-in-time (JIT) access with time-limited privilege elevation.
- Skip authentication for internal APIs because "only our services call them."
- Assume cloud VPCs are inherently secure. Default security groups and NACLs are often too permissive.
- Implement zero trust at the network layer only. Application-level identity verification is equally critical.

## Common AI Mistakes

- Building microservices that trust any request from within the Kubernetes cluster without authentication.
- Using shared API keys for service-to-service auth instead of per-service identity with mTLS.
- Implementing network policies but leaving application endpoints unauthenticated.
- Generating infrastructure code with overly broad security groups (`0.0.0.0/0` ingress on internal services).
- Treating VPN access as equivalent to authentication — "if they're on the VPN, they're authorized."
