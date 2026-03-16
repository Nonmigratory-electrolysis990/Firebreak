# Kubernetes Security

## DO

- **Enforce RBAC** with least-privilege roles. Create `Role`/`ClusterRole` with specific verbs and resources — never use `cluster-admin` for workloads.
- **Enable Pod Security Standards** (Restricted profile). Set `securityContext`: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`.
- **Apply NetworkPolicies** to restrict pod-to-pod communication. Default-deny all ingress/egress, then allow only required traffic.
- **Encrypt Secrets at rest** with a KMS provider. Kubernetes Secrets are base64-encoded by default, not encrypted.
- **Scan container images** for vulnerabilities in CI/CD. Use tools like Trivy, Grype, or Snyk. Block deployment of images with critical CVEs.
- **Use service accounts per workload** with `automountServiceAccountToken: false` unless the pod needs API access.
- **Set resource limits** (`resources.limits`) on every container to prevent DoS from resource exhaustion.

## DON'T

- Run containers as root. Set `runAsNonRoot: true` and specify a non-root `runAsUser` in the pod security context.
- Use `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` unless absolutely required — they break pod isolation.
- Store secrets in ConfigMaps, environment variables in pod specs, or Helm `values.yaml`. Use external secret operators (External Secrets Operator, Vault).
- Pull images with `latest` tag. Pin to specific digests (`image: app@sha256:abc123`) for reproducibility and supply chain security.
- Grant `cluster-admin` to CI/CD service accounts. Create scoped roles for the specific namespaces and resources needed.
- Skip NetworkPolicies — without them, any pod can communicate with any other pod in the cluster.
- Expose the Kubernetes API server to the public internet without IP allowlisting.

## Common AI Mistakes

- Creating a `ClusterRoleBinding` with `cluster-admin` for a deployment's service account "so it can access the API."
- Defining Secrets in YAML manifests committed to git — base64 is encoding, not encryption.
- Setting `privileged: true` in the security context because "the container needs to bind to port 80."
- Omitting NetworkPolicies entirely and assuming namespace isolation provides network segmentation.
- Using `automountServiceAccountToken: true` (the default) on pods that never call the Kubernetes API.
