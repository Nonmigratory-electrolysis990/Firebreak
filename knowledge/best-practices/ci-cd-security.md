# CI/CD Security

## DO

- **Inject secrets via the CI platform's secret store** (GitHub Actions secrets, GitLab CI variables, CircleCI contexts). Never hardcode secrets in pipeline files.
- **Mask secrets in logs**. Most CI platforms auto-mask registered secrets, but verify with `echo "$SECRET"` tests. Use `::add-mask::` in GitHub Actions for dynamic values.
- **Sign commits and verify in CI**. Require signed commits on protected branches. Use GPG or SSH signing with verified identities.
- **Run dependency scanning** (Dependabot, Snyk, Trivy) in every PR pipeline. Block merges when critical vulnerabilities are found.
- **Generate and publish SBOMs** (Software Bill of Materials) with each release. Use SPDX or CycloneDX format for supply chain transparency.
- **Use ephemeral CI runners** that are destroyed after each job. Persistent runners accumulate credentials, cached data, and attack surface.
- **Pin action/image versions by SHA**, not tag: `uses: actions/checkout@abc123` not `uses: actions/checkout@v4`. Tags are mutable.

## DON'T

- Print secrets in CI logs, even for debugging. Use `${{ secrets.TOKEN }}` without echoing. If you must debug, use a temporary dummy value.
- Store secrets in `.env` files committed to the repository. Use `.env.example` with placeholder values.
- Allow CI pipelines to run on untrusted forks without restrictions. Fork PRs can exfiltrate secrets if `pull_request_target` is misconfigured.
- Use `pull_request_target` in GitHub Actions with `actions/checkout` of the PR branch — it runs fork code with repo secrets.
- Skip dependency lock files (`package-lock.json`, `Cargo.lock`) in CI. Without them, builds may fetch tampered packages.
- Use broad permissions on CI/CD tokens. GitHub Actions: set `permissions` explicitly per job instead of `permissions: write-all`.
- Allow self-hosted runners to be shared across public and private repos.

## Common AI Mistakes

- Writing `echo $DATABASE_URL` in a pipeline step for "debugging connectivity."
- Using `permissions: write-all` at the workflow level instead of scoping to specific permissions per job.
- Referencing actions by tag (`actions/checkout@v4`) instead of pinning to a commit SHA.
- Using `pull_request_target` with `actions/checkout@${{ github.event.pull_request.head.sha }}` — runs untrusted code with secrets.
- Creating a `.env` file in CI with `echo "API_KEY=${{ secrets.API_KEY }}" > .env` and accidentally uploading it as an artifact.
