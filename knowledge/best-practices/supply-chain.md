# Supply Chain Security

## DO

- **Review dependency changes** in every PR. Use `npm diff`, `pip-audit`, or `cargo audit` to inspect what changed between versions.
- **Pin exact dependency versions** in lockfiles (`package-lock.json`, `poetry.lock`, `Cargo.lock`). Commit lockfiles to version control.
- **Generate and maintain an SBOM** (Software Bill of Materials) using tools like `syft`, `cdxgen`, or `npm sbom`. Update it on every release.
- **Verify package signatures** where available. Use `npm audit signatures`, check GPG signatures on downloads, verify checksums.
- **Use reproducible builds** — the same source should produce the same binary. Pin build tool versions, use deterministic build flags.
- **Scan dependencies in CI** with tools like Snyk, Dependabot, or Trivy. Block merges when critical vulnerabilities are found.
- **Minimize your dependency tree** — each dependency is an attack surface. Evaluate whether you need a package or can implement the functionality in 20 lines.

## DON'T

- Install packages with `npm install random-package` in production without reviewing the source, maintainers, and download stats.
- Use unpinned version ranges (`"^1.0.0"`, `"*"`) for critical dependencies — a compromised minor release auto-installs.
- Ignore `npm audit` or `pip audit` warnings. Triage them: fix critical/high, document accepted risks for low.
- Download binaries from unofficial mirrors or unverified URLs. Use official package registries and verify checksums.
- Auto-merge Dependabot PRs without reviewing changelog and diff. Malicious updates have been distributed this way.
- Use `curl | bash` installation patterns in production CI pipelines. Download, verify checksum, then execute.

## Common AI Mistakes

- Adding dependencies for trivial functionality (`is-odd`, `left-pad`) instead of implementing it inline.
- Generating `package.json` with `"*"` or latest-major version ranges instead of pinned versions.
- Not including lockfiles in `.gitignore` recommendations — lockfiles SHOULD be committed.
- Suggesting `curl -sSL https://install.example.com | sh` without checksum verification.
- Ignoring transitive dependencies — the package you install is safe, but its dependency of a dependency is compromised.
