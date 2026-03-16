# Contributing to Firebreak

Thanks for your interest. Here's how to contribute.

## Setup

```bash
git clone https://github.com/protonese3/Firebreak.git
cd Firebreak
cargo build
cargo test
```

The server runs on `http://localhost:9090/mcp`.

## What to work on

Check [open issues](https://github.com/protonese3/Firebreak/issues), especially those labeled `good first issue`.

### Adding a VCVD pattern

1. Add the pattern to `src/vcvd/data.rs`
2. Add a regex matcher to `src/tools/knowledge/check_pattern.rs` (if detectable)
3. Include OWASP mapping and CWE number

### Adding a best practice guide

1. Create a markdown file in `knowledge/best-practices/`
2. Follow the format: title, DO section, DON'T section, Common AI Mistakes section
3. Register it in `src/tools/knowledge/best_practices.rs`

### Adding a scan check

1. Add a check function in `src/engine/checks.rs`
2. Wire it into the appropriate scan method in `src/engine/mod.rs`
3. Call `safety.check_scope()` and `safety.acquire_rate_limit()` before every HTTP request

### Adding checklist items

1. Edit `src/tools/knowledge/checklist.rs`
2. Add items to the `ITEMS` array with the appropriate component, priority, and description

## Submitting changes

1. Fork the repo
2. Create a branch (`git checkout -b my-change`)
3. Make your changes
4. Run `cargo check && cargo clippy -- -D warnings`
5. Open a pull request

## Code style

- No unnecessary comments. If the code is clear, don't comment it.
- Guard clauses over nested if/else.
- Match the style of surrounding code.
- Every finding must have verifiable evidence.

## Security issues

If you find a security vulnerability in Firebreak itself, please email security@firebreak.dev instead of opening a public issue.
