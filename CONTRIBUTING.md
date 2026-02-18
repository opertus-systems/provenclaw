# Contributing

## Development Setup

1. Install Rust with `rustup`.
2. Use the repository toolchain from `rust-toolchain.toml`.
3. Clone the repository and initialize local layout with `cargo run -p provenclaw-cli -- init`.

## Required Checks Before PR

Run all checks locally:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check advisories bans sources
cargo audit
./scripts/spec_parity.sh
```

## Pull Request Requirements

1. Use a feature branch (prefix `codex/` is preferred for Codex-generated work).
2. Keep changes scoped and include tests for behavior changes.
3. Document security-impacting changes in `README.md` or `/docs` as needed.
4. Ensure CI is green before merge.

## Security Requirements

1. Do not add fallback execution paths that bypass provenance checks.
2. Keep capability enforcement deny-by-default.
3. Treat host ABI and policy schema changes as security-sensitive.
4. Never commit raw secrets or secret material.

## Release and Signing Expectations

1. Release tags must be annotated and signed.
2. Release notes must include:
   - toolchain version,
   - gate results,
   - security-relevant dependency changes.
3. Runtime and policy artifacts must remain digest-addressed and verifiable.
