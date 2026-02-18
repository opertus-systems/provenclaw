# ProvenClaw

ProvenClaw is a secure assistant runtime with policy-governed execution, provenance verification, signed receipts, and tamper-evident audit chains.

Phase 0.5 adds a TUI-first operator experience (`provenclaw`) plus script-friendly subcommands.

## Core invariants

1. Side effects only occur through verified bundles.
2. Tools are addressed by immutable digests.
3. Capabilities are deny-by-default.
4. Secrets are handle-based at the host boundary.
5. Every execution emits a receipt.
6. Network access is allowlist-only.
7. Every decision is auditable.

## Workspace layout

- `/Users/jove/code/provenclaw/crates/provenclaw-core`: shared types, config, receipts.
- `/Users/jove/code/provenclaw/crates/provenclaw-host`: runtime, provenance, signing, trust, enforcement.
- `/Users/jove/code/provenclaw/crates/provenclaw-policy`: policy parsing/evaluation/signature checks.
- `/Users/jove/code/provenclaw/crates/provenclaw-audit`: receipt persistence and audit-chain verification.
- `/Users/jove/code/provenclaw/crates/provenclaw-cli`: command router and automation interface.
- `/Users/jove/code/provenclaw/crates/provenclaw-tui`: full-screen terminal UX (ratatui + crossterm).
- `/Users/jove/code/provenclaw/crates/provenclaw-api`: optional local API schemas.

## Quick start

```bash
cargo build
cargo run -p provenclaw-cli -- init

# Interactive operator UX
cargo run -p provenclaw-cli

# Non-interactive automation
cargo run -p provenclaw-cli -- tools add sha256:abc123 --name fetch_invoice --publisher acme.sec --policy policy.default.json --signature /tmp/sig.json --attestation /tmp/att.json
cargo run -p provenclaw-cli -- run fetch_invoice --input /tmp/provenclaw-input.json
cargo run -p provenclaw-cli -- receipts deep-verify <receipt_id>
cargo run -p provenclaw-cli -- enforcement status
cargo run -p provenclaw-cli -- diagnostics security-report
```

## Runtime prerequisites

- `provenact` must be installed locally and available on `PATH`, or set `provenact_path` in `~/.provenclaw/config.toml`.
- Registered tools must include a valid `bundle_path` for secure execution.
- If runtime execution fails (missing bundle, missing `provenact`, invalid runtime output), ProvenClaw now records a denied decision with audit evidence instead of falling back.

## Docs

- `/Users/jove/code/provenclaw/docs/ARCHITECTURE.md`
- `/Users/jove/code/provenclaw/docs/THREAT_MODEL.md`
- `/Users/jove/code/provenclaw/docs/OPERATIONS.md`
- `/Users/jove/code/provenclaw/docs/ENTERPRISE_README.md`
