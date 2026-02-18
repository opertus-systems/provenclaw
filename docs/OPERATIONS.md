# Operations Runbook (Phase 0.5)

## Initialize

```bash
cargo run -p provenclaw-cli -- init
```

Creates `~/.provenclaw/` with:
- `config.toml`
- `tools.json`
- `trust.json`
- `policies/policy.default.json`
- `audit.ndjson`
- `metrics.ndjson`
- `receipts/*.json`

## Interactive operator workflow

```bash
cargo run -p provenclaw-cli
# or explicit
cargo run -p provenclaw-cli -- tui
cargo run -p provenclaw-cli -- tui --read-only
cargo run -p provenclaw-cli -- tui --snapshot /tmp/provenclaw-snapshot.txt
```

If no TTY is available and no subcommand is provided, `provenclaw` exits non-zero with guidance to use explicit subcommands.

## Register tool with provenance artifacts

```bash
cargo run -p provenclaw-cli -- tools add sha256:<digest> \
  --name <tool_name> --publisher <signer> --policy policy.default.json \
  --signature /path/to/signature.json --attestation /path/to/attestation.json
```

## Run tool

```bash
cargo run -p provenclaw-cli -- run <tool_name> --input ./input.json
```

Execution is fail-safe at runtime boundaries: missing bundle paths, missing `provenact`, or invalid runtime output are recorded as denied runs with receipts/audit records.

## Receipt and audit verification

```bash
cargo run -p provenclaw-cli -- receipts ls
cargo run -p provenclaw-cli -- receipts verify <receipt_id>
cargo run -p provenclaw-cli -- receipts deep-verify <receipt_id>
cargo run -p provenclaw-cli -- receipts export --format json
cargo run -p provenclaw-cli -- receipts export --format ndjson
```

## Trust and enforcement

```bash
cargo run -p provenclaw-cli -- trust ls
cargo run -p provenclaw-cli -- trust add-signer <signer>
cargo run -p provenclaw-cli -- trust revoke-signer <signer>

cargo run -p provenclaw-cli -- enforcement status
cargo run -p provenclaw-cli -- enforcement evaluate-slo
cargo run -p provenclaw-cli -- enforcement set-mode warn
cargo run -p provenclaw-cli -- enforcement set-mode enforce
```

## Diagnostics

```bash
cargo run -p provenclaw-cli -- diagnostics security-report
```
