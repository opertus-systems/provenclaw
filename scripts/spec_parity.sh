#!/usr/bin/env bash
set -euo pipefail

required_paths=(
  "Cargo.toml"
  "README.md"
  "configs/policy.default.json"
  "configs/provenclaw.example.toml"
  "docs/ARCHITECTURE.md"
  "docs/THREAT_MODEL.md"
  "docs/OPERATIONS.md"
  "docs/ENTERPRISE_README.md"
  "docs/PHASE0_BLUEPRINT.md"
  "crates/provenclaw-core/src/lib.rs"
  "crates/provenclaw-host/src/lib.rs"
  "crates/provenclaw-policy/src/lib.rs"
  "crates/provenclaw-audit/src/lib.rs"
  "crates/provenclaw-cli/src/main.rs"
  "crates/provenclaw-tui/src/lib.rs"
)

for path in "${required_paths[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing required path: $path"
    exit 1
  fi
done

echo "spec parity checks passed"
