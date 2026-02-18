# Threat Model (Phase 0)

## Assets

- Tool digests and signer metadata.
- Policy profiles and capability allowlists.
- Execution receipts.
- Audit records.
- Secret handles (not raw secret values).

## Trust boundaries

- CLI/user input -> host runtime.
- Host runtime -> control-plane contract boundary.
- Host runtime -> verified bundle runtime.
- Host runtime -> network egress proxy boundary.
- Host runtime -> policy and audit storage.

## Primary threats and controls

- Digest spoofing: tools must reference immutable `sha256:` digests.
- Unauthorized signer execution: policy allowlist on signers.
- Capability escalation: deny-by-default with explicit allowlists.
- Prompt injection pivot: tainted input downgrades network capability.
- Secret leakage: `secrets.materialize=false` by default and boundary control.
- Audit tampering: append-only NDJSON log and receipt hash verification.

## Residual risks in Phase 0

- Provenance quality still depends on external `provenact` verifier/runtime correctness and operator key hygiene.
- Runtime hardening is capability-broker + external sandbox delegation; kernel-level isolation policy is not yet formally verified.
- TUI dependency chain currently includes upstream RustSec warnings (`RUSTSEC-2024-0436`, `RUSTSEC-2026-0002`) via `ratatui`.
- Output leakage scanning is policy-level placeholder, not deep DLP.
