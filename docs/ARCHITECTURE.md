# ProvenClaw Architecture (Phase 0.5)

## Purpose

ProvenClaw is a local execution-governance runtime for verified tools, with enterprise-auditable provenance and policy enforcement.

## Execution flow

1. CLI/TUI receives a request.
2. Host resolves tool metadata by name/digest.
3. Host loads trust store and policy profile.
4. Host runs provenance verification (`digest + signature + attestation`) through the verifier adapter.
5. Policy engine validates policy signature and capability ceilings.
6. Policy engine computes allow/deny.
7. Enforcement mode (`warn` or `enforce`) applies provenance failure behavior.
8. Host resolves control-plane contract (currently local in-process) for authn/authz/transport boundaries.
9. Runtime executor enforces capability preflight and delegates execution to `provenact run` with strict limits (no insecure fallback path).
10. Host signs receipt and appends hash-chained audit record.
11. CLI/TUI exposes deep verification and diagnostics.

## Control-plane boundaries

- Host runtime and control-plane communicate only through typed contracts from `provenclaw-control-plane`.
- Default Phase 0.5 mode is local in-process control-plane (`mode=local_only`, `transport=in_process`).
- Remote-capable transport contract exists but is not active by default:
  - `unix_socket`
  - `loopback_http`
  - `mtls_https`
- Authn hooks are explicit (`local_shared_token`, `oidc_bearer`, `mutual_tls`, `workload_identity`).
- Authz hooks are explicit with role-based decision points for high-risk actions (`manage_trust`, `manage_policy`, `set_enforcement_mode`).

## Crate responsibilities

- `provenclaw-core`: shared security models (`EnforcementMode`, `VerificationReport`, signed `ReceiptEnvelope`, config model).
- `provenclaw-policy`: policy schema, signature checks, capability ceiling checks, decision engine.
- `provenclaw-audit`: append-only audit records, sequence/hash chain, chain verification, receipt store.
- `provenclaw-control-plane`: control-plane API contracts, transport/auth hooks, role-based authorization boundary.
- `provenclaw-host`: provenance verifier integration, runtime execution, receipt signing, trust/enforcement APIs.
- `provenclaw-cli`: TUI-first entrypoint and automation-friendly subcommands.
- `provenclaw-tui`: full-screen operations cockpit with command palette and multi-view navigation.
- `provenclaw-api`: optional local API request/response schema crate.
