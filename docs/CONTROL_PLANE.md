# Control Plane Contract (Phase 1 Skeleton)

## Purpose

Define a stable boundary between the host runtime and a future control plane while keeping Phase 0.5 local execution intact.

## Current mode

- Mode: `local_only`
- Transport: `in_process`
- Authn hook: `local_shared_token` (contracted)
- Authz hook: embedded RBAC contract (`embedded-rbac`)

The host currently instantiates a local control-plane profile and surfaces it in diagnostics.

## API contracts

Implemented in `/Users/jove/code/provenclaw/crates/provenclaw-control-plane/src/lib.rs`.

### Requests

- `health`
- `profile`
- `authorize`

### Responses

- `health`
- `profile`
- `authorize`

### Authorization model

Actions are role-gated.

- Operator/auditor/security-admin actions:
  - `run_tool`
  - `read_receipts`
  - `verify_receipts`
  - `tail_audit`
  - `export_diagnostics`
- Security-admin-only actions:
  - `manage_policy`
  - `manage_trust`
  - `set_enforcement_mode`

## Transport choices (contracted)

- `in_process`: default local Phase 0.5 path.
- `unix_socket`: local daemon boundary for host <-> control-plane separation.
- `loopback_http`: localhost-only integration for local control-plane service.
- `mtls_https`: remote-capable endpoint for future enterprise control plane.

Transport validation rules are enforced in the contract crate.

## Authn/Authz hook choices

Authn schemes (contracted):

- `local_shared_token`
- `oidc_bearer`
- `mutual_tls`
- `workload_identity`

Authz hook modes:

- `local`
- `external`
- `disabled` (not recommended)

## Trust boundaries

1. Host runtime never bypasses the control-plane authorization contract for governance actions.
2. Transport type defines boundary hardness:
   - `in_process` < `unix_socket` < `loopback_http` < `mtls_https`.
3. Endpoint validation prevents obvious unsafe configurations (non-loopback loopback transport, non-absolute socket paths, non-HTTPS for mTLS transport).

## Non-goals in this phase

- No remote control plane implementation yet.
- No production OIDC or mTLS handshake implementation yet.
- No distributed state or tenancy model in this crate.
