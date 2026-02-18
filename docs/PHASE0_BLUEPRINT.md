# ProvenClaw Phase 0 Repository Blueprint

Status: Draft (Phase 0 - Corporate-First MVP)
Version: 0.1

## 1. Purpose

ProvenClaw is a secure assistant runtime built on Provenact. It provides a policy-governed orchestration layer that executes only verified, immutable, capability-constrained tools and emits cryptographic receipts for every action.

Phase 0 establishes ProvenClaw as an enterprise-evaluable execution governance host.

Non-goal: build a consumer-style autonomous agent.

## 2. Core Invariants

1. All side effects occur through Provenact-verified bundles.
2. Tools are addressed by immutable digests.
3. Capabilities are deny-by-default.
4. Secrets are never passed directly into tool memory.
5. All executions emit receipts.
6. Network access is allowlist-only.
7. All decisions are auditable.

## 3. Repository Layout

```text
provenclaw/
├─ crates/
│  ├─ provenclaw-core/
│  ├─ provenclaw-host/
│  ├─ provenclaw-policy/
│  ├─ provenclaw-audit/
│  ├─ provenclaw-cli/
│  └─ provenclaw-api/
├─ configs/
│  ├─ policy.default.json
│  └─ provenclaw.example.toml
├─ docs/
│  ├─ ARCHITECTURE.md
│  ├─ THREAT_MODEL.md
│  ├─ OPERATIONS.md
│  └─ ENTERPRISE_README.md
├─ scripts/
├─ .github/workflows/
├─ Cargo.toml
└─ README.md
```

## 4. Crate Responsibilities

### 4.1 provenclaw-core

Shared primitives:
- `ToolRef`
- `InvocationContext`
- `CapabilitySpec`
- `ReceiptEnvelope`
- Config loader/parsing helpers

No direct I/O side effects.

### 4.2 provenclaw-host

Main daemon/runtime (`provenclawd`):
- Load configuration
- Maintain tool registry
- Integrate bundle verification path
- Enforce policies
- Emit audit events
- Manage execution lifecycle

### 4.3 provenclaw-policy

Policy evaluation engine:
- Parse policy schema
- Validate capability ceilings
- Compute effective allow/deny decisions
- Explain policy outcomes

### 4.4 provenclaw-audit

Audit and receipt persistence:
- Append-only log writer
- Receipt store
- Verification helpers
- Export interface

Initial backend: NDJSON + filesystem.

### 4.5 provenclaw-cli

Operator interface (`provenclaw`):
- Tool management
- Invocation commands
- Receipt inspection
- Diagnostics

### 4.6 provenclaw-api (optional)

Local API schema and integration surface:
- Daemon service request/response contracts
- Local-only auth model
- JSON schema-friendly payloads

## 5. Configuration

### 5.1 Main Config (TOML)

Default location: `~/.provenclaw/config.toml`

Fields:
- `workspace_dir`
- `policy_dir`
- `receipt_dir`
- `provenact_path`
- `log_level`
- `network_enabled`

### 5.2 Tool Registry

Default location: `~/.provenclaw/tools.json`

```json
{
  "tools": [
    {
      "name": "fetch_invoice",
      "digest": "sha256:...",
      "publisher": "acme.sec",
      "policy": "policies/fetch.json"
    }
  ]
}
```

### 5.3 Policy Profile

Default location: `~/.provenclaw/policies/*.json`

```json
{
  "allowed_signers": ["acme.sec"],
  "capabilities": {
    "net.http": {
      "allow": [
        {
          "host": "api.example.com",
          "path": "/v1/",
          "method": "POST"
        }
      ]
    },
    "fs.read": {
      "allow": ["/data/"]
    }
  },
  "secrets": {
    "materialize": false
  }
}
```

## 6. Execution Flow

1. CLI/API receives request.
2. Resolve `ToolRef` by digest.
3. Load policy profile.
4. Verify bundle.
5. Compute effective policy.
6. Spawn runtime.
7. Enforce host ABI capabilities.
8. Capture receipt.
9. Persist audit record.
10. Return output.

## 7. Audit Record Schema

Default location: `~/.provenclaw/audit.ndjson`

```json
{
  "id": "uuid",
  "timestamp": "2026-02-13T19:00:00Z",
  "tool_digest": "sha256:...",
  "policy_hash": "sha256:...",
  "receipt_hash": "sha256:...",
  "decision": "allow",
  "reason": "policy-match",
  "duration_ms": 423
}
```

## 8. Security Model

### 8.1 Default Deny

- No network
- No filesystem
- No secrets
- No randomness

Unless explicitly granted.

### 8.2 Secret Handling

- Tools receive handles only.
- Host injects secrets at boundary.
- Outputs scanned for leakage.

### 8.3 Network Enforcement

- Central proxy
- Host/path/method allowlists
- Request logging

### 8.4 Prompt Injection

- External content marked tainted
- Sanitization pipeline
- Policy downgrade on taint

## 9. CLI Specification

```text
provenclaw init
provenclaw tools add <digest>
provenclaw tools ls
provenclaw run <name> --input file.json
provenclaw chat
provenclaw receipts ls
provenclaw receipts verify <id>
provenclaw receipts export --format json|ndjson
provenclaw policy explain <tool>
```

## 10. CI Requirements

- `cargo fmt`
- `cargo clippy -D warnings`
- `cargo test`
- `cargo audit`
- `cargo deny`
- spec parity checks

## 11. Phase 0 Milestones

- M0: Scaffold (repo + workspace + CI green)
- M1: Golden path (verify -> run -> receipt -> audit)
- M2: Policy enforcement (capability ceilings + allowlists)
- M3: Guardrails (injection scan + secret boundary)
- M4: Ops readiness (packaging + docs + runbooks)

## 12. Out of Scope

- Tool marketplace
- Dynamic code generation
- Remote execution
- Multi-tenant SaaS
- Rich memory subsystem
- Autonomous planning

## 13. Development Principles

- Prefer correctness over features.
- Every host ABI change requires review.
- Receipts are first-class artifacts.
- No ambient authority.
- Security regressions block releases.

## 14. Definition of Done

- Local daemon runs.
- Tools verified by digest.
- Policies enforced.
- Receipts verifiable.
- Audit log exportable.
- Threat model published.
- Enterprise pilot-ready.
