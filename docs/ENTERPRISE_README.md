# Enterprise Evaluation Notes (Phase 0)

## Evaluation goals

- Verify immutable tool addressing by digest.
- Confirm deny-by-default capability model.
- Validate auditable allow/deny decisions.
- Confirm receipt verification and audit exportability.

## Current guarantees

- Every `run` request produces a receipt artifact.
- Every request appends an audit record with policy/receipt hash links.
- Policy profiles restrict signer and capability scopes.
- Network use is blocked unless explicitly enabled and allowlisted.

## Pilot checklist

- Integrate Provenact full verification pipeline.
- Harden host ABI boundaries and runtime isolation.
- Add SIEM export bridge.
- Add packaging and deployment artifacts.
