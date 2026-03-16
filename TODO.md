# TODO

Last updated: 2026-03-16

## Priority

- Rework the trust boundary in signing mode handling; "hardware" mode must not silently fall back to software-key paths.
- Replace naive filesystem prefix matching in policy evaluation with canonical, boundary-aware path checks.
- Re-review `#11` only after the signing and policy model are hardened and retested.
- Add explicit threat-model documentation for host, policy, and control-plane interactions.

## Notes

- `#11` remains intentionally unmerged despite passing CI because the current design still has real security flaws.
