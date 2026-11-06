# Architecture Decision Records (ADR)

This directory contains the Architecture Decision Records (ADRs) for `hx`. ADRs capture significant architectural, security, and design choices along with their context, trade-offs, and consequences.

## Process and Rules

- **One decision per file**: Each record is stored as `docs/adr/NNNN-kebab-title.md` using 4-digit sequential numbers (e.g. `0001-record-architecture-decisions.md`). Numbers are never renumbered or reused.
- **Status values**: Status MUST be exactly one of:
  - `Proposed`
  - `Accepted`
  - `Superseded by ADR-NNNN`
  - `Deprecated`
- **Immutability of Accepted ADRs**: After an ADR is marked `Accepted` and merged, its Decision text is immutable. When a decision changes, a new ADR is authored that supersedes it; only the `Status` line of the previous record is updated (e.g. to `Status: Superseded by ADR-NNNN`).
- **Living version numbers**: Living version numbers (e.g., dependency patch versions or platform matrix updates) do NOT go into ADRs. Living versions and concrete version pins live in [docs/compatibility.md](../compatibility.md). ADRs record architectural policy and structural invariants.
- **Scope expansions**: Any change that expands a collector manifest, permission set, or provider access scope requires an ADR or an explicit manifest-diff security review.

## ADR Template

All ADRs in this directory MUST follow this exact structure:

```markdown
# ADR-NNNN: Title
- Status: Accepted
- Date: YYYY-MM-DD
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none
## Context
## Decision
## Consequences
## Verification
## References
```

- **Verification**: Explicitly describes how and in which follow-up issue(s) the decision is enforced, verified, and tested.
- **References**: Lists primary technical and design sources with "checked YYYY-MM-DD" dates.

## ADR Index

| ADR | Title | Status | Owning follow-up issues |
|---|---|---|---|
| [ADR-0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted | [Issue #9 (F01)](https://github.com/hndrxc/hx/issues/9) |
| [ADR-0002](0002-hub-owned-credentials-and-read-only-integrations.md) | Hub-owned credentials and read-only integrations | Accepted | [Issue #14 (S02)](https://github.com/hndrxc/hx/issues/14), [Issue #18 (S07)](https://github.com/hndrxc/hx/issues/18), [Issue #72 (X01)](https://github.com/hndrxc/hx/issues/72), [Issue #73 (X02)](https://github.com/hndrxc/hx/issues/73) |
| [ADR-0003](0003-in-process-collector-trust-boundary.md) | In-process collector trust boundary | Accepted | [Issue #24 (I01)](https://github.com/hndrxc/hx/issues/24), [Issue #79 (E01)](https://github.com/hndrxc/hx/issues/79) |
| [ADR-0004](0004-toolchain-and-dependency-selection.md) | Toolchain and dependency selection | Accepted | [Issue #10 (F02)](https://github.com/hndrxc/hx/issues/10), [Issue #22 (D01)](https://github.com/hndrxc/hx/issues/22), [Issue #23 (D02)](https://github.com/hndrxc/hx/issues/23) |
| [ADR-0005](0005-supported-platforms-and-build-targets.md) | Supported platforms and build targets | Accepted | [Issue #10 (F02)](https://github.com/hndrxc/hx/issues/10), [Issue #43 (O01)](https://github.com/hndrxc/hx/issues/43), [Issue #60 (C03)](https://github.com/hndrxc/hx/issues/60), [Issue #61 (A01)](https://github.com/hndrxc/hx/issues/61), [Issue #62 (A02)](https://github.com/hndrxc/hx/issues/62) |
| [ADR-0006](0006-private-tls-trust-without-verification-bypass.md) | Private TLS trust without verification bypass | Accepted | [Issue #16 (S05)](https://github.com/hndrxc/hx/issues/16), [Issue #20 (F04)](https://github.com/hndrxc/hx/issues/20), [Issue #25 (I02)](https://github.com/hndrxc/hx/issues/25) |
| [ADR-0007](0007-tailnet-transport-and-bootstrap-egress.md) | Tailnet transport and bootstrap egress | Accepted | [Issue #15 (S04)](https://github.com/hndrxc/hx/issues/15), [Issue #18 (S07)](https://github.com/hndrxc/hx/issues/18), [Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19), [Issue #43 (O01)](https://github.com/hndrxc/hx/issues/43) |
| [ADR-0008](0008-outbound-only-device-agents.md) | Outbound-only device agents | Accepted | [Issue #61 (A01)](https://github.com/hndrxc/hx/issues/61), [Issue #62 (A02)](https://github.com/hndrxc/hx/issues/62) |
| [ADR-0009](0009-vault-locked-start-and-unlock.md) | Vault locked-start and unlock | Accepted | [Issue #14 (S02)](https://github.com/hndrxc/hx/issues/14), [Issue #22 (D01)](https://github.com/hndrxc/hx/issues/22), [Issue #81 (E03)](https://github.com/hndrxc/hx/issues/81) |
| [ADR-0010](0010-provider-permission-gaps.md) | Provider permission floors and known gaps | Accepted | [Issue #36](https://github.com/hndrxc/hx/issues/36), [Issue #37](https://github.com/hndrxc/hx/issues/37), [Issue #38](https://github.com/hndrxc/hx/issues/38), [Issue #39](https://github.com/hndrxc/hx/issues/39), [Issue #45](https://github.com/hndrxc/hx/issues/45), [Issue #46](https://github.com/hndrxc/hx/issues/46), [Issue #47](https://github.com/hndrxc/hx/issues/47), [Issue #48](https://github.com/hndrxc/hx/issues/48), [Issue #49](https://github.com/hndrxc/hx/issues/49), [Issue #50](https://github.com/hndrxc/hx/issues/50) |
| [ADR-0011](0011-package-layout-and-dependency-direction.md) | Package layout and dependency direction | Accepted | [Issue #10 (F02)](https://github.com/hndrxc/hx/issues/10), [Issue #22 (D01)](https://github.com/hndrxc/hx/issues/22) |
| [ADR-0012](0012-defer-ai-investigation-commitments.md) | Defer AI investigation commitments | Accepted | [Issue #58 (N06)](https://github.com/hndrxc/hx/issues/58), [Issue #64 (AI01)](https://github.com/hndrxc/hx/issues/64), [Issue #66 (AI03)](https://github.com/hndrxc/hx/issues/66), [Issue #67 (AI07)](https://github.com/hndrxc/hx/issues/67), [Issue #71 (AI08)](https://github.com/hndrxc/hx/issues/71) |
