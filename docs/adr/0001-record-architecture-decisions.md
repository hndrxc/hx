# ADR-0001: Record architecture decisions
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

The `hx` system is a distributed homelab and cloud observability, security, and alerting platform with strict trust boundaries. As the architecture evolves across foundational milestones, multiple architectural, cryptographic, and operational decisions must be preserved, auditable, and accessible to contributors and security reviewers. Without a disciplined mechanism to record the context, choices, trade-offs, and consequences of design decisions, rationale is easily lost, leading to accidental regressions, redundant debates, or unreviewed boundary expansions.

A structured Architecture Decision Record (ADR) system provides a durable log of engineering decisions, keeping architectural rationale version-controlled alongside repository documentation.

## Decision

We adopt a formal Architecture Decision Record (ADR) process governed by the following rules:

- **Storage and format**: Every significant architectural or security decision is recorded in an individual Markdown document located at `docs/adr/NNNN-kebab-title.md`, utilizing 4-digit zero-padded sequential numbers starting with `0001`. Numbers are permanent and never renumbered or recycled.
- **Fixed lifecycle statuses**: Every ADR must specify a `Status` that is strictly one of:
  - `Proposed`
  - `Accepted`
  - `Superseded by ADR-NNNN`
  - `Deprecated`
- **Immutability of Accepted ADRs**: Once an ADR is marked `Accepted` and merged to `main`, its `Decision` text and substantive content are immutable. If a decision changes or is refined, a new ADR must be authored to supersede it. The only permitted modification to an existing ADR upon supersession is updating its `Status` line (e.g. to `Status: Superseded by ADR-NNNN`).
- **Decoupling living version numbers**: ADRs define architectural policy, invariant requirements, and structural designs. Concrete version pins, library release tags, and OS platform matrix updates do not live in ADRs; they are maintained in [docs/compatibility.md](../compatibility.md).
- **Mandatory template structure**: Every ADR must strictly implement the standard template containing the sections `# ADR-NNNN: Title`, metadata header (`Status`, `Date`, `Issue`, `Superseded by`), `## Context`, `## Decision`, `## Consequences`, `## Verification`, and `## References`.
- **Review gate for boundary expansions**: Any code change or PR that introduces new external dependencies, expands a collector's permissions or network egress manifest, or modifies trust boundaries requires either a new/superseding ADR or an explicit security review recorded against the relevant component manifest.
- **Initial decision corpus**: ADRs 0001 through 0012 establish the baseline architecture for `hx` foundation issue #9 (F01).

## Consequences

### Positive
- Clear, version-controlled audit trail for all security-load-bearing architectural decisions.
- Contributors understand the invariants and boundaries before proposing implementations.
- Clean separation between immutable architectural policy (ADRs) and living dependency pins (`compatibility.md`).
- Established process for deprecation and supersession rather than silent drift.

### Negative / Trade-offs
- Modest overhead when introducing structural architectural or permission changes.
- Requires discipline to prevent living version numbers from leaking into ADR Decision bodies.

## Verification

Enforcement of this ADR is verified as follows:
- In [Issue #9 (F01)](https://github.com/hndrxc/hx/issues/9), docs validation checks verify that all twelve initial ADRs exist, conform strictly to the required template sections, define `Status: Accepted`, and are cataloged in `docs/adr/README.md`.
- In [Issue #20 (F04)](https://github.com/hndrxc/hx/issues/20), CI documentation linters verify ADR filename conventions, link integrity, and template section completeness on pull requests modifying `docs/adr/`.

## References

- Michael Nygard, "Documenting Architecture Decisions", checked 2026-11-06: https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions
- ADR GitHub Organization, "Architecture Decision Record (ADR)", checked 2026-11-06: https://adr.github.io/
- hx Architecture Decisions Issue #9, checked 2026-11-06: https://github.com/hndrxc/hx/issues/9
