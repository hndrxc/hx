# ADR-0012: Defer AI Investigation Commitments and Establish Inviolable Safety Boundaries

- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

The overall product vision for `hx` includes an automated incident investigation and diagnostic assistance subsystem (Phase 3 milestone sequence A through F). However, the detailed specification for the AI investigation capability (source spec A–F) is not currently present in the repository and will be provided separately by the project owner.

Committing to specific model weights, inference runtimes, hardware footprints, tool catalogs, prompt templates, or evaluation metrics without the complete source specification would result in premature design assumptions, brittle architecture, and potential security boundary violations. At the same time, the core platform architecture requires unambiguous, non-negotiable safety boundaries to ensure that future AI capabilities cannot compromise the deterministic monitoring, alerting, and credential security foundations of `hx`.

## Decision

1. **Defer all model, runtime, and schema commitments**:
   - `hx` commits to no specific model family, model weights, license terms, model artifact digests, inference runtimes, diagnostic tool catalogs, time/token/memory budgets, report schemas, evaluation metrics, or evaluation thresholds in this architectural baseline.
   - All such commitments are explicitly deferred to issue AI01 (https://github.com/hndrxc/hx/issues/64) and follow-up AI issues upon receipt of the complete source specification.
   - The status of all missing AI source materials is documented in [`docs/ai-investigation-inputs.md`](../ai-investigation-inputs.md).

2. **Inviolable architectural safety constraints**:
   Future AI investigation capabilities introduced in Phase 3 must strictly conform to the following non-negotiable architectural boundaries:
   - **Deterministic rules and dedicated delivery retain total authority**: Alert detection, alert severity scoring, alert grouping, suppression, and routing are decided exclusively by the deterministic rules engine (`internal/hub/rules/`), and alert delivery dispatch is executed exclusively by dedicated notification delivery (`internal/hub/delivery/`). Neither subsystem depends on or awaits AI inference. AI components must never determine, override, or alter alert state, severity levels, routing, or delivery dispatch.
   - **Read-only controller with allowlisted tools**: The investigation controller interacts with the hub exclusively through a bounded, read-only interface with allowlisted diagnostic tools and strict execution budgets.
   - **Advisory-only output**: Investigation reports produced by models are treated as untrusted, advisory plain-text narrative citing evidence. Reports must explicitly cite evidence (log timestamps, metric series, health check results) and are rendered with sanitization in client interfaces.
   - **Optional, offline, and isolated inference**: The inference runtime is completely optional and disabled by default. When enabled, it executes locally (or via an isolated local sidecar), never requires external internet egress, and runs with unprivileged OS permissions.
   - **Shadow evaluation gate**: No AI-driven diagnostic features may be enabled in production workflows until they pass deterministic benchmark evaluations and shadow deployment validation (AI08 https://github.com/hndrxc/hx/issues/71).

## Consequences

- The core `hx` platform (Phases 0 through 2) remains lightweight, deterministic, and fully functional without any AI runtime, Python environment, or GPU/NPU dependencies.
- Downstream AI development is constrained by planned architectural boundaries: prompt injection cannot override deterministic rule outcomes, mutate monitoring state, or alter delivery dispatch because model outputs are strictly advisory plain text, tools are bounded and read-only, and neither rules nor delivery depend on inference (mitigations planned for enforcement across downstream AI issues).

## Verification
Planned for enforcement across downstream AI milestone issues:
- AI01 (https://github.com/hndrxc/hx/issues/64): Ingestion and formalization of the complete source specification A–F.
- N06 (https://github.com/hndrxc/hx/issues/58): Validation of hardware resource feasibility and CPU/RAM execution bounds on target hub hardware.
- AI03 (https://github.com/hndrxc/hx/issues/66): Static and runtime enforcement of read-only tool allowlists and controller budget limits.
- AI07 (https://github.com/hndrxc/hx/issues/67): Benchmark evaluation framework against simulated incident corpora.
- AI08 (https://github.com/hndrxc/hx/issues/71): Evaluation thresholds and shadow rollout gating.

## References

- [ADR-0002: Hub-Owned Credentials and Read-Only Integrations](0002-hub-owned-credentials-and-read-only-integrations.md)
- [ADR-0003: In-Process Collector Trust Boundary](0003-in-process-collector-trust-boundary.md)
- [Threat Model Trust Boundary TB10 (Hub ↔ Local Inference Service)](../security/threat-model.md)
- [AI Investigation Inputs Checklist](../ai-investigation-inputs.md)
- Issue #9: Architecture, threat model and supported-platform decisions: https://github.com/hndrxc/hx/issues/9 (checked 2026-11-06)
- Issue #64 (AI01): Ingest AI investigation specification: https://github.com/hndrxc/hx/issues/64 (checked 2026-11-06)
