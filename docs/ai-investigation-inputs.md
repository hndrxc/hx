# AI Investigation Missing Inputs and Source Material Checklist

## Status and Overview

The product vision for `hx` incorporates an automated incident investigation and diagnostic assistant (Phase 3 milestone sequence A through F). However, the referenced **AI investigation source specification (milestones A through F)** is not currently present in the repository.

Per [ADR-0012](adr/0012-defer-ai-investigation-commitments.md), `hx` commits to no specific model family, model weights, license terms, model artifact digests, inference runtimes, diagnostic tool catalogs, time/token/memory budgets, report schemas, evaluation metrics, or evaluation thresholds in this architectural baseline. The project owner will provide the complete source specification at a future date, and its formal ingestion and implementation will take place within issue [AI01 (https://github.com/hndrxc/hx/issues/64)](https://github.com/hndrxc/hx/issues/64).

Until that specification is supplied and accepted, nothing in the `hx` codebase represents, implements, or depends upon the AI investigation capability.

## Fixed Architectural Constraints

Regardless of the model, runtime, or tools ultimately selected upon delivery of the source specification, all future AI capabilities must conform to the fixed architectural safety constraints established in [ADR-0012](adr/0012-defer-ai-investigation-commitments.md) and the [System Threat Model](security/threat-model.md) (specifically Trust Boundary TB10):

1. **Deterministic rules and dedicated delivery retain alert authority**: Detection, severity assignment, alert grouping, suppression, and routing are decided exclusively by the deterministic rules engine (`internal/hub/rules/`), and alert delivery dispatch is executed exclusively by dedicated notification delivery (`internal/hub/delivery/`). Neither subsystem depends on or awaits AI inference. AI components never set or alter alert status, severity, routing, or delivery dispatch.
2. **Read-only controller and allowlisted tools**: The investigation controller interacts with the hub via a bounded, read-only interface with allowlisted diagnostic tools and strict execution budgets.
3. **Advisory plain-text reports**: Investigation outputs are strictly advisory, untrusted narratives citing evidence (timestamps, metrics, logs) and must undergo sanitization before rendering in clients.
4. **Optional, offline, and isolated inference**: The inference engine is disabled by default, runs locally (or via an isolated local sidecar), requires no internet egress, and operates with unprivileged OS rights.
5. **Mandatory evaluation and shadow gating**: No AI capability may be enabled in production workflows without satisfying quantitative benchmark thresholds and completing shadow rollout validation (AI08 https://github.com/hndrxc/hx/issues/71).
## Missing-Material Checklist

The following items are missing from the repository as of 2026-11-06 and are required before AI investigation implementation can begin. Each item is tracked with its resolving issue:

| Item | Description | Status & Owning Issue |
| --- | --- | --- |
| Source specification A–F | Complete specification covering incident investigation milestones A through F | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) |
| Model identity, license, and artifact digest | Exact model family, release tag, license terms, and cryptographic hash of model weights | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) |
| Hardware resource feasibility (CPU/RAM) | Profiling and validation of model execution footprint against Debian 13 hub target hardware constraints | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) / N06 (https://github.com/hndrxc/hx/issues/58) |
| Diagnostic tool catalog | Explicit catalog of read-only diagnostic tools, schema definitions, and permitted parameter ranges | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) |
| Execution budgets | Definitive ceilings on execution time, token context windows, response byte size, and tool call depth | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) |
| Report schema and citation format | Structured schema for investigation findings and mandatory evidence citation formatting | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) |
| Evaluation metrics and acceptance thresholds | Quantitative scoring rubric and pass/fail thresholds | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) / AI07 (https://github.com/hndrxc/hx/issues/67) |
| Shadow rollout criteria | Operational criteria and operator review workflows required for shadow mode evaluation | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) / AI08 (https://github.com/hndrxc/hx/issues/71) |
| Simulated incident corpus | Benchmark corpus of historical/synthetic multi-service telemetry failures used for deterministic regression testing | Missing — resolved in AI01 (https://github.com/hndrxc/hx/issues/64) |
## Related Documentation

- [ADR-0012: Defer AI Investigation Commitments and Establish Inviolable Safety Boundaries](adr/0012-defer-ai-investigation-commitments.md)
- [Architecture Overview](architecture/overview.md)
- [System Threat Model (Trust Boundary TB10)](security/threat-model.md)
