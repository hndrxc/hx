# hx Documentation

**Status:** Core Go module and minimal CLI bootstrap implemented in [F02 (#10)](https://github.com/hndrxc/hx/issues/10). `hx hub`, `hx tui` and bare `hx-agent`/`hx-desktop` exit 1; help/version exit 0; `hx` without arguments prints help and exits 0. Further subsystem implementations remain planned.

- [Build & Verification Guide](build.md) — Toolchain requirements, headless build commands, version injection, GUI isolation, and import policy enforcement.
- [Architecture Overview](architecture/overview.md) — System context, hub internals, remote read sequence, and vault lifecycle diagrams plus data flow rules.
- [CI & Ruleset Configuration](ci.md) — Specification of continuous integration checks (formatting, build, test, generated), fork execution security, and repository protection ruleset setup.
- [Contributing Guide](../CONTRIBUTING.md) — Contribution workflow, branch conventions, PR acceptance criteria, and local check commands.
- [Security Policy](../SECURITY.md) — Security scope, vulnerability disclosure procedure, and credential handling rules.
- [Project README](../README.md) — System overview, implemented vs. planned status, credential-free quickstart, and license.
- [Threat Model](security/threat-model.md) — Trust zones, trust boundaries TB1–TB13, the root STRIDE register, residual risks, and the review checklist.
- [ADR Index & Process](adr/README.md) — The architecture decision record process, template, and index of ADRs 0001–0012.
- [ADR-0001: Record Architecture Decisions](adr/0001-record-architecture-decisions.md) — Adopts the ADR process as the record for F01 and all later security-relevant decisions.
- [ADR-0002: Hub-Owned Credentials and Read-Only Integrations](adr/0002-hub-owned-credentials-and-read-only-integrations.md) — Provider credentials live only in the hub vault; integrations are read-only through Phase 3.
- [ADR-0003: In-Process Collector Trust Boundary](adr/0003-in-process-collector-trust-boundary.md) — Built-in collectors share the hub process and make no isolation claim; untrusted collectors are never loaded in-process.
- [ADR-0004: Toolchain and Dependency Selection](adr/0004-toolchain-and-dependency-selection.md) — Selects the Go toolchain and libraries (Cobra, Charm v2, ConnectRPC v2, SQLite, tsnet, Wails v3).
- [ADR-0005: Supported Platforms and Build Targets](adr/0005-supported-platforms-and-build-targets.md) — Defines Supported / Build-verified / Build-unverified / Unsupported tiers for each binary's targets.
- [ADR-0006: Private TLS Trust Without Verification Bypass](adr/0006-private-tls-trust-without-verification-bypass.md) — Establishes `private-ca` and `pinned-leaf` trust modes without disabling certificate verification.
- [ADR-0007: Tailnet Transport and Bootstrap Egress](adr/0007-tailnet-transport-and-bootstrap-egress.md) — Hub embeds tsnet with mTLS + WhoIs; clients/agents use the host Tailscale client; egress allowlist.
- [ADR-0008: Outbound-Only Device Agents](adr/0008-outbound-only-device-agents.md) — Agents open no listening socket and push bounded batches with an ingest-only role.
- [ADR-0009: Vault Locked Start and Unlock](adr/0009-vault-locked-start-and-unlock.md) — Hub vault starts locked on every process start; unlock only via local IPC with a TTY passphrase.
- [ADR-0010: Provider Permission Gaps](adr/0010-provider-permission-gaps.md) — Records intended read-only credentials and suspected permission gaps per provider, all unverified pending implementation.
- [ADR-0011: Package Layout and Dependency Direction](adr/0011-package-layout-and-dependency-direction.md) — Defines the Go package layout and allow/deny import rules that F02 must implement and test.
- [ADR-0012: Defer AI Investigation Commitments](adr/0012-defer-ai-investigation-commitments.md) — Fixes only the constraints for AI; all model/tool/budget/report commitments land with AI01 #64.
- [Compatibility & Capability Matrix](compatibility.md) — Dated version and platform/capability matrix; the source of truth for version numbers.
- [AI Investigation Inputs](ai-investigation-inputs.md) — Lists the missing AI investigation source material that lands with AI01 #64.
- [Build Feasibility Spike](spikes/2026-11-build-feasibility.md) — Evidence from the throwaway toolchain build spike (environment, builds, smoke runs, scan).
