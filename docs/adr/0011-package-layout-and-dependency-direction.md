# ADR-0011: Package Layout and Dependency Direction

- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

`hx` is composed of multiple binary entrypoints operating in different operational contexts:
1. `hx` — unified CLI executable serving as both the hub runtime (`hx hub`) and terminal client (`hx tui` and subcommands).
2. `hx-desktop` — graphical desktop client using Wails v3.
3. `hx-agent` — headless outbound-only telemetry agent for managed devices.

Because `hx hub` manages sensitive state (vault material, credentials, hub CA private keys, egress policies, and collector code), separate client binaries (`cmd/hx-desktop`, `cmd/hx-agent`) and client package subtrees must never depend on server-side hub components, egress controls, or provider integrations. The unified `cmd/hx` binary intentionally links both hub and client code paths into a single executable, but its client front-end code paths (such as `hx tui`) must import only client packages, while `cmd/hx-desktop` and `cmd/hx-agent` remain completely free of hub code. Without strict architectural package boundaries and automated dependency checking, shared-code refactorings can inadvertently pull hub packages or provider integrations into separate client binaries.

## Decision

We establish an explicit target package layout and a strict, checkable import dependency hierarchy. The target structure will be created by downstream issues (starting with F02 https://github.com/hndrxc/hx/issues/10) and enforced continuously.

### Target Package Layout

```
cmd/hx/                    Cobra root; `hub` and `tui` subcommands (F02)
cmd/hx-desktop/            Wails v3 entry (F02/C03)
cmd/hx-agent/              device agent entry (F02/A02)
proto/hx/v1/               protobuf sources (D01)
internal/buildinfo/        version metadata (F02)
internal/domain/           provider-neutral resources/observations/events (D01)
internal/api/              generated protobuf + Connect code (D01)
internal/secret/           redacted secret values, scoped handles (S01)
internal/sanitize/         untrusted-text sanitization (S06)
internal/client/           hub RPC client, client config, enrollment credential storage (S07/C01)
internal/cli/              CLI command implementations (C01)
internal/tui/              terminal user interface views and components (C02)
internal/desktop/          desktop backend bindings and assets (C03)
internal/agent/            host metrics collection and telemetry loop (A01/A02)
internal/hub/              hub core services (S02/S03/S08/D02/H01-H04)
  internal/hub/vault/      data key encryption, Argon2id wrapping, secure lock/unlock
  internal/hub/audit/      hash-chained audit logging
  internal/hub/store/      SQLite storage, migrations, and queries
  internal/hub/scheduler/  collector scheduling engine
  internal/hub/rules/      deterministic evaluation and alerting rules
  internal/hub/delivery/   notification dispatching
  internal/hub/rpc/        ConnectRPC server handlers and mTLS/WhoIs authn
  internal/hub/ipc/        local administration Unix socket IPC handlers
  internal/hub/enroll/     operator approval and enrollment workflows
internal/egress/           egress policy enforcement + TLS trust/pinning (S04/S05)
internal/collector/        manifest definitions, Collector interface, runtime context (I01)
internal/integrations/     built-in provider integrations (P01-P10)
  internal/integrations/<provider>/  one package per provider
```

### Import Rules and Allowed Dependency Graph

The following dependency rules define the allowable imports across internal packages (note that these rules govern internal package dependencies and do not prohibit standard library imports):

1. **Leaf foundational packages**:
   - `internal/domain`, `internal/secret`, `internal/sanitize`, and `internal/buildinfo` must not import any other `internal/` package.
   - `internal/api` may import only `internal/domain`. It must not import any other `internal/` package.

2. **Client packages isolation**:
   - Client packages (`internal/client`, `internal/cli`, `internal/tui`, `internal/desktop`, `internal/agent`) and client binaries (`cmd/hx-desktop`, `cmd/hx-agent`) **MUST NOT** import:
     - `internal/hub/...`
     - `internal/egress`
     - `internal/collector`
     - `internal/integrations/...`

3. **Provider integrations isolation**:
   - Provider packages under `internal/integrations/...` may import only:
     - `internal/collector`
     - `internal/egress`
     - `internal/domain`
     - `internal/secret`
     - `internal/sanitize`
   - Provider packages **MUST NOT** import `internal/hub/...`.

4. **Hub core wiring**:
   - Only `internal/hub/...` wires integrations.
   - `cmd/hx` is the only binary linking hub and client code; the `tui` code path imports only client packages.

## Consequences

- Import boundaries are explicitly defined and decoupled from hub core subsystems.
- Dependency checks verify that separate client binaries (`cmd/hx-desktop`, `cmd/hx-agent`) and client subtrees remain free of hub and integration packages.
- Headless build requirement: `hx` and `hx-agent` builds and tests must not require GUI libraries (WebKitGTK, GTK4, or CGO); this is a project requirement enforced in F02 per [ADR-0005](0005-supported-platforms-and-build-targets.md) (e.g. via build tags such as `//go:build desktop`), not an automatic guarantee of the package import graph alone.

## Verification

Planned for enforcement in Go module layout issue F02 (https://github.com/hndrxc/hx/issues/10) via automated CI checks:
- An automated test will execute `go list -deps` on each binary target (`cmd/hx`, `cmd/hx-desktop`, `cmd/hx-agent`) and package subtree.
- The test parses the resulting dependency graph to verify the required allow/deny import rules across package boundaries.

## References

- [ADR-0002: Hub-Owned Credentials and Read-Only Integrations](0002-hub-owned-credentials-and-read-only-integrations.md)
- [ADR-0003: In-Process Collector Trust Boundary](0003-in-process-collector-trust-boundary.md)
- [ADR-0004: Toolchain and Dependency Selection](0004-toolchain-and-dependency-selection.md)
- [ADR-0005: Supported Platforms and Build Targets](0005-supported-platforms-and-build-targets.md)
- Issue #9: Architecture, threat model and supported-platform decisions: https://github.com/hndrxc/hx/issues/9 (checked 2026-11-06)
- Issue #10 (F02): Go module layout and repository scaffolding: https://github.com/hndrxc/hx/issues/10 (checked 2026-11-06)
