# ADR-0004: Toolchain and Dependency Selection
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context
hx requires a coherent, modern, and production-grade toolchain for building a headless security hub, cross-platform CLI/TUI tools, lightweight device agents, and an optional desktop frontend. Downstream issues (notably [F02 (#10)](https://github.com/hndrxc/hx/issues/10), [D01 (#22)](https://github.com/hndrxc/hx/issues/22), [D02 (#23)](https://github.com/hndrxc/hx/issues/23), and [C03 (#60)](https://github.com/hndrxc/hx/issues/60)) consume toolchain choices, Go module structures, and dependency selections.

To prevent dependency sprawl, supply-chain risks, and CGO compilation bottlenecks across diverse deployment environments, hx must establish an explicit selection policy, evaluate alternatives, and commit to primary dependencies upfront.

## Decision
We adopt the following dependency selection policy:
1. **Latest Stable Releases Only**: Target the latest stable non-pre-release versions of all core toolchain components and dependencies at the time of implementation.
2. **Version Pinning Policy**: Living version numbers and exact dependency pins are maintained strictly in `go.mod`/`go.sum` and recorded in [docs/compatibility.md](../compatibility.md). ADRs record architectural rationale and policy without duplicating living patch/minor version pins, with the sole exceptions of the Go directive mandate enforced by upstream tsnet and the tsnet source citation in ADR-0007.
3. **CGO-Free Core Binaries**: The hub (`hx hub`), CLI/TUI client (`hx`), and agent (`hx-agent`) must build with `CGO_ENABLED=0` to ensure seamless cross-compilation and static portability. CGO is strictly confined to the desktop client (`hx-desktop`).

### Selected Toolchain & Dependencies

- **Go Toolchain**: Current stable major Go toolchain (go1.27.x). The repository `go.mod` will declare `go 1.27.3` because `tailscale.com` requires it in its module directive, which sets the minimum floor for the entire module. Patch updates follow official Go security and maintenance releases.
- **CLI Framework**: `github.com/spf13/cobra`. Industry-standard CLI command routing, POSIX flag parsing, subcommand composition, and shell autocompletion.
- **TUI Framework**: Charm v2 libraries via modern canonical import paths `charm.land/bubbletea/v2`, `charm.land/lipgloss/v2`, and `charm.land/bubbles/v2` (not legacy `github.com/charmbracelet/...` paths). Bubble Tea v2 provides Elm-architecture terminal state management, Lip Gloss v2 handles declarative terminal styling, and Bubbles v2 supplies reusable interactive components.
- **RPC & Protocol Buffers**: `connectrpc.com/connect/v2` paired with `google.golang.org/protobuf`. Code generation is standardized on `buf` (`github.com/bufbuild/buf`) with `protoc-gen-go` and `protoc-gen-connect-go` at matching version lines (generation layout owned by [D01 (#22)](https://github.com/hndrxc/hx/issues/22)). ConnectRPC v2 eliminates legacy request/response wrapper overhead (`connect.Request[T]`/`connect.Response[T]`), provides native HTTP/2 and gRPC wire compatibility, and simplifies handler signatures. Adopting v2 greenfield avoids future v1-to-v2 migration breaking changes.
- **Embedded Database**: `modernc.org/sqlite` (pure Go, CGO-free). SQLite is our primary storage engine for hub configuration, observation caches, and audit indices. Schema and WAL management are owned by [D02 (#23)](https://github.com/hndrxc/hx/issues/23).
- **Tailnet Overlay Transport**: `tailscale.com/tsnet` embedded exclusively inside the hub service (`hx hub`). Provides authenticated, peer-to-peer WireGuard mesh connectivity, node identity attribution, and mutual TLS integration without exposing listening ports to public interfaces or LANs.
- **Desktop Application Framework**: `github.com/wailsapp/wails/v3` with React and TypeScript frontend ([C03 (#60)](https://github.com/hndrxc/hx/issues/60)). Provides native webview integration with Go backend bindings. CGO is required on Linux (GTK4 + WebKitGTK 6.0).

### Rejected Alternatives

- **CGO SQLite (`github.com/mattn/go-sqlite3`)**: Rejected because compiling C code via CGO breaks effortless cross-compilation for `linux/arm64` and `windows/amd64` and complicates static linking on Debian targets. Pure Go `modernc.org/sqlite` meets all throughput requirements for hx while keeping `CGO_ENABLED=0` across hub and agent.
- **Wasm SQLite (`github.com/ncruces/go-sqlite3`)**: Rejected because bundling a WebAssembly runtime (wazero) adds unnecessary binary overhead, complex runtime abstractions, and execution overhead without tangible benefit over `modernc.org/sqlite`.
- **ConnectRPC v1 (`connectrpc.com/connect`)**: Rejected for greenfield development. While stable, ConnectRPC v2 provides a streamlined API surface; adopting v1 would impose technical debt and an eventual breaking upgrade.
- **Legacy Charm Import Paths (`github.com/charmbracelet/...`)**: Rejected in favor of official `charm.land/...` v2 paths, ensuring long-term compatibility with upstream Charm developments and modular v2 architecture.
## Consequences
- Greenfield code builds against modern APIs (`connect/v2`, Charm v2, Wails v3).
- `go 1.27.3` directive requirement strictly mandates go1.27.x toolchain availability across development workstations and CI runners.
- Hub and agent binaries compile with `CGO_ENABLED=0`, enabling reliable cross-compilation across Linux (amd64, arm64) and Windows (amd64).
- Desktop builds require platform-specific CGO toolchains and native GUI development libraries on Linux (GTK4 and WebKitGTK 6.0).

## Verification
- Dependency module resolution and compatibility verified via `@latest` queries recorded in `/tmp/hx-f01-spike/version-resolution.json` and documented in [docs/spikes/2026-11-build-feasibility.md](../spikes/2026-11-build-feasibility.md).
- Headless compilation with `CGO_ENABLED=0` across targets verified in the build feasibility spike ([docs/spikes/2026-11-build-feasibility.md](../spikes/2026-11-build-feasibility.md)).
- Downstream implementation and enforcement:
  - Module initialization and dependency locking in [F02 (#10)](https://github.com/hndrxc/hx/issues/10).
  - Protobuf generation pipelines in [D01 (#22)](https://github.com/hndrxc/hx/issues/22).
  - SQLite persistence layer and WAL configuration in [D02 (#23)](https://github.com/hndrxc/hx/issues/23).
  - Wails desktop frontend scaffolding and CSP rules in [C03 (#60)](https://github.com/hndrxc/hx/issues/60).

## References
- Go release history and release policy: `https://go.dev/doc/devel/release` (checked 2026-11-06).
- Cobra repository: `https://github.com/spf13/cobra` (checked 2026-11-06).
- Charm v2 documentation and packages: `https://charm.land` (checked 2026-11-06).
- ConnectRPC Go v2 documentation: `https://connectrpc.com/docs/go/` (checked 2026-11-06).
- modernc.org/sqlite package reference: `https://pkg.go.dev/modernc.org/sqlite` (checked 2026-11-06).
- Tailscale tsnet package reference: `https://pkg.go.dev/tailscale.com/tsnet` (checked 2026-11-06).
- Wails v3 repository and documentation: `https://github.com/wailsapp/wails/v3` (checked 2026-11-06).
- Dependency version resolution spike data: `version-resolution.json` (captured 2026-11-06).
