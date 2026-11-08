# Compatibility & Capability Matrix

Last verified: 2026-11-08

> **Policy Note**: This document serves as the single source of truth for living version numbers, dependency pins, platform support tiers, and system capability mappings. Architectural decisions and policies are recorded in [Architecture Decision Records](adr/README.md) (ADRs), while concrete dependency versions and verification dates are tracked here.
>
> **Status Clarification**: The initial Go module scaffolding and minimal binary command bootstrap is implemented in [F02 (#10)](https://github.com/hndrxc/hx/issues/10). `hx hub`, `hx tui` and bare `hx-agent`/`hx-desktop` exit 1; help/version exit 0; `hx` without arguments prints help and exits 0. The support tiers listed below describe compiler and build feasibility demonstrated during the initial toolchain spike ([docs/spikes/2026-11-build-feasibility.md](spikes/2026-11-build-feasibility.md)) and the headless CGO-free build verification in F02. Production runtime features will be built and verified in their owning follow-up issues.
---

## 1. Toolchain & Dependencies

All dependencies adhere to the selection policy defined in [ADR-0004](adr/0004-toolchain-and-dependency-selection.md): latest stable releases only and zero pre-releases.

In accordance with the F02 bootstrap design and S01 secret values implementation, direct imports and locks in `go.mod` / `go.sum` are intentionally minimal: only Go toolchain `1.27.3`, direct runtime dependencies `github.com/spf13/cobra v1.10.2`, `golang.org/x/term v0.47.0`, and `golang.org/x/sys v0.49.0`, and transitive dependencies (`github.com/spf13/pflag v1.0.9` and `github.com/inconshreveable/mousetrap v1.1.0`) are pinned and verified. Selected future dependencies (Charm v2, ConnectRPC v2, Protobuf, modernc SQLite, tsnet, Wails v3) are documented below as architectural selections to be added by their owning follow-up issues.

| Component | Module / Artifact | Selected Version | Released | Go Directive | License | Primary Source | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Go Toolchain** | `go` | 1.27.3 | 2026-10-19 | 1.27.3 | BSD-3-Clause | [go.dev/dl](https://go.dev/dl/) | Supported major line (go1.27.x). Module directive set to `1.27.3` due to `tailscale.com` requirement. |
| **CLI Framework** | `github.com/spf13/cobra` | v1.10.2 | 2025-12-03 | 1.15 | Apache-2.0 | [github.com/spf13/cobra](https://github.com/spf13/cobra/releases/tag/v1.10.2) | Subcommand routing and POSIX flag handling for `hx`. |
| **Terminal Input** | `golang.org/x/term` | v0.47.0 | 2026-10-09 | 1.26.0 | BSD-3-Clause | [pkg.go.dev/golang.org/x/term@v0.47.0](https://pkg.go.dev/golang.org/x/term@v0.47.0) | Echo-disabled TTY secret input (`internal/secret`). |
| **Low-Level OS** | `golang.org/x/sys` | v0.49.0 | 2026-10-06 | 1.26.0 | BSD-3-Clause | [pkg.go.dev/golang.org/x/sys@v0.49.0](https://pkg.go.dev/golang.org/x/sys@v0.49.0) | Linux memory protection (`internal/secret`) and transitive via x/term. |
| **TUI Core** | `charm.land/bubbletea/v2` | v2.1.1 | 2026-10-28 | 1.26.0 | MIT | [charm.land/bubbletea/v2](https://pkg.go.dev/charm.land/bubbletea/v2@v2.1.1) | Elm-architecture terminal UI runtime for `hx tui`. |
| **TUI Styling** | `charm.land/lipgloss/v2` | v2.0.6 | 2026-08-11 | 1.25.0 | MIT | [charm.land/lipgloss/v2](https://pkg.go.dev/charm.land/lipgloss/v2@v2.0.6) | Declarative terminal styling and layout primitives. |
| **TUI Components** | `charm.land/bubbles/v2` | v2.2.1 | 2026-08-24 | 1.25.0 | MIT | [charm.land/bubbles/v2](https://pkg.go.dev/charm.land/bubbles/v2@v2.2.1) | Interactive terminal components (spinners, viewports, tables). |
| **RPC Framework** | `connectrpc.com/connect/v2` | v2.0.2 | 2026-10-21 | 1.26.0 | Apache-2.0 | [connectrpc.com/connect/v2](https://pkg.go.dev/connectrpc.com/connect/v2@v2.0.2) | Direct handler signatures without request/response wrapper types. |
| **RPC Code Generation** | `protoc-gen-connect-go` | v2.0.2 | 2026-10-21 | 1.26.0 | Apache-2.0 | [connectrpc.com/connect/v2](https://pkg.go.dev/connectrpc.com/connect/v2@v2.0.2) | Connect Go plugin matching `connect/v2` runtime line. |
| **Protobuf Runtime** | `google.golang.org/protobuf` | v1.36.12 | 2026-08-10 | 1.23 | BSD-3-Clause | [google.golang.org/protobuf](https://pkg.go.dev/google.golang.org/protobuf@v1.36.12) | Core Go protocol buffer runtime and reflection. |
| **Protobuf Code Generation** | `protoc-gen-go` | v1.36.12 | 2026-08-10 | 1.23 | BSD-3-Clause | [google.golang.org/protobuf](https://pkg.go.dev/google.golang.org/protobuf@v1.36.12) | Standard Go protocol compiler plugin matching `google.golang.org/protobuf` version. |
| **Protobuf Toolchain** | `github.com/bufbuild/buf` | v1.75.0 | 2026-10-21 | 1.26.7 | Apache-2.0 | [github.com/bufbuild/buf](https://pkg.go.dev/github.com/bufbuild/buf@v1.75.0) | Schema management, linting, breaking change detection, and codegen. |
| **Embedded Database** | `modernc.org/sqlite` | v1.61.1 | 2026-10-31 | 1.26.0 | BSD-3-Clause | [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite@v1.61.1) | Pure Go (CGO-free), bundles SQLite 3.54.1; requires `modernc.org/libc` v1.79.0 in actual graph. |
| **Tailnet Engine** | `tailscale.com` | v1.104.5 | 2026-11-02 | 1.27.3 | BSD-3-Clause | [tailscale.com/tsnet](https://pkg.go.dev/tailscale.com@v1.104.5/tsnet) | Embedded wireguard mesh (`tsnet`) for `hx hub`. Forces module go directive ≥ 1.27.3. Residual vulnerability note: Transitive module-only uncalled findings exist in dependency graph (`GO-2026-6866` / `GO-2026-6860` in `golang.org/x/net` v0.60.0; fixed in v0.62.0, and `GO-2026-5932` `x/crypto/openpgp` in `golang.org/x/crypto` v0.58.0 with fix in pre-release); neither package is imported nor called by hx. Downstream issues F02/F04 rerun scans on the actual application. |
| **Desktop Framework** | `github.com/wailsapp/wails/v3` | v3.1.0 | 2026-11-01 | 1.26.0 | MIT | [github.com/wailsapp/wails/v3](https://pkg.go.dev/github.com/wailsapp/wails/v3@v3.1.0) | Webview bridge for `hx-desktop`. Go scan reports 0 vulnerabilities. Security note: GHSA-2p5f-2gx8-mh8m architectural advisory residual remains for same-origin child frames on Linux WebKitGTK; requires strict CSP (`frame-src 'none'`) and packaged assets. |
| **Compression Override (transitive)** | `github.com/klauspost/compress` | v1.20.3 | 2026-10-12 | 1.25 | BSD-3-Clause | [github.com/klauspost/compress](https://pkg.go.dev/github.com/klauspost/compress@v1.20.3) | Transitive dependency via `tailscale.com` (`tsnet` -> `controlclient` -> `zstdframe`). To avoid unused dependencies, F02 does not directly require this package; this version floor (>= v1.20.3) is required to be pinned when `tailscale.com` is first imported into `go.mod` to resolve `GO-2026-6865`. |

---

## 2. Platform Targets & Support Tiers

Defined in accordance with [ADR-0005](adr/0005-supported-platforms-and-build-targets.md):
- **Supported**: Built, verified, and smoke-tested on the target OS and CPU architecture with recorded execution evidence in project verification documentation.
- **Build-verified**: Compiled for the target `GOOS`/`GOARCH` without errors (or the resulting binary smoke-tested on a compatible OS family), but not executed on real hardware running that exact operating system.
- **Build-unverified**: An approved architectural target whose build feasibility has not yet been demonstrated in project spikes or CI. Follow-up issues are assigned to implement and verify the build.
- **Unsupported**: Explicitly out of scope, untested, and without design accommodation or support commitments.

> **Desktop GUI vs. Bootstrap Command Note**: The `hx-desktop` rows below record historical evidence from the F01 Wails spike ([docs/spikes/2026-11-build-feasibility.md#desktop-build](spikes/2026-11-build-feasibility.md#desktop-build)) only. The default F02 desktop command is a pure Go (`CGO_ENABLED=0`), headless command-only artifact with no GUI dependencies and no GUI tier claim. Full desktop GUI capabilities and tier claims land in [C03 (#60)](https://github.com/hndrxc/hx/issues/60).

| Binary | GOOS / GOARCH | OS Family / Version | CGO | Tier | Evidence | Owning Issue |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `hx` (hub) | `linux/amd64` | Debian 13 "trixie" | `CGO_ENABLED=0` | Build-verified | [docs/spikes/2026-11-build-feasibility.md#headless-builds](spikes/2026-11-build-feasibility.md#headless-builds) (Compiled pure Go statically; smoke run on Ubuntu host, not Debian) | [O01 (#43)](https://github.com/hndrxc/hx/issues/43) |
| `hx` (CLI / TUI) | `linux/amd64` | Ubuntu 24.04 LTS | `CGO_ENABLED=0` | Supported | [docs/spikes/2026-11-build-feasibility.md#runtime-smoke](spikes/2026-11-build-feasibility.md#runtime-smoke) (Spike scope: compiled pure Go, executed `version`, `nosuch`, `tui` construction on Ubuntu workstation) | [F02 (#10)](https://github.com/hndrxc/hx/issues/10) |
| `hx` (CLI / TUI) | `linux/amd64` | Debian 13 "trixie" | `CGO_ENABLED=0` | Build-verified | [docs/spikes/2026-11-build-feasibility.md#headless-builds](spikes/2026-11-build-feasibility.md#headless-builds) (Compiled pure Go statically; awaiting native Debian 13 execution verification) | [F02 (#10)](https://github.com/hndrxc/hx/issues/10) |
| `hx` (CLI / TUI) | `windows/amd64` | Windows 11 | `CGO_ENABLED=0` | Build-verified | [docs/spikes/2026-11-build-feasibility.md#headless-builds](spikes/2026-11-build-feasibility.md#headless-builds) (Cross-compiled pure Go PE32+ executable; awaiting native Windows execution verification) | [F02 (#10)](https://github.com/hndrxc/hx/issues/10) |
| `hx-agent` | `linux/amd64` | Ubuntu 24.04 LTS | `CGO_ENABLED=0` | Supported | [docs/spikes/2026-11-build-feasibility.md#runtime-smoke](spikes/2026-11-build-feasibility.md#runtime-smoke) (Spike scope: compiled pure Go, client construction smoke run succeeded on Ubuntu workstation) | [A01 (#61)](https://github.com/hndrxc/hx/issues/61) |
| `hx-agent` | `linux/amd64` | Debian 13 "trixie" | `CGO_ENABLED=0` | Build-verified | [docs/spikes/2026-11-build-feasibility.md#headless-builds](spikes/2026-11-build-feasibility.md#headless-builds) (Compiled pure Go statically; awaiting native Debian 13 execution verification) | [A01 (#61)](https://github.com/hndrxc/hx/issues/61) |
| `hx-agent` | `linux/arm64` | Debian-based Linux, Raspberry Pi OS 64-bit | `CGO_ENABLED=0` | Build-verified | [docs/spikes/2026-11-build-feasibility.md#headless-builds](spikes/2026-11-build-feasibility.md#headless-builds) (Cross-compiled pure Go ELF 64-bit ARM aarch64 executable; awaiting native ARM64 execution verification) | [A01 (#61)](https://github.com/hndrxc/hx/issues/61) |
| `hx-agent` | `windows/amd64` | Windows 11 | `CGO_ENABLED=0` | Build-verified | [docs/spikes/2026-11-build-feasibility.md#headless-builds](spikes/2026-11-build-feasibility.md#headless-builds) (Cross-compiled pure Go PE32+ executable; awaiting native Windows execution verification) | [A02 (#62)](https://github.com/hndrxc/hx/issues/62) |
| `hx-desktop` | `linux/amd64` | Ubuntu 24.04 LTS | `CGO_ENABLED=1` (GTK4 + WebKitGTK 6.0) | Build-verified | [docs/spikes/2026-11-build-feasibility.md#desktop-build](spikes/2026-11-build-feasibility.md#desktop-build) (Wails v3 build succeeded; binary execution exited 1 with "Failed to open display" in headless session, not graphical smoke tested) | [C03 (#60)](https://github.com/hndrxc/hx/issues/60) |
| `hx-desktop` | `linux/amd64` | Debian 13 "trixie" | `CGO_ENABLED=1` (GTK4 + WebKitGTK 6.0) | Build-verified | [docs/spikes/2026-11-build-feasibility.md#desktop-build](spikes/2026-11-build-feasibility.md#desktop-build) (Awaiting native Debian 13 desktop package install and execution verification) | [C03 (#60)](https://github.com/hndrxc/hx/issues/60) |
| `hx-desktop` | `windows/amd64` | Windows 11 | `CGO_ENABLED=0` / WebView2 | Build-verified | [docs/spikes/2026-11-build-feasibility.md#desktop-build](spikes/2026-11-build-feasibility.md#desktop-build) (`CGO_ENABLED=0 GOOS=windows` cross-build succeeded producing PE32+ executable; awaiting native Windows 11 WebView2 runtime verification) | [C03 (#60)](https://github.com/hndrxc/hx/issues/60) |
| `*` (all) | `darwin/*` (all) | macOS (all versions) | — | Unsupported | None (explicitly out of scope; no packaging or testing planned) | None |
| `*` (all) | `windows/*` | Windows 10 (all editions) | — | Unsupported | None (Microsoft retired Windows 10 support on 2025-10-14) | None |
| `*` (all) | `windows/arm64` | Windows on ARM | — | Unsupported | None (Go secondary port; out of deployment scope) | None |

---

## 3. Platform Capabilities

System capability mappings, storage backends, and isolation boundaries across supported operating systems.

| Capability | Linux | Windows | Owner |
| :--- | :--- | :--- | :--- |
| **Enrollment Credential Storage** | Protected file (mode `0600`) in user config directory. | Windows Credential Manager. | [S07 (#18)](https://github.com/hndrxc/hx/issues/18) |
| **Local Admin IPC** | Unix Domain Socket (`hx.sock`) mode `0660`, restricted by group ownership and peer UID/GID verification (`SO_PEERCRED`). | Explicitly not applicable (hub is Linux-only; #19 named-pipe criterion has no supported target). | [S08 (#19)](https://github.com/hndrxc/hx/issues/19) |
| **Desktop Webview Engine** | WebKitGTK 6.0 (`libwebkitgtk-6.0-dev`) via GTK4. | Microsoft Edge WebView2 runtime. | [C03 (#60)](https://github.com/hndrxc/hx/issues/60) |
| **Desktop Notifications** | Desktop native notification integration (exact APIs deferred to owning issue). | Desktop native notification integration (exact APIs deferred to owning issue). | [C03 (#60)](https://github.com/hndrxc/hx/issues/60) |
| **Agent Service Manager** | `systemd` system or user unit (exact choice deferred to owning issue). | Windows service or scheduled task (exact choice deferred to owning issue). | [A02 (#62)](https://github.com/hndrxc/hx/issues/62) |
| **Tailnet Access** | Hub: embedded `tsnet` listener (in-process).<br>Clients/Agents: Host Tailscale routed network / MagicDNS. | Clients/Agents: Host Tailscale routed network / MagicDNS. | [ADR-0007](adr/0007-tailnet-transport-and-bootstrap-egress.md), [S08 (#19)](https://github.com/hndrxc/hx/issues/19) |

---

## 4. Headless Build Isolation Contract

As decided in [ADR-0005](adr/0005-supported-platforms-and-build-targets.md) and established in [F02 (#10)](https://github.com/hndrxc/hx/issues/10):
1. **Zero CGO for Headless**: Headless binaries (`hx`, `hx hub`, `hx tui`, `hx-agent`, and default `hx-desktop`) and their internal packages MUST build with `CGO_ENABLED=0`.
2. **Zero Native GUI Dependencies for Tests**: `go test ./...` across all non-desktop packages MUST pass on systems without GTK4, WebKitGTK, X11, or Wayland libraries installed.
3. **Isolation Mechanism**: Selected in [F02 (#10)](https://github.com/hndrxc/hx/issues/10): F02 contains zero GUI library dependencies. Future Wails-importing source files in `cmd/hx-desktop` and `internal/desktop` MUST use the `//go:build desktop` build tag so that default builds and tests remain CGO-free and headless.
