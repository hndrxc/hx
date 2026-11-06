# ADR-0005: Supported Platforms and Build Targets
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context
hx comprises multiple binaries with distinct operational roles:
1. `hx` in hub mode (`hx hub`): central coordinator, vault manager, and API service.
2. `hx` in client mode (CLI and `hx tui`): operator interface for configuration, status, and alerts.
3. `hx-agent`: lightweight background daemon for host telemetry and metrics pushing.
4. `hx-desktop`: operator desktop graphical application embedding a webview.

These binaries run across distinct execution contexts ranging from headless servers and minimal appliances (e.g., Raspberry Pi) to operator workstations (Linux and Windows). We must define explicit platform support tiers, target architectures, build configurations, and headless build isolation rules.

## Decision

### Platform Support Tiers
We establish four rigorous platform support tiers for hx components:
- **Supported**: Built, verified, and smoke-tested on the target OS and CPU architecture with recorded execution evidence in project verification documentation.
- **Build-verified**: Compiled for the target `GOOS`/`GOARCH` without errors (or the resulting binary smoke-tested on a compatible OS family), but not executed on real hardware running that exact operating system.
- **Build-unverified**: An approved architectural target whose build feasibility has not yet been demonstrated in project spikes or CI. Follow-up issues are assigned to implement and verify the build.
- **Unsupported**: Explicitly out of scope, untested, and without design accommodation or support commitments.

> **Feasibility Spike Clarification**: Initial tier assignments in [docs/compatibility.md](../compatibility.md) reflect findings from the preliminary toolchain build feasibility spike ([docs/spikes/2026-11-build-feasibility.md](../spikes/2026-11-build-feasibility.md)), demonstrating compiler feasibility, rather than finished, production-hardened binary implementations. Production binaries remain `Planned` pending their respective feature issues.

### Target Matrix and Scope

1. **Hub (`hx hub`)**:
   - **Target**: Debian 13 "trixie" `linux/amd64` only.
   - **Build Configuration**: `CGO_ENABLED=0` (pure Go), managed as a non-root systemd service with strict sandboxing (`ProtectSystem=strict`) ([O01 (#43)](https://github.com/hndrxc/hx/issues/43)).
   - **Rationale**: Debian 13 amd64 serves as the standard homelab and server deployment baseline. Confining the hub server to Debian 13 amd64 drastically minimizes deployment permutations and security auditing scope.

2. **Operator CLI and TUI (`hx` / `hx tui`)**:
   - **Targets**: `linux/amd64` (Ubuntu 24.04 LTS, Debian 13) and `windows/amd64` (Windows 11).
   - **Build Configuration**: `CGO_ENABLED=0` (pure Go). No graphical libraries required.

3. **Device Agent (`hx-agent`)**:
   - **Targets**: `linux/amd64`, `linux/arm64` (Debian-based including Raspberry Pi OS 64-bit), and `windows/amd64` (Windows 11).
   - **Build Configuration**: `CGO_ENABLED=0` (pure Go) ([A01 (#61)](https://github.com/hndrxc/hx/issues/61), [A02 (#62)](https://github.com/hndrxc/hx/issues/62)). Operates as an outbound-only telemetry pusher without inbound listening sockets.

4. **Desktop GUI Client (`hx-desktop`)**:
   - **Targets**: `linux/amd64` (Ubuntu 24.04+, Debian 13+) and `windows/amd64` (Windows 11).
   - **Frontend Engine**: Wails v3 with React/TypeScript ([C03 (#60)](https://github.com/hndrxc/hx/issues/60)).
   - **Linux Requirements**: CGO enabled (`CGO_ENABLED=1`), GTK4 (`libgtk-4-dev`), and WebKitGTK 6.0 (`libwebkitgtk-6.0-dev`). Legacy GTK3 (`-tags gtk3`) is deprecated and rejected.
   - **Windows Requirements**: Windows 11 with installed Microsoft Edge WebView2 runtime.

### Explicitly Excluded & Unsupported Platforms

- **macOS (Darwin)**: Explicitly **Unsupported**. macOS is not an operational target for the hub, agent, or desktop client. No testing, CI runners, or packaging will be provided for Darwin.
- **Windows 10**: Explicitly **Unsupported**. Microsoft retired Windows 10 from mainstream support on October 14, 2025. Supported Windows targets require Windows 11.
- **Windows on ARM (`windows/arm64`)**: Explicitly **Unsupported**. Considered a secondary port by Go without broad desktop or server hardware deployment in our target environments.

### Headless Build Isolation (F02 Contract)
To prevent GUI dependencies (GTK4, WebKitGTK, X11, Wayland) and CGO requirements from leaking into headless builds or continuous integration checks:
1. `hx` (hub, CLI, TUI) and `hx-agent` builds MUST NEVER require CGO or native GUI header libraries (`libgtk-4-dev`, `libwebkitgtk-6.0-dev`).
2. Standard test execution (`go test ./...`) for all non-desktop packages MUST succeed in headless environments without CGO (`CGO_ENABLED=0`).
3. Follow-up issue [F02 (#10)](https://github.com/hndrxc/hx/issues/10) selects the isolation mechanism between desktop and headless packages (recommended: `//go:build desktop` build tags on Wails-importing source files).

## Consequences
- Single-command pure Go cross-compilation (`CGO_ENABLED=0 GOOS=windows GOARCH=amd64` and `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`) is guaranteed for `hx` and `hx-agent`.
- Operators deploying the hub must run Debian 13 amd64. Other distributions may run the binary due to static compilation, but are not supported.
- Desktop development on Linux requires native GTK4 and WebKitGTK 6.0 development packages.
- Cross-compiling the desktop client for Windows from a Linux host requires WebView2 and CGO/MinGW-w64 toolchains or native Windows compilation. If cross-compilation is infeasible, Windows desktop builds remain `Build-unverified` until verified via native Windows runners in [C03 (#60)](https://github.com/hndrxc/hx/issues/60).

## Verification
- Cross-compilation for headless targets (`linux/amd64`, `linux/arm64`, `windows/amd64`) verified with `CGO_ENABLED=0` in the build feasibility spike ([docs/spikes/2026-11-build-feasibility.md](../spikes/2026-11-build-feasibility.md)).
- Wails v3 Linux compilation and smoke run verified on Ubuntu 24.04 LTS (WebKitGTK 6.0, GTK4) in the build feasibility spike.
- Headless test execution without CGO verified in [F02 (#10)](https://github.com/hndrxc/hx/issues/10).
- Systemd service sandboxing on Debian 13 verified in [O01 (#43)](https://github.com/hndrxc/hx/issues/43).
- Agent service execution on Windows and Linux arm64 verified in [A02 (#62)](https://github.com/hndrxc/hx/issues/62).

## References
- Go Porting Policy and First-Class Ports: `https://go.dev/wiki/PortingPolicy` and `https://go.dev/wiki/MinimumRequirements` (checked 2026-11-06).
- Microsoft Windows 10 End of Support lifecycle notice (October 14, 2025): `https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro` (checked 2026-11-06).
- Debian 13 "trixie" release information: `https://www.debian.org/releases/trixie/` (checked 2026-11-06).
- Wails v3 Linux and Windows prerequisites: `https://v3.wails.io/` (checked 2026-11-06).
- Build feasibility spike evidence: [docs/spikes/2026-11-build-feasibility.md](../spikes/2026-11-build-feasibility.md).
