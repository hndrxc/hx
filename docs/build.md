# Build and Verification Guide

**Status:** Minimal bootstrap implemented in Issue [F02 (#10)](https://github.com/hndrxc/hx/issues/10). `hx hub`, `hx tui` and bare `hx-agent`/`hx-desktop` exit 1; help/version exit 0; `hx` without arguments prints help and exits 0.

This guide documents the toolchain, build commands, version embedding, build tag policies, dependency status, and package boundary enforcement for the `hx` project.

---

## 1. Toolchain & Dependencies

The repository uses standard Go toolchain mechanics without external build automation:

- **Go Toolchain:** Go `1.27.3` (`go 1.27.3` in `go.mod`).
- **Direct Runtime Dependency:** `github.com/spf13/cobra v1.10.2` (and transitive dependencies including `github.com/spf13/pflag v1.0.9` and `github.com/inconshreveable/mousetrap v1.1.0` locked in `go.mod` / `go.sum`).
- **Minimal Graph Policy:** In accordance with the F02 bootstrap design, optional and future dependencies (Charm v2, ConnectRPC v2, Protobuf, modernc SQLite, tsnet, Wails v3) are **not** present in `go.mod`.
- **Security Requirement on Tailnet Import:** A security floor of `github.com/klauspost/compress >= v1.20.3` is required to mitigate `GO-2026-6865`. Rather than pinning an unused direct dependency in F02, this pin must be added when `tailscale.com` (`tsnet`) is first imported into the module graph.
- **No Empty Stub Packages:** Packages for domain, hub, store, api, egress, or providers are not created as empty placeholders; they land in their owning feature issues.

---

## 2. Binaries and Commands

The repository provides three binary entrypoints under `cmd/`:

1. `cmd/hx`: Unified CLI executable.
   - Command routing via Cobra v1.10.2.
   - Root command displays usage and help; exits 0 when invoked without arguments or with `--help` / `-h`.
   - `--version` flag and `version` subcommand report version information from `internal/buildinfo`.
   - Auto-generated completion command is explicitly disabled.
   - Unknown subcommands and invalid flags return non-zero exit codes.
   - `hx hub`: Subcommand entry for hub service. Runtime execution outputs a semantic not-implemented error to stderr (`Error: hub: not implemented`) and exits 1 without runtime side effects, network listening, or storage operations.
   - `hx tui`: Subcommand entry for terminal interface (wired via `internal/cli`). Runtime execution outputs a semantic not-implemented error to stderr (`Error: tui: not implemented`) and exits 1 without runtime side effects or terminal initialization.

2. `cmd/hx-agent`: Outbound device telemetry agent daemon.
   - Offers `--help` and `--version`.
   - Runtime execution outputs a semantic not-implemented error to stderr (`Error: agent: not implemented`) and exits 1 without telemetry loops, network calls, storage operations, or service registration.
   - Strictly isolated from hub packages and provider integrations.

3. `cmd/hx-desktop`: Graphical desktop application entrypoint.
   - Offers `--help` and `--version`.
   - Default build contains no GUI dependencies and executes headlessly; runtime execution outputs a semantic not-implemented error to stderr (`Error: desktop: not implemented`) and exits 1 without opening windows, requiring display servers, or invoking GUI runtimes.
   - Strictly isolated from hub packages and provider integrations.
---

## 3. Headless & CGO-Free Build Commands

All headless binaries support single-command pure Go compilation (`CGO_ENABLED=0`).

### Linux amd64 (`hx`, `hx-agent`, `hx-desktop`)

```bash
# Build hx CLI
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/hx ./cmd/hx

# Build hx-agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/hx-agent ./cmd/hx-agent

# Build hx-desktop (headless bootstrap entrypoint)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/hx-desktop ./cmd/hx-desktop
```

### Windows amd64 (`hx`, `hx-agent`, `hx-desktop`)

Cross-compiled pure Go PE32+ executables:

```bash
# Cross-compile hx CLI for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o bin/hx.exe ./cmd/hx

# Cross-compile hx-agent for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o bin/hx-agent.exe ./cmd/hx-agent

# Cross-compile hx-desktop (headless bootstrap entrypoint) for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o bin/hx-desktop.exe ./cmd/hx-desktop
```

### Linux arm64 (`hx-agent`)

Cross-compiled pure Go 64-bit ARM ELF executable:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/hx-agent-arm64 ./cmd/hx-agent
```

---

## 4. Version Injection via Linker Flags (`-ldflags`)

Version information defaults to `dev` in `internal/buildinfo.Version`. Build systems override this at link time via `-ldflags`:

```bash
go build -ldflags "-X github.com/hndrxc/hx/internal/buildinfo.Version=v0.1.0-alpha.1" -o bin/hx ./cmd/hx
```

Testing verification:
```bash
./bin/hx --version
# Output: hx version v0.1.0-alpha.1

./bin/hx version
# Output: hx version v0.1.0-alpha.1
```

---

## 5. GUI Isolation and Planned Build Tags

To ensure tests and headless builds run cleanly in environments lacking display servers and native GUI headers:

1. **Current State:** No GUI libraries (GTK4, WebKitGTK, Wails runtime) are imported in the F02 bootstrap. All three binary targets compile with `CGO_ENABLED=0` without native graphical toolchains.
2. **Planned Build Tag:** Future Wails-importing source files in `cmd/hx-desktop` and `internal/desktop` must specify the `desktop` build tag:
   ```go
   //go:build desktop
   ```
3. **Native Desktop Prerequisites (ADR-0005, C03 #60):**
   - **Linux:** Requires `CGO_ENABLED=1`, GTK4 development libraries (`libgtk-4-dev`), and WebKitGTK 6.0 (`libwebkitgtk-6.0-dev`). Legacy GTK3 is rejected.
   - **Windows:** Requires Windows 11 with the Microsoft Edge WebView2 runtime.
4. **Honest Capability Scope:** No functional graphical desktop application is claimed or provided in F02. The desktop entrypoint exists only as a CLI command scaffold returning `not implemented`.

---

## 6. Testing and Architecture Policy Enforcement

All test execution requires zero CGO and zero external services:

```bash
# Run headless unit and architecture tests
CGO_ENABLED=0 go test ./...

# Run static analysis
go vet ./...
```

### Architecture Dependency Rules Test

Package dependency boundaries defined in [ADR-0011](adr/0011-package-layout-and-dependency-direction.md) are enforced by tests under `internal/architecture/`:

- **Leaf Foundations:** `internal/buildinfo` (and future `internal/domain`, `internal/secret`, `internal/sanitize`) must never import any other `internal/` packages.
- **Client Isolation:** Client binaries (`cmd/hx-desktop`, `cmd/hx-agent`) and client package subtrees (`internal/cli`, etc.) must not import `internal/hub/...`, `internal/egress`, `internal/collector`, or `internal/integrations/...` (verified directly and transitively).
- **Composition Exception:** `cmd/hx` may link both client and hub packages, but client front-ends (`internal/cli`) must not link hub packages.
- **Integrations Isolation:** Provider packages may import only collector, egress, domain, secret, and sanitize; they must never import `internal/hub/...`. Only hub wires integrations.
- **Negative Test Cases:** The test suite includes negative assertion cases verifying that hypothetical violations (e.g., client importing hub, leaf package importing client) are reliably detected.

---

## 7. Supported vs. Cross-Compiled Platforms

The platform support tiers listed below describe command-entry build feasibility only (verified pure Go cross-compilation and entrypoint invocation), never production runtime support:

| Target Binary | Platform | Tier | Notes |
| :--- | :--- | :--- | :--- |
| `hx` (hub) | `linux/amd64` (Debian 13) | Build-verified | Pure Go command-entry build feasibility. Hub deployment target is Debian 13 amd64 only. |
| `hx` (CLI / TUI) | `linux/amd64` (Ubuntu 24.04, Debian 13) | Supported (host) / Build-verified | Pure Go command-entry build feasibility. |
| `hx` (CLI / TUI) | `windows/amd64` (Windows 11) | Build-verified | Pure Go cross-compilation (`.exe`). Command-entry build feasibility; native execution unverified in F02. |
| `hx-agent` | `linux/amd64` | Supported (host) / Build-verified | Pure Go command-entry build feasibility. |
| `hx-agent` | `linux/arm64` | Build-verified | Pure Go cross-compilation (aarch64). Command-entry build feasibility; native execution unverified in F02. |
| `hx-agent` | `windows/amd64` (Windows 11) | Build-verified | Pure Go cross-compilation (`.exe`). Command-entry build feasibility; native execution unverified in F02. |
| `hx-desktop` | `linux/amd64`, `windows/amd64` | Not tiered (command-only) | Headless scaffold entrypoint only. Pure Go (`CGO_ENABLED=0`), no GUI implementation or Wails dependency exists, and carries no GUI tier claim. |

Unsupported targets: macOS (all versions), Windows 10, Windows ARM64.

---

## 8. Rollback and Operational Scope

- **No Credentials / Provider Scopes:** F02 introduces no credential handling, tokens, API keys, or provider integrations.
- **No Data Storage:** No database files, caches, or state files are created.
- **Rollback Procedure:** Reverting the git commit cleanly restores repository state without migration reversals, state cleanup, or data loss.

---

## 9. Primary References

- Go Modules Reference: [https://go.dev/ref/mod](https://go.dev/ref/mod) (checked 2026-11-06)
- Go Linker Flags (`-X`): [https://pkg.go.dev/cmd/link](https://pkg.go.dev/cmd/link) (checked 2026-11-06)
- Cobra CLI Framework: [https://github.com/spf13/cobra](https://github.com/spf13/cobra) (v1.10.2, checked 2026-11-06)
- ADR-0004: Toolchain and Dependency Selection: [docs/adr/0004-toolchain-and-dependency-selection.md](adr/0004-toolchain-and-dependency-selection.md)
- ADR-0005: Supported Platforms and Build Targets: [docs/adr/0005-supported-platforms-and-build-targets.md](adr/0005-supported-platforms-and-build-targets.md)
- ADR-0011: Package Layout and Dependency Direction: [docs/adr/0011-package-layout-and-dependency-direction.md](adr/0011-package-layout-and-dependency-direction.md)

## 10. F02 Verification Record — 2026-11-06

Executed on Ubuntu 24.04.5 LTS amd64 with Go 1.27.3, staticcheck 2026.2.2 and govulncheck v1.9.0:

- `go mod tidy -diff` and `go mod verify`: clean and all modules verified.
- `CGO_ENABLED=0 go test ./...`, `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 staticcheck ./...`: passed.
- `CGO_ENABLED=0 govulncheck ./...`: no vulnerabilities found.
- `CGO_ENABLED=1 go test -race ./...`: passed; race instrumentation requires CGO, not GUI libraries.
- CGO-free builds: all three command entry points for Linux amd64 and Windows amd64; agent for Linux arm64. Artifact inspection confirmed static ELF and Windows PE32+ formats.
- Actual Linux process smoke: 27 scenarios passed, covering help/version, unavailable runtimes, unknown flags/commands, extra arguments and linker-injected version output.
- Import-policy smoke: a desktop-tag-only client package importing hub vault code incorrectly passed before the correction and was rejected afterward. The probe was removed; permanent isolated regressions cover tagged-only packages, malformed imports and provider/leaf restrictions.
- Local link targets in all six changed documents resolved. Bootstrap secret-pattern scan found no matches.

Windows, ARM64 and Debian 13 native execution were not performed. No GUI application was exercised. LSP diagnostics were unavailable because no language server is configured; compiler, vet and staticcheck checks passed.
