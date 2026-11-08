# hx

Secure, read-only-first infrastructure monitoring system for hybrid cloud and homelab environments.

---

## Project Status

`hx` is in active early development ([Phase 0: Foundations and security](https://github.com/hndrxc/hx/issues/2)). The project follows a strict issue-driven roadmap detailed in [Issue #1](https://github.com/hndrxc/hx/issues/1).

### Implemented vs. Planned

| Area | Current State (Bootstrap / F02) | Planned Implementation |
| :--- | :--- | :--- |
| **Toolchain & Module** | Go 1.27.3 module bootstrap (`go.mod`, `go.sum`). Locked runtime dependency on `github.com/spf13/cobra v1.10.2`. Zero CGO requirement (`CGO_ENABLED=0`). | Minimal, auditable dependency tree. Pinned dependencies for TUI, RPC, SQLite, and WireGuard added only when owning issues land. |
| **Command Entry Points** | Three headless executable targets under `cmd/`: `cmd/hx`, `cmd/hx-agent`, `cmd/hx-desktop`. | Full subsystem commands and background daemons. |
| **CLI & Help** | `hx` root displays help and exits `0`. Root `--version` flag and `version` subcommand report version information from `internal/buildinfo`. Unknown commands/flags exit non-zero. Auto-completion commands are disabled. | Operational client commands, configuration inspection, and profile management ([C01 / #31](https://github.com/hndrxc/hx/issues/31)). |
| **Subsystem Runtimes** | `hx hub`, `hx tui`, bare `hx-agent`, and bare `hx-desktop` exit `1` with descriptive `not implemented` messages on stderr. No background services, network listeners, file watchers, or IPC channels start. | Hub background service ([H01 / #27](https://github.com/hndrxc/hx/issues/27)), Bubble Tea TUI ([C02 / #34](https://github.com/hndrxc/hx/issues/34)), telemetry agent daemon ([A02 / #62](https://github.com/hndrxc/hx/issues/62)), and Wails desktop application ([C03 / #60](https://github.com/hndrxc/hx/issues/60)). |
| **Architecture Boundaries** | Package layout and internal import allow/deny rules enforced via unit tests (`internal/architecture`). Agent and desktop targets cannot import hub or provider packages. | Strict internal trust boundaries documented in [ADR-0011](docs/adr/0011-package-layout-and-dependency-direction.md). |
| **Vault & Security** | No vault, encryption, or secret handling code is executed in bootstrap. Vault starts locked by design when built. | Encrypted vault storage ([S02 / #14](https://github.com/hndrxc/hx/issues/14)), redacted secrets ([S01 / #12](https://github.com/hndrxc/hx/issues/12)), verifiable audit log ([S03 / #13](https://github.com/hndrxc/hx/issues/13)), and security gates ([F04 / #20](https://github.com/hndrxc/hx/issues/20)). |
| **Network & Transport** | No listening ports, network sockets, or external connections are established. | Embedded Tailscale mesh (`tsnet`) for hub ([ADR-0007](docs/adr/0007-tailnet-transport-and-bootstrap-egress.md)), outbound-only agents ([ADR-0008](docs/adr/0008-outbound-only-device-agents.md)), and strict egress allowlisting ([S04 / #15](https://github.com/hndrxc/hx/issues/15)). |
| **GUI & Display** | `cmd/hx-desktop` builds as a headless, CGO-free stub binary without webview or display dependencies. | Webview-based desktop client isolated behind the `desktop` build tag ([ADR-0005](docs/adr/0005-supported-platforms-and-build-targets.md), [C03 / #60](https://github.com/hndrxc/hx/issues/60)). |

---

## Quickstart (Credential-Free)

The current repository builds with standard Go toolchain tools without credentials, external daemons, database servers, or live provider services. First run, module download, or environment setup may require public network access for Go proxy and checksum verification.

### Prerequisites

- Go `1.27.3` minimum (`go version` $\ge$ `go1.27.3`).
- Git.
- C compiler is **not** required (`CGO_ENABLED=0`).

### Build

Compile all three headless entry points locally:

```bash
# Build the unified CLI
CGO_ENABLED=0 go build -trimpath -o bin/hx ./cmd/hx

# Build the telemetry agent daemon stub
CGO_ENABLED=0 go build -trimpath -o bin/hx-agent ./cmd/hx-agent

# Build the headless desktop client stub
CGO_ENABLED=0 go build -trimpath -o bin/hx-desktop ./cmd/hx-desktop
```

### Try Help and Version

Help and version commands are fully functional and exit `0` without side effects:

```bash
# Display top-level CLI help
./bin/hx --help

# Display version
./bin/hx version
./bin/hx --version

# Agent and desktop stubs also display help and version cleanly
./bin/hx-agent --help
./bin/hx-agent --version

./bin/hx-desktop --help
./bin/hx-desktop --version
```

### Unavailable Runtime Commands

Subsystems that have not yet been implemented exit cleanly with exit code `1` and print a descriptive error message to stderr. They do not start background processes, open network sockets, write state files, or require configuration files:

```bash
$ ./bin/hx hub
Error: hub: not implemented
$ echo $?
1

$ ./bin/hx tui
Error: tui: not implemented
$ echo $?
1

$ ./bin/hx-agent
Error: agent: not implemented
$ echo $?
1

$ ./bin/hx-desktop
Error: desktop: not implemented
$ echo $?
1
```

---

## Documentation Links

- **Roadmap & Tracking:** [Issue #1 (Development roadmap and dependency index)](https://github.com/hndrxc/hx/issues/1)
- **Architecture Documentation:** [docs/architecture/overview.md](docs/architecture/overview.md)
- **Threat Model:** [docs/security/threat-model.md](docs/security/threat-model.md)
- **Build & Verification Guide:** [docs/build.md](docs/build.md)
- **Compatibility & Capability Matrix:** [docs/compatibility.md](docs/compatibility.md)
- **Architecture Decision Records (ADRs):** [docs/adr/README.md](docs/adr/README.md)
- **CI & Ruleset Configuration:** [docs/ci.md](docs/ci.md)
- **Documentation Index:** [docs/README.md](docs/README.md)

---

## Contributing and Security

- **Contributing Guide:** [CONTRIBUTING.md](CONTRIBUTING.md) — Covers branch naming conventions, readiness criteria, required validation checks, PR workflow, and commit standards.
- **Security Policy:** [SECURITY.md](SECURITY.md) — Details current security guarantees, private vulnerability reporting guidelines, and secret handling policies.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
