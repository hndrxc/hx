# Build Feasibility Spike: Toolchain and Platform Feasibility

- **Date**: 2026-11-06
- **Spike Location**: `/tmp/hx-f01-spike` (isolated throwaway scratchpad, completely outside repository)
- **Status**: Complete — All headless, CLI, agent, and desktop build targets verified; pure-Go CGO-free compilation confirmed for hub, CLI, and agent; Wails v3 React/TypeScript desktop builds verified on Linux and Windows; pinned-leaf TLS verified without verification bypass; transitive vulnerability remediated.
- **Security & Isolation Notice**: This spike was executed in an isolated temporary directory. It contains no production secrets, no tailnet enrollment credentials, and no network access tokens. Tailscale `tsnet.Server` was instantiated in memory with configured parameters (`Hostname`, `AdvertiseTags`), but `Start()` was never called; no tailnet connection was opened. SQLite was evaluated solely via in-memory (`:memory:`) databases.

---

## Environment

The build feasibility spike was executed on the developer workstation under the following environment:

| Property | Value | Check Command | Exit Code | CWD |
| :--- | :--- | :--- | :--- | :--- |
| **OS / Distribution** | `Ubuntu 24.04.5 LTS` (linux/amd64) | `lsb_release -ds` | `0` | `/tmp` |
| **Go Toolchain** | `go version go1.27.3 linux/amd64` | `go version` | `0` | `/tmp` |
| **Go Environment** | `GOVERSION=go1.27.3`, `GOOS=linux`, `GOARCH=amd64` | `go env GOVERSION GOOS GOARCH` | `0` | `/tmp` |
| **GTK / WebKitGTK** | `gtk4`: `4.14.5`, `webkitgtk-6.0`: `2.52.6` | `pkg-config --modversion gtk4 webkitgtk-6.0` | `0` | `/tmp` |
| **Node.js** | `v26.13.0` | `node --version` | `0` | `/tmp` |
| **Display Session** | *Unset* (Headless / non-graphical terminal session) | `printenv DISPLAY WAYLAND_DISPLAY` | `1` | `/tmp` |

### Display environment observation
Command `printenv DISPLAY WAYLAND_DISPLAY` returned exit code `1` with empty stdout and stderr. The execution environment lacks an active X11 or Wayland display server. Consequently, desktop graphical applications cannot map windows to a display on this host.

---

## Version resolution

All planned external modules and toolchain components were queried at `@latest` on 2026-11-06 using `go list -m -json <module>@latest`. All queries returned exit code `0`.

**Historical Record Notice**: The version resolution table, timestamps, and module metadata below represent historical point-in-time spike results obtained on 2026-11-06. The single canonical source of truth for living dependency pins, supported versions, and dependency selection policies is [docs/compatibility.md](../compatibility.md).

### Resolved modules table

| Component / Path | Resolved Version | Release Timestamp | Go Directive | License | Plan Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `github.com/spf13/cobra` | `v1.10.2` | `2025-12-03T23:51:15Z` | `1.15` | Apache-2.0 | Matches plan |
| `charm.land/bubbletea/v2` | `v2.1.1` | `2026-10-28T10:18:02Z` | `1.26.0` | MIT | Matches plan |
| `charm.land/lipgloss/v2` | `v2.0.6` | `2026-08-11T17:16:07Z` | `1.25.0` | MIT | Matches plan |
| `charm.land/bubbles/v2` | `v2.2.1` | `2026-08-24T09:13:59Z` | `1.25.0` | MIT | Matches plan |
| `connectrpc.com/connect/v2` | `v2.0.2` | `2026-10-21T22:05:54Z` | `1.26.0` | Apache-2.0 | Matches plan |
| `google.golang.org/protobuf` | `v1.36.12` | `2026-08-10T13:29:45Z` | `1.23` | BSD-3-Clause | Matches plan |
| `github.com/bufbuild/buf` | `v1.75.0` | `2026-10-21T23:42:22Z` | `1.26.7` | Apache-2.0 | Matches plan |
| `modernc.org/sqlite` | `v1.61.1` | `2026-10-31T10:08:39Z` | `1.26.0` | BSD-3-Clause | Matches plan (bundles SQLite 3.54.1) |
| `tailscale.com` | `v1.104.5` | `2026-11-02T21:52:02Z` | `1.27.3` | BSD-3-Clause | Matches plan (forces module `go 1.27.3`) |
| `github.com/wailsapp/wails/v3` | `v3.1.0` | `2026-11-01T11:57:25Z` | `1.26.0` | MIT | Matches plan |

### Transitive resolution details
- **Go Directive Constraint**: `tailscale.com@v1.104.5` declares `go 1.27.3` in its `go.mod`. Downstream module `hx` ([F02 (https://github.com/hndrxc/hx/issues/10)](https://github.com/hndrxc/hx/issues/10)) MUST declare `go 1.27.3` or newer.
- **C-Runtime Transitive Dependency**: `modernc.org/sqlite@v1.61.1` resolves `modernc.org/libc v1.79.0` in the headless build graph (verified via `go list -m modernc.org/libc`). While `modernc.org/libc@latest` resolved to `v1.80.1` (released 2026-11-03T18:46:12Z), the active dependency graph remains pinned to `v1.79.0` by `modernc.org/sqlite@v1.61.1`.
- **Pre-download Command**:
  ```bash
  go mod download -json tailscale.com@v1.104.5 connectrpc.com/connect/v2@v2.0.2 \
    charm.land/bubbletea/v2@v2.1.1 charm.land/bubbles/v2@v2.2.1 charm.land/lipgloss/v2@v2.0.6 \
    modernc.org/sqlite@v1.61.1
  ```
  *Result*: Exit code `0` (cwd `/tmp`).

---

## Headless builds

A standalone throwaway Go module was created manually at `/tmp/hx-f01-spike/headless` with `module hxspike` and `go 1.27.3` declared in `go.mod`. Four prototype programs were implemented to evaluate toolchain compatibility, API patterns, and cross-compilation feasibility without CGO.

### Spike programs and API adaptation

1. **Hub Spike (`cmd/hub/main.go`)**:
   - Evaluates pure-Go SQLite (`modernc.org/sqlite`) via `database/sql` in `:memory:` mode.
   - Instantiates `tsnet.Server` with `Hostname: "hx-spike"` and `AdvertiseTags: []string{"tag:hx-hub"}` without invoking `Start()` (no network activity).
   - **ConnectRPC v2 API Adaptation**: ConnectRPC v2 (`connectrpc.com/connect/v2`) removes Connect v1's `connect.NewUnaryHandler` and `connect.Request[T]`/`Response[T]` wrapper types. The spike adapts to v2's native server API: handlers are registered using `connect.NewServer()`, `connect.Method` with `connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: "/hx.v1.HubService/Ping"}` and `ServerStream.Receive`/`Send` handling, and mounted onto an HTTP multiplexer via `connecthttp.Mount()`.
   - Evaluates cryptographic primitives from `golang.org/x/crypto`: authenticated encryption via `chacha20poly1305.NewX` (XChaCha20-Poly1305) and key derivation via `argon2.IDKey`.

2. **CLI & TUI Spike (`cmd/cli/main.go`)**:
   - Implements Cobra root command `hxspike` with a `version` subcommand.
   - Implements a `tui` subcommand that constructs (without running) a `tea.NewProgram` from `charm.land/bubbletea/v2` with a model styled using `charm.land/lipgloss/v2` and `charm.land/bubbles/v2/spinner`.

3. **Agent Ingest Spike (`cmd/agent/main.go`)**:
   - Constructs a ConnectRPC v2 client using `connecthttp.NewTransport(httpClient, "http://127.0.0.1:1")` and `connect.NewClient(transport)` targeting procedure `/hx.v1.AgentService/Push` without issuing network calls.

4. **TLS Pinned-Leaf Spike (`cmd/tlspin/main.go`)**:
   - Validates [ADR-0006](../adr/0006-private-tls-trust-without-verification-bypass.md) `pinned-leaf` mode strictly within standard library `crypto/tls` without verification bypass (`InsecureSkipVerify` is never set; Go defaults to false).
   - Starts local `httptest.NewTLSServer` (server cert SANs: `127.0.0.1`, `::1`, `example.com`, `*.example.com`).
   - Computes SHA-256 Subject Public Key Info (SPKI) pin: `sha256.Sum256(srvCert.RawSubjectPublicKeyInfo)`.
   - Configures client `tls.Config.RootCAs` containing only `srvCert` and enforces the pin inside `VerifyConnection: func(cs tls.ConnectionState) error`.
   - Tests three sequential cases:
     1. Correct pin with valid SAN (`example.com`) -> Handshake succeeds.
     2. Wrong pin (`0000...`) with valid SAN (`example.com`) -> Handshake rejected by `VerifyConnection`.
     3. Wrong hostname (`wrong.example`) with correct pin -> Handshake rejected during standard hostname verification before `VerifyConnection` is reached.

### Build commands and exit codes

| Step / Command | Environment Variables | Exit Code | CWD | Output Summary |
| :--- | :--- | :--- | :--- | :--- |
| `gofmt -w cmd/hub/main.go cmd/cli/main.go cmd/agent/main.go cmd/tlspin/main.go` | Default | `0` | `/tmp/hx-f01-spike/headless` | Clean |
| `go mod tidy` | Default | `0` | `/tmp/hx-f01-spike/headless` | Downloaded dependencies |
| `go build -o out/ ./cmd/...` | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` | `0` | `/tmp/hx-f01-spike/headless` | Linux amd64 headless binaries compiled |
| `go build -o out/win/ ./cmd/cli ./cmd/agent` | `CGO_ENABLED=0 GOOS=windows GOARCH=amd64` | `0` | `/tmp/hx-f01-spike/headless` | Windows amd64 CLI & agent cross-compiled |
| `go build -o out/arm64/ ./cmd/agent` | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` | `0` | `/tmp/hx-f01-spike/headless` | Linux arm64 agent cross-compiled |
| `go vet ./...` | `CGO_ENABLED=0` | `0` | `/tmp/hx-f01-spike/headless` | Clean vet check across all packages |

### Compiled artifacts inspection

- **Inspection Command**:
  ```bash
  file out/hub out/cli out/agent out/tlspin out/win/cli.exe out/win/agent.exe out/arm64/agent \
    /tmp/hx-f01-spike/desktop/hxdesktop/bin/hxdesktop /tmp/hx-f01-spike/desktop/hxdesktop/hxdesktop.exe
  ```
- **Exit Code**: `0` (cwd `/tmp/hx-f01-spike/headless`)
- **Inspection Findings**:
  - All Linux headless executables (`out/hub`, `out/cli`, `out/agent`, `out/tlspin`): ELF 64-bit LSB x86-64, statically linked.
  - Linux desktop binary (`/tmp/hx-f01-spike/desktop/hxdesktop/bin/hxdesktop`): ELF 64-bit LSB x86-64, dynamically linked (interpreter `/lib64/ld-linux-x86-64.so.2`).
  - Windows executables (`out/win/cli.exe`, `out/win/agent.exe`, `/tmp/hx-f01-spike/desktop/hxdesktop/hxdesktop.exe`): PE32+ executable (console) x86-64, for MS Windows, 16 sections.
  - ARM agent executable (`out/arm64/agent`): ELF 64-bit LSB ARM aarch64, statically linked.

| File | Size (Bytes) | Size (MB) | Format / `file` Utility Inspection |
| :--- | :--- | :--- | :--- |
| `out/hub` | `38,370,438` | ~38.4 MB | ELF 64-bit LSB executable, x86-64, statically linked |
| `out/cli` | `5,846,686` | ~5.8 MB | ELF 64-bit LSB executable, x86-64, statically linked |
| `out/agent` | `12,718,295` | ~12.7 MB | ELF 64-bit LSB executable, x86-64, statically linked |
| `out/tlspin` | `10,087,073` | ~10.1 MB | ELF 64-bit LSB executable, x86-64, statically linked |
| `out/win/cli.exe` | `6,118,400` | ~6.1 MB | PE32+ executable (console) x86-64, for MS Windows, 16 sections |
| `out/win/agent.exe` | `12,872,192` | ~12.9 MB | PE32+ executable (console) x86-64, for MS Windows, 16 sections |
| `out/arm64/agent` | `11,857,629` | ~11.9 MB | ELF 64-bit LSB executable, ARM aarch64, statically linked |
| `/tmp/hx-f01-spike/desktop/hxdesktop/bin/hxdesktop` | `11,067,688` | ~11.1 MB | ELF 64-bit LSB executable, x86-64, dynamically linked |
| `/tmp/hx-f01-spike/desktop/hxdesktop/hxdesktop.exe` | `18,882,560` | ~18.9 MB | PE32+ executable (console) x86-64, for MS Windows, 16 sections |

*Note*: Headless binary sizes reflect unstripped development builds (`-ldflags="-s -w"` was not passed for headless builds).

---

## Runtime smoke

All headless linux/amd64 binaries were executed directly on the workstation from `/tmp/hx-f01-spike/headless`.

| Command | Exit Code | Stdout | Stderr | Verification Result |
| :--- | :--- | :--- | :--- | :--- |
| `./out/hub` | `0` | `3.54.1`<br>`ok` | *(empty)* | Bundled SQLite 3.54.1 verified in-memory; crypto verified; `tsnet` struct initialized without CGO. |
| `./out/cli version` | `0` | `hxspike dev` | *(empty)* | Cobra command tree executes as expected. |
| `./out/cli nosuch` | `1` | *(empty)* | `Error: unknown command "nosuch" for "hxspike"`<br>`Run 'hxspike --help' for usage.` | Invalid subcommand handled gracefully with non-zero exit code. |
| `./out/cli tui` | `0` | `tui program constructed` | *(empty)* | Bubble Tea v2 program, Lip Gloss v2 styles, and Bubbles v2 spinner models constructed successfully. |
| `./out/agent` | `0` | `ok` | *(empty)* | Connect v2 client transport constructed successfully. |
| `./out/tlspin` | `0` | `pinned-leaf ok`<br>`pin mismatch rejected`<br>`hostname rejected` | `http: TLS handshake error ... remote error: tls: bad certificate`<br>`http: TLS handshake error ... read tcp ... use of closed network connection` | ADR 0006 `pinned-leaf` mode verified: valid leaf + SAN succeeds; bad pin rejected by `VerifyConnection`; bad hostname rejected by certificate validation. Zero bypasses. |

### Empirical TLS verification summary
The `tlspin` smoke test empirically verifies that Go's standard library `crypto/tls` supports pinning a self-signed leaf certificate by adding it to `RootCAs` without verification bypass (`InsecureSkipVerify` is never set; Go defaults to false). Hostname and SAN verification remains fully active.

---

## Desktop build

Desktop GUI feasibility was evaluated using Wails v3 (`github.com/wailsapp/wails/v3@v3.1.0`) under `/tmp/hx-f01-spike/desktop`.

### Wails prerequisites inspection (`wails3 doctor`)
- **Command**: `go run github.com/wailsapp/wails/v3/cmd/wails3@v3.1.0 doctor` (exit `0`, cwd `/tmp/hx-f01-spike`)
- **Output Summary**:
  - Wails CLI: `v3.1.0`
  - Platform: `Ubuntu 24.04.5 LTS linux amd64`
  - System Dependencies: `gtk4 4.14.5`, `webkitgtk-6.0 2.52.6`, `npm 12.2.1`, `go1.27.3`, `CGO_ENABLED 1`
  - Legacy Packages: `gtk3` and `webkit2gtk-4.1` absent (not needed; Wails v3 default on modern Linux uses GTK4/WebKitGTK 6.0)
  - Result: `SUCCESS No issues found; Your system is ready for Wails development!`

### Project initialization
- **Template Discovery**: `go run github.com/wailsapp/wails/v3/cmd/wails3@v3.1.0 init -l` (exit `0`)
- **Template Selected**: `react` (Wails v3 official React + TypeScript template)
- **Project Init Command**:
  ```bash
  go run github.com/wailsapp/wails/v3/cmd/wails3@v3.1.0 init -n hxdesktop -t react
  ```
  *Result*: Exit code `0` (cwd `/tmp/hx-f01-spike/desktop`). Created project with React framework, TypeScript language, and interface-based IPC bindings.

### Linux native build
- **Build Command**: `go run github.com/wailsapp/wails/v3/cmd/wails3@v3.1.0 build` (exit `0`, cwd `/tmp/hx-f01-spike/desktop/hxdesktop`)
- **Build Pipeline Output**:
  - Dependency resolution: `task go mod tidy`
  - Frontend installation: `npm install` (added 27 packages)
  - IPC binding generation: `wails3 generate bindings` processed 246 packages, 1 Service, 1 Method
  - Frontend bundle: `npm run build` with Vite v8.3.6 built 46 modules (`dist/index.html` 0.50 kB, `dist/assets/index-DX_rOpxD.js` 172.03 kB)
  - Go native build: `go build -tags production -trimpath -buildvcs=false -ldflags="-w -s" -o bin/hxdesktop`
  - Compiled Linux artifact: `bin/hxdesktop` (size `11,067,688` bytes, ~11.1 MB)

### Linux runtime launch attempt (headless host)
- **Command**: `timeout 10 ./bin/hxdesktop` (cwd `/tmp/hx-f01-spike/desktop/hxdesktop`)
- **Exit Code**: `1`
- **Stderr**:
  ```
  (hxdesktop:3067666): Gtk-WARNING **: 14:10:48.484: Failed to open display
  ```
- **Analysis & Explicit Tier Constraint**:
  The Linux desktop binary compiled cleanly with GTK4 and WebKitGTK 6.0 bindings. However, execution failed immediately because the workstation lacks an active graphical display session (`DISPLAY` and `WAYLAND_DISPLAY` unset).
  In strict accordance with [ADR-0005](../adr/0005-supported-platforms-and-build-targets.md), **no graphical smoke claim is made** for `hx-desktop` on Linux. Its platform status is recorded as **Build-verified**, not `Supported`. Full graphical smoke verification is assigned to [C03 (https://github.com/hndrxc/hx/issues/60)](https://github.com/hndrxc/hx/issues/60).

### Windows cross-compilation feasibility
- **Cross-Build Command**:
  ```bash
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o hxdesktop.exe .
  ```
- **Exit Code**: `0` (cwd `/tmp/hx-f01-spike/desktop/hxdesktop`)
- **Compiled Windows Artifact**:
  - Size: `18,882,560` bytes (~18.9 MB)
  - Inspection: `file hxdesktop.exe` -> `PE32+ executable (console) x86-64, for MS Windows, 16 sections`
- **Result**: Confirms Wails v3 supports cross-compiling Windows client binaries on Linux with `CGO_ENABLED=0` without requiring external cross-compilers or native Windows build infrastructure. Windows execution remains **Build-verified** until tested on physical hardware ([C03 (https://github.com/hndrxc/hx/issues/60)](https://github.com/hndrxc/hx/issues/60)).

---

## Vulnerability scan

Vulnerability scanning was conducted using the latest official Go vulnerability database scanner:
`go run golang.org/x/vuln/cmd/govulncheck@latest ./...`

### Desktop module scan
- **Command**: `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
- **Location**: `/tmp/hx-f01-spike/desktop/hxdesktop`
- **Exit Code**: `0`
- **Output**: `No vulnerabilities found.`

### Headless module initial scan
- **Command**: `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
- **Location**: `/tmp/hx-f01-spike/headless`
- **Exit Code**: `1` (exit status 3)
- **Finding**: 1 active vulnerability detected:
  - **ID**: `GO-2026-6865`
  - **Title**: Panic on two-block frames in `github.com/klauspost/compress`
  - **Details**: `https://pkg.go.dev/vuln/GO-2026-6865`
  - **Affected Version**: `github.com/klauspost/compress@v1.20.0`
  - **Fixed Version**: `github.com/klauspost/compress@v1.20.2`
  - **Import Trace** (`go mod why -m github.com/klauspost/compress`):
    ```
    # github.com/klauspost/compress
    hxspike/cmd/hub
    tailscale.com/tsnet
    tailscale.com/control/controlclient
    tailscale.com/util/zstdframe
    github.com/klauspost/compress/zstd
    ```

### Remediation & patched graph verification
1. **Resolution Query**: `go list -m -json github.com/klauspost/compress@latest` returned `v1.20.3` (released `2026-10-12T09:19:21Z`, Go directive `1.25`).
2. **Remediation**: Added explicit indirect pin `github.com/klauspost/compress v1.20.3 // indirect` to `/tmp/hx-f01-spike/headless/go.mod`.
3. **Graph Update**: Executed `go mod tidy` (exit `0`, downloaded `v1.20.3`).
4. **Re-compilation**: Re-ran all three build commands (`linux/amd64`, `windows/amd64`, `linux/arm64`) and `go vet ./...`. All completed with exit code `0`. Runtime smoke tests re-executed with identical expected outputs.
5. **Re-scan Standard**:
   `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` (exit `0`):
   ```
   === Symbol Results ===

   No vulnerabilities found.

   Your code is affected by 0 vulnerabilities.
   This scan also found 0 vulnerabilities in packages you import and 3
   vulnerabilities in modules you require, but your code doesn't appear to call
   these vulnerabilities.
   ```
6. **Verbose Scan Inspection**:
   `go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...` (exit `0`):
   Scanned 64 modules and `go1.27.3` standard library.
   - **Symbol Results**: 0 vulnerabilities found.
   - **Package Results**: 0 vulnerabilities found.
   - **Module Results (Residual Uncalled Vulnerabilities in Required Modules)**:
     1. `GO-2026-6866`: Check all ancestor namespace transitions when rendering raw text in html in `golang.org/x/net@v0.60.0` (fixed in `v0.62.0`). Transitive module requirement; uncalled by hxspike.
     2. `GO-2026-6860`: Avoid quadratic complexity when coalescing text nodes in html in `golang.org/x/net@v0.60.0` (fixed in `v0.62.0`). Transitive module requirement; uncalled by hxspike.
     3. `GO-2026-5932`: The `golang.org/x/crypto/openpgp` package is unmaintained, unsafe by design, and has known security issues in `golang.org/x/crypto@v0.58.0` (fixed in `v0.58.1-0.20261009181718-2f1f834330b2`). The fix is a pseudo-version / pre-release and is not selected under the project stable-release dependency policy ([ADR-0004](../adr/0004-toolchain-and-dependency-selection.md)). Uncalled by hxspike (neither hx nor tsnet imports or uses `openpgp`).

### Assessment and residual risk
The scanner found no vulnerable code paths reachable in the exercised graph. No production application exists yet; the spike evaluates only prototype entrypoints. The three module-level residual vulnerabilities above remain in transitive required modules.

Downstream owning issues [F02 (https://github.com/hndrxc/hx/issues/10)](https://github.com/hndrxc/hx/issues/10) and [F04 (https://github.com/hndrxc/hx/issues/20)](https://github.com/hndrxc/hx/issues/20) must re-evaluate actual application reachability and enforce vulnerability scanning gates across the full repository build graph.

### Downstream contract for F02
Issue [F02 (https://github.com/hndrxc/hx/issues/10)](https://github.com/hndrxc/hx/issues/10) must explicitly include `github.com/klauspost/compress v1.20.3` in `go.mod` to remediate `GO-2026-6865` in tsnet's zstdframe dependency tree.

---

## Source checks

Source-level audits were performed directly against cached module sources in `$(go env GOMODCACHE)` using specialized grep inspection to verify security properties and API invariants.

### 1. tsnet silent environment variable reads
- **Target File**: `$(go env GOMODCACHE)/tailscale.com@v1.104.5/tsnet/tsnet.go`
- **Pattern**: `os.Getenv`
- **Verified Lines**:
  - Line 773: `if v := os.Getenv("TS_AUTHKEY"); v != "" { ... }`
  - Line 776: `return os.Getenv("TS_AUTH_KEY")`
  - Line 783: `return os.Getenv("TS_CONTROL_URL")`
  - Line 790: `return os.Getenv("TS_CLIENT_SECRET")`
  - Line 797: `return os.Getenv("TS_CLIENT_ID")`
  - Line 804: `return os.Getenv("TS_ID_TOKEN")`
  - Line 811: `return os.Getenv("TS_AUDIENCE")`
- **Conclusion**: Confirms that `tsnet.Server` silently reads all seven environment variables if not overridden. Confirms the [ADR-0007](../adr/0007-tailnet-transport-and-bootstrap-egress.md) requirement: `hx hub` MUST inspect the process environment on startup and refuse to start if any of these variables is set ([S08 (https://github.com/hndrxc/hx/issues/19)](https://github.com/hndrxc/hx/issues/19)).

### 2. tsnet `AdvertiseTags` public field
- **Target File**: `$(go env GOMODCACHE)/tailscale.com@v1.104.5/tsnet/tsnet.go`
- **Pattern**: `AdvertiseTags`
- **Verified Lines**:
  - Line 330: `AdvertiseTags []string` field defined on `type Server struct`.
  - Line 996: `prefs.AdvertiseTags = s.AdvertiseTags` wired into backend IPN options.
- **Conclusion**: Confirms `AdvertiseTags` is an exported configuration field on `tsnet.Server` at `v1.104.5`.

### 3. Tailscale log upload suppression
- **Target Files**:
  - `$(go env GOMODCACHE)/tailscale.com@v1.104.5/logpolicy/logpolicy.go`
  - `$(go env GOMODCACHE)/tailscale.com@v1.104.5/envknob/envknob.go`
- **Pattern**: `NoLogsNoSupport|noopPretendSuccessTransport`
- **Verified Lines**:
  - `logpolicy.go` line 721: `disableLogging := envknob.NoLogsNoSupport() || ...`
  - `logpolicy.go` lines 894–896:
    ```go
    if testenv.InTest() || envknob.NoLogsNoSupport() {
        return noopPretendSuccessTransport{}
    }
    ```
  - `envknob.go` lines 498–500: `envknob.SetNoLogsNoSupport()` sets `TS_NO_LOGS_NO_SUPPORT=true`.
- **Conclusion**: Source audit confirms that setting `TS_NO_LOGS_NO_SUPPORT=true` or calling `envknob.SetNoLogsNoSupport()` replaces log transport with `noopPretendSuccessTransport{}`, completely suppressing remote HTTP connections to `log.tailscale.com`. (Note: source-confirmed; live network testing was not performed because tsnet was never started).

---

## Findings → tier assignments

Based on the empirical evidence gathered during this spike, platform support tiers are assigned according to the criteria established in [ADR-0005](../adr/0005-supported-platforms-and-build-targets.md):

- **Supported**: Binary was compiled and successfully smoke-executed on that OS/architecture.
- **Build-verified**: Binary was compiled for that target OS/architecture (or executed on an equivalent distribution), awaiting native execution testing on that specific platform.
- **Build-unverified**: Target is decided by architecture, but successful compilation has not yet been demonstrated.
- **Unsupported**: Explicitly out of scope; no build or compatibility guarantees.

### Scope of feasibility sample
The **Supported** tier assignments recorded in this spike demonstrate toolchain compilation feasibility and basic prototype execution on the Ubuntu 24.04 amd64 workstation. They represent feasibility samples only and do not signify completed production deliverables, end-to-end device collection, or interactive TUI user operation. Full production applications and interactive execution tests are owned by their respective follow-up issues.

### Platform tier assignments
Canonical platform targets, operating system versions, and CGO settings are maintained in [docs/compatibility.md](../compatibility.md#2-platform-targets--support-tiers). Platform tier assignments derived from this spike are:

- **Supported**:
  - `hx` (CLI / TUI) on Ubuntu 24.04 LTS amd64 (pure Go, CGO-free; CLI `version`, `nosuch`, and TUI program construction verified; production CLI in [C01 (https://github.com/hndrxc/hx/issues/53)](https://github.com/hndrxc/hx/issues/53), TUI in [C02 (https://github.com/hndrxc/hx/issues/54)](https://github.com/hndrxc/hx/issues/54)).
  - `hx-agent` on Ubuntu 24.04 LTS amd64 (pure Go, CGO-free; ConnectRPC v2 client construction verified; production agent in [A01 (https://github.com/hndrxc/hx/issues/61)](https://github.com/hndrxc/hx/issues/61)).
- **Build-verified**:
  - `hx` (hub) on Debian 13 "trixie" amd64 (pure Go, CGO-free; in-memory SQLite 3.54.1, crypto, and tsnet smoke-tested on Ubuntu host; Debian 13 systemd service verification in [O01 (https://github.com/hndrxc/hx/issues/43)](https://github.com/hndrxc/hx/issues/43)).
  - `hx` (CLI / TUI) on Debian 13 "trixie" amd64 (same binary target; runtime validation in [C01 (https://github.com/hndrxc/hx/issues/53)](https://github.com/hndrxc/hx/issues/53) / [C02 (https://github.com/hndrxc/hx/issues/54)](https://github.com/hndrxc/hx/issues/54)).
  - `hx` (CLI / TUI) on Windows 11 amd64 (cross-compiled CGO-free PE32+ executable `out/win/cli.exe`; runtime validation in [C01 (https://github.com/hndrxc/hx/issues/53)](https://github.com/hndrxc/hx/issues/53) / [C02 (https://github.com/hndrxc/hx/issues/54)](https://github.com/hndrxc/hx/issues/54)).
  - `hx-agent` on Debian 13 "trixie" amd64 (same binary target; runtime validation in [A02 (https://github.com/hndrxc/hx/issues/62)](https://github.com/hndrxc/hx/issues/62)).
  - `hx-agent` on Linux arm64 (cross-compiled CGO-free ELF 64-bit ARM aarch64 executable `out/arm64/agent`; hardware validation in [A02 (https://github.com/hndrxc/hx/issues/62)](https://github.com/hndrxc/hx/issues/62)).
  - `hx-agent` on Windows 11 amd64 (cross-compiled CGO-free PE32+ executable `out/win/agent.exe`; runtime validation in [A02 (https://github.com/hndrxc/hx/issues/62)](https://github.com/hndrxc/hx/issues/62)).
  - `hx-desktop` on Linux amd64 (Ubuntu 24.04 and Debian 13, GTK4 + WebKitGTK 6.0; compiled via `wails3 build` to `bin/hxdesktop`; execution exited 1 with display warning in headless session; runtime validation in [C03 (https://github.com/hndrxc/hx/issues/60)](https://github.com/hndrxc/hx/issues/60)).
  - `hx-desktop` on Windows 11 amd64 (cross-compiled CGO-free PE32+ executable `hxdesktop.exe` via `CGO_ENABLED=0 GOOS=windows`; runtime validation in [C03 (https://github.com/hndrxc/hx/issues/60)](https://github.com/hndrxc/hx/issues/60)).
- **Unsupported**:
  - `hx-desktop` on macOS (all versions; out of scope per user decision and [ADR-0005](../adr/0005-supported-platforms-and-build-targets.md)).
  - All binaries on Windows 10 (Microsoft ended Windows 10 support on 2025-10-14; [ADR-0005](../adr/0005-supported-platforms-and-build-targets.md)).
  - All binaries on Windows 11 ARM64 (Go secondary port; out of scope; [ADR-0005](../adr/0005-supported-platforms-and-build-targets.md)).

### Downstream contracts for follow-up issues

1. **Issue [F02 (https://github.com/hndrxc/hx/issues/10)](https://github.com/hndrxc/hx/issues/10)**:
   - Module `go` directive MUST be set to `go 1.27.3` due to `tailscale.com@v1.104.5`.
   - `go.mod` MUST explicitly pin `github.com/klauspost/compress v1.20.3` to remediate `GO-2026-6865`.
   - `modernc.org/libc` remains at `v1.79.0` as resolved by `modernc.org/sqlite@v1.61.1`.
   - GUI isolation: Follow-up issue [F02 (https://github.com/hndrxc/hx/issues/10)](https://github.com/hndrxc/hx/issues/10) selects the isolation mechanism between desktop and headless packages (a `//go:build desktop` build tag on Wails-importing source files is recommended only) so that headless builds (`hx`, `hx-agent`) and headless CI workflows compile with `CGO_ENABLED=0` without requiring GTK/WebKit system libraries.
   - Use ConnectRPC v2 API patterns (`connect.NewServer()`, `connect.Method`, and `connecthttp.Mount()`).

2. **Issue [S05 (https://github.com/hndrxc/hx/issues/16)](https://github.com/hndrxc/hx/issues/16)**:
   - Implement `pinned-leaf` mode strictly within standard library `crypto/tls` using `RootCAs` containing only the approved leaf certificate and SPKI comparison in `VerifyConnection`, maintaining strict hostname verification without verification bypass (`InsecureSkipVerify` is never set).

3. **Issue [S08 (https://github.com/hndrxc/hx/issues/19)](https://github.com/hndrxc/hx/issues/19)**:
   - Enforce environment variable checks at hub startup: refuse to start if any of `TS_AUTHKEY`, `TS_AUTH_KEY`, `TS_CONTROL_URL`, `TS_CLIENT_SECRET`, `TS_CLIENT_ID`, `TS_ID_TOKEN`, or `TS_AUDIENCE` is present in the process environment.
   - Suppress Tailscale remote support logs via `envknob.SetNoLogsNoSupport()`.
