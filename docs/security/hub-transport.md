# Hub transport: tailnet RPC and local IPC

Scope: [S08 (#19)](https://github.com/hndrxc/hx/issues/19). This is listener
**scaffolding only**. No daemon wiring, no `hx hub` start-up path, no business
RPC service, no provider/collector route, and no live tailnet join ship with
it. Callers supply the handler; the scaffold supplies authentication, limits,
and audit around it. Architecture: [ADR-0007](../adr/0007-tailnet-transport-and-bootstrap-egress.md).
Credentials: [enrollment.md](enrollment.md), [tls-trust.md](tls-trust.md).

## Dependencies

Narrow additions, pinned per [ADR-0004](../adr/0004-toolchain-and-dependency-selection.md)
and recorded in [compatibility.md](../compatibility.md):

| Module | Version | Why | Primary source (checked 2026-11-21) |
|--------|---------|-----|-------------------------------------|
| Go toolchain | 1.27.4 | Floor forced by `tailscale.com@v1.104.7` `go.mod` (`go 1.27.4`); latest stable | `https://go.dev/dl/?mode=json` |
| `tailscale.com` (`tsnet`, `envknob`, `client/local`) | v1.104.7 | Embedded hub node, `Listen`, `WhoIs` | `proxy.golang.org/tailscale.com/@latest` (tag `cbc74fe`) |
| `connectrpc.com/connect/v2` | v2.0.2 | RPC handler/interceptor seam, read limits | `proxy.golang.org/connectrpc.com/connect/v2/@latest` (tag `8f69fe4`) |
| `github.com/Microsoft/go-winio` | v0.6.4 | Named pipe with explicit SDDL (Windows build only) | `proxy.golang.org/github.com/!microsoft/go-winio/@latest` (tag `b900fd8`) |
| `golang.org/x/net` | v0.63.0 | Imported directly by `internal/hub/rpc` (`netutil.LimitListener` tailnet connection cap); also the security floor for `GO-2026-6866` / `GO-2026-6860` (fixed v0.62.0) | `pkg.go.dev/vuln` |
| `github.com/klauspost/compress` | v1.20.5 | Indirect only (via `tailscale.com`); security floor for `GO-2026-6865` (advisory fixed v1.20.2; the earlier repo floor v1.20.3 is also met) | `pkg.go.dev/vuln/GO-2026-6865` |

go-winio is imported only by `//go:build windows` files; Linux builds do not
link it. The hub itself remains Linux-only (compatibility §3); the pipe adapter
exists for Windows local clients and is not a supported hub target.

tsnet v1.104.7 source lines cited by ADR-0007 are unchanged from v1.104.5:
ambient credential reads `tsnet/tsnet.go` L773–L811, `AdvertiseTags` L330,
`Listen` L1321, `ListenTLS` L1458, `envknob.SetNoLogsNoSupport` L499.

## Public API

| Function | Behaviour |
|----------|-----------|
| `rpc.ServeTailnet(ctx, stateDir, rpc.Config, loginURL func(string))` | Refuses start if any ambient tsnet credential/control variable (`TS_AUTHKEY`, `TS_AUTH_KEY`, `TS_CONTROL_URL`, `TS_CLIENT_SECRET`, `TS_CLIENT_ID`, `TS_ID_TOKEN`, `TS_AUDIENCE`) is set; calls `envknob.SetNoLogsNoSupport()`; state in `<stateDir>/tsnet` (`0700`, owned by the service user); hostname `hx-hub`, tag `tag:hx-hub`; listens only via `tsnet.Server.Listen("tcp", ":443")`, capped by `netutil.LimitListener`, with hub-CA TLS requiring client certs. tsnet logs are discarded; only a vetted `https://login.tailscale.com/...` login URL is delegated to the local `loginURL` callback, never logged. |
| `ipc.ListenUnix(path, adminGID, hooks)` | Linux Unix socket, mode `0660`, group `adminGID`; per-connection `SO_PEERCRED` check. |
| `ipc.ListenPipe(name, sid, hooks)` | Windows named pipe; `sid` must equal the service process account SID; protected DACL grants only `sid`; per-connection client SID check. |
| `ipc.DialPipe(ctx, name)` | Windows companion client. Validates `name` as a local pipe name (no remote/UNC server); before writing, checks the pipe's owner SID equals the caller's own token user SID; opens with client security QoS at **Identification** level (not go-winio's anonymous default, and never Impersonation/Delegation, so the server cannot act as the client); writes the one preface byte `0x01` before any framed exchange. |
| `Listener.Serve(ctx, handler)` | `handler` is `func(context.Context, audit.ID, []byte) ([]byte, error)`; the `audit.ID` is the opaque peer actor ID. Serves framed request/response messages; returns when `ctx` ends. |

## Remote request rules

Every remote request, and every stream data operation, must pass all of:

1. TLS 1.3 with a client certificate chaining to the pinned hub CA (no
   ambient roots, no verification bypass — ADR-0006).
2. The certificate's enrolled ID is current (not revoked/renewed-away) in the
   enrollment store, checked per request, never cached per connection.
3. `LocalClient().WhoIs(remoteAddr)` (bounded to 5 s) returns a node whose
   stable node ID, user ID, and role tag match the enrolled record.
4. The RPC procedure is allowed for the record's role (`RoleRead` → read
   procedures, `RoleIngest` → ingest procedures; unknown procedures deny).

Streams are re-authorized immediately at every data boundary (send, header
send, delivered receive; at most 1024 per stream) with no cached grant, and a
bounded idle watchdog (1 s period) re-checks between data operations; a
revoked credential ends the stream. There is no unauthenticated route,
including health.

## Exposure guardrails

- No `net.Listen` on host interfaces for remote RPC; the only remote listener
  is inside tsnet.
- `tsnet.Server.ListenTLS` / `ListenFunnel` / serve config are not used:
  Tailscale HTTPS certificates publish node names to public Certificate
  Transparency logs (Tailscale KB 1153). Hub TLS uses the internal CA only.
- Tailscale log upload is disabled (`SetNoLogsNoSupport`); `log.tailscale.com`
  is also blocked by host egress policy (O01 #43).
- Control plane is the Tailscale SaaS default. Ambient overrides, stored
  non-SaaS preferences and persisted Serve/Funnel configuration are refused.

## Local IPC rules

Common framing (`internal/hub/ipc/server.go`): each message is a 4-byte
big-endian length followed by that many bytes; empty frames and frames over
64 KiB are rejected. At most 16 connections are served simultaneously, each
under a 10 s deadline.

- Unix: socket `0660`, group `adminGID`, in a directory chain owned by root or
  the service user and not writable by others. A peer is admitted when its
  `SO_PEERCRED` UID equals the service UID or its **effective GID** equals
  `adminGID`; supplementary groups are not looked up. A preexisting entry at
  the path is never unlinked — `ListenUnix` fails instead; `Close` unlinks only
  the inode this listener created. Abstract-namespace sockets are not used.
- Windows: the first pipe instance is created with `FILE_CREATE`, so an
  existing (possibly squatted) pipe makes listen fail; remote clients are
  rejected (`FILE_PIPE_REJECT_REMOTE_CLIENTS`). Only the same account SID as
  the service is admitted. The client must first send the single transport
  preface byte `0x01`; the server consumes it, impersonates the client and
  compares the token user SID with `sid`, and only then exchanges framed
  payloads. PIDs are never consulted. The token check is an identity query
  only: `DialPipe` grants Identification-level QoS, enough for the server to
  read the client SID but not to act as the client. Server-side OS token and
  protected-DACL checks remain authoritative regardless of client behaviour:
  a different SID, or an anonymous/unidentifiable client token (e.g. a
  generic go-winio dial with anonymous QoS), is denied. Client-side owner
  check guards against connecting to a squatted pipe owned by another SID.
- Local IPC authenticates the operator (enrollment step 3/5) independently of
  tailnet identity; it carries no remote credential.

## Limits and audit

RPC limits (`internal/hub/rpc`):

| Limit | Value |
|-------|-------|
| Tailnet connections | 128 (`netutil.LimitListener`) |
| Concurrent requests (total) | 64 |
| HTTP/2 streams per connection | 16 |
| Request header bytes | 16 KiB |
| Connect message (read and write) | 256 KiB |
| Inbound request body | 4 MiB |
| Unary lifetime / stream lifetime | 30 s / 5 min |
| WhoIs lookup | 5 s |
| Header read / idle connection | 10 s / 60 s |

Audit (via `internal/hub/audit`): each event stores only the action, outcome,
actor kind, opaque actor/integration/correlation IDs, and time (`audit.Event`).
It does not store a reason, transport, node, or method, and never raw request
data, certificates, tokens, or the login URL. A grant is issued only after its
audit event is recorded; an audit failure fails closed.

Cannot be audited by hx:
- Traffic dropped by tailnet ACLs or WireGuard before reaching tsnet.
- Local connection attempts the kernel refuses by file mode/DACL before
  `accept` returns.

## Residual risks

- WhoIs depends on the local tsnet node's netmap; a stale netmap can
  briefly attribute a reassigned tailnet IP. Mitigation: mTLS must also match.
- Tailscale SaaS control plane remains trusted for node identity (ADR-0007).
- The service user and root are trusted and retain host control; they defeat
  IPC peer checks and can read tsnet state.
- Transitive `tailscale.com` vulnerability findings are tracked in
  compatibility.md and rechecked by `govulncheck`.
- The offline exposure test starts the actual tsnet listener in a network
  namespace with only loopback and verifies the process gains no host TCP
  listener. The mTLS/WhoIs tests use synthetic peers; no test joins a live
  tailnet or verifies a production tailnet ACL.
- The Windows pipe adapter has no native Windows execution evidence here.

Operational opt-out / rollback: the scaffold is not wired into `hx hub`;
reverting the #19 PR removes it. Once wired, stopping the hub closes both
listeners; deleting `<stateDir>/tsnet` and removing the node in the Tailscale
admin console de-registers the hub.

## Verification

Results are recorded in the #19 PR, not here. Commands, from the repository
root:

```sh
bash scripts/check.sh all
go test ./internal/hub/rpc/... ./internal/hub/ipc/... -count=1
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./internal/hub/ipc/...
govulncheck ./...
```
