# Egress Policy

Tracking issue: [Issue #15 (S04)](https://github.com/hndrxc/hx/issues/15)

This document describes the implemented egress policy primitives: an exact-origin allowlist with an HTTP call surface (`Do`) and a raw socket seam (`Dial`). **No live runtime uses them yet**; `hx hub`, `hx tui`, `hx-agent`, and `hx-desktop` still exit `1` with not-implemented errors and open no connections. The package performs no global client replacement and installs nothing into `http.DefaultClient` or `http.DefaultTransport`.

---

## 1. Call Surface

```go
type Destination struct {
    Scheme     string       // http, https, ws, wss, tcp, tls
    Host       string
    Port       uint16
    PrivateIPs []netip.Addr // exact homelab bindings (section 4)
    Trust      *tlstrust.Binding // optional exact-origin private TLS trust
}

type Limits struct {
    Timeout      time.Duration
    MaxBodyBytes int64
}

func New(destinations []Destination, limits Limits) (*Policy, error)
func (*Policy) Do(*http.Request) (*http.Response, error)
func (*Policy) Dial(context.Context, *url.URL) (net.Conn, error)
```

- **Origins are exact.** An origin is the tuple scheme + host + port. There are no wildcards, suffix matches, or CIDR/subnet entries. A request matches only a configured tuple.
- **Schemes:** `http`, `https`, `ws`, `wss`, `tcp`, `tls`. Default ports (`80` for `http`/`ws`, `443` for `https`/`wss`) apply only to HTTP and WebSocket families; `tcp` and `tls` destinations must name a port explicitly.
- **`Do` accepts only `http`/`https`.** **`Dial` accepts only `ws`/`wss`/`tcp`/`tls`.** Using the wrong entry point is denied.
- Every call authorizes the URL against the allowlist first, then resolves, then connects. A denied destination never triggers resolution or a connection.

## 2. Redirects

Cross-origin redirects are **denied outright**; they are not followed and not forwarded to the new origin. A redirect to the same exact origin is subject to the usual authorization and response limits. Callers needing a different origin must issue a new, separately authorized request.

## 3. Response Caps and Dial Deadline

- `Limits.Timeout` bounds the dial: resolution, TCP connect, and the TLS handshake for `https`/`wss`/`tls` all fall inside it. For `Do` it also bounds the overall exchange. Context cancellation or deadline expiry may be returned directly (`context.Canceled`, `context.DeadlineExceeded`).
- **`Dial` lifetime.** The lifetime of the returned stream includes lookup, connect, and TLS, measured from the start of `Dial`. It is capped by the earlier of the caller context deadline and the policy `Timeout`; when it ends the policy automatically closes the socket and further I/O fails with `os.ErrDeadlineExceeded`. Callers may set shorter read/write deadlines (longer ones are clamped to the lifetime) and must `Close` the conn when done. The context governs only establishment: cancelling it after `Dial` returns, when it carried no earlier deadline, does not affect the stream.
- `Do` responses are limited to 64 KiB of response headers and at most 10 redirect hops (same-origin only, section 2). Compression is not transparently handled: there is no automatic gzip decompression, so bodies are returned as sent and `MaxBodyBytes` applies to those bytes.
- `Limits.MaxBodyBytes` caps the response body returned by `Do`. The limit is applied while the body is being read; exceeding it yields `ErrTooLarge` rather than a silently truncated body.
- Per-message and framing limits for WebSocket traffic are **not** handled here (see section 6).

## 4. Exact Homelab Bindings

Destination classes, by resolved address:

- **Hard-denied, no opt-in:** loopback, link-local, unspecified, multicast, and other special-use non-public ranges. `PrivateIPs` cannot enable them.
- **Exact opt-in only:** RFC1918 (`10/8`, `172.16/12`, `192.168/16`), IPv6 ULA (`fc00::/7`), and CGNAT (`100.64/10`). Such an address is permitted only if it is listed in `PrivateIPs` for that exact destination.
- **Public:** permitted without listing. In a mixed answer, public members need not be listed; only the private members are checked against `PrivateIPs`.

An exact private exception authorizes only that listed address for that destination. A resolution that yields a *different* private IP is denied, even if another private IP is listed, and even if the hostname matches.

Synthetic examples (simulated names and addresses only):

```go
[]egress.Destination{
    // Public API, verified public trust.
    {Scheme: "https", Host: "api.example.test", Port: 443},
    // Homelab service pinned to one private address.
    {Scheme: "https", Host: "nas.lab.example.test", Port: 8443,
        PrivateIPs: []netip.Addr{netip.MustParseAddr("10.42.0.10")}},
    // Raw TLS socket bound to two private addresses.
    {Scheme: "tls", Host: "broker.lab.example.test", Port: 9443,
        PrivateIPs: []netip.Addr{
            netip.MustParseAddr("10.42.0.20"),
            netip.MustParseAddr("10.42.0.21")}},
}
```

Listing `10.42.0.10` for `nas.lab.example.test` does not authorize `10.42.0.11`, another port, another scheme, or another hostname.

## 5. Audit-Safe Errors and Caller Logging

Errors from `Do` and from establishing a `Dial` are the sentinels `ErrDenied`, `ErrResolve`, `ErrConnect`, `ErrResponse`, and `ErrTooLarge` (plus direct context errors). They are fixed-text: they do **not** contain hostnames, IP addresses, ports, URLs, resolver output, or wrapped raw causes, so they are safe to hand to audit sinks. Callers must test with `errors.Is`.

TLS certificate verification failures use `ErrCertificate` (also matches `ErrConnect`); private [trust](tls-trust.md) adds fixed approval, store, audit and pin mismatch categories.

Stream I/O on a conn returned by `Dial` is distinct from the primary sentinels. Its errors are redacted to a fixed canonical set: `io.EOF`, `io.ErrUnexpectedEOF`, `os.ErrDeadlineExceeded` (deadline or lifetime expiry), and `net.ErrClosed` (closed socket). Any other I/O failure is reported as `ErrConnect`. All of these are safe to log by category.

Caller rules:

1. Log the sentinel category and the *configured* destination label chosen by the caller, not the request URL, resolved addresses, or `err.Error()` of any underlying transport.
2. Never log request or response headers, bodies, query strings, or URL userinfo.
3. Do not attempt to recover raw causes (e.g., via unwrapping or reflection) for logging.
4. Treat `ErrDenied` as a policy event worth auditing; it is not retriable.

## 6. Boundaries With Other Work

| Concern | Owner | Notes |
| :--- | :--- | :--- |
| WebSocket upgrade, framing, message limits, collection helper limits | [#25](https://github.com/hndrxc/hx/issues/25) | `Dial` returns an authorized raw connection only; it performs no upgrade and enforces no message limits. |
| Public TLS trust | this policy | Standard verified TLS; no verification bypass. |
| Private roots, pinning, private-CA TLS | [#16 (S05)](https://github.com/hndrxc/hx/issues/16), [ADR-0006](../adr/0006-private-tls-trust-without-verification-bypass.md) | `Destination.Trust` applies one [approved binding](tls-trust.md) to the exact HTTPS, WSS or TLS origin. Missing or invalid approved state fails closed; nil explicitly selects system trust. |
| Operational vs bootstrap egress | [ADR-0007](../adr/0007-tailnet-transport-and-bootstrap-egress.md) | tsnet bootstrap is **not** governed by this collector policy; it is isolated separately by host controls per ADR-0007. Distinct operational allowlists must never augment collector scopes: do not add operational or bootstrap destinations to a collector `Policy`, and use separate `Policy` values for separate paths. |
| Cooperative vs enforced controls | [ADR-0003](../adr/0003-in-process-collector-trust-boundary.md) | See section 7. |

## 7. Limitations

- **Cooperative control only.** The policy binds code that calls it. In-process code can use `net` or `net/http` directly; this is not a firewall or sandbox (ADR-0003). OS firewall rules, network namespaces, or process sandboxing are needed for enforcement and are out of scope.
- No runtime currently routes traffic through it; no guarantee exists for any shipped command.
- DNS answers are resolved by the policy at dial time; the exact-binding check applies to those answers. It does not defend a compromised host resolver for public destinations beyond TLS verification.
- WebSocket upgrade, framing and message limits are outside this policy.
- Allowlist is fixed at `New`; there is no dynamic reload.

## 8. Rollback

The package is leaf code with no callers in shipped commands. Rolling back means reverting the egress package and this document and the `SECURITY.md` link; no data, configuration, or runtime state migrates.

## 9. Planned Gate (#21)

A planned gate ([#21](https://github.com/hndrxc/hx/issues/21)) is intended to verify that outbound traffic in application code goes through this policy. It is not implemented or enforced today; until it lands, adherence relies on review.
