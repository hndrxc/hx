# ADR-0007: Tailnet transport and bootstrap egress
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

The `hx` architecture comprises a centralized monitoring hub (`hx hub`), administrative user clients (`hx` CLI/TUI, `hx-desktop`), and distributed device metric agents (`hx-agent`). Communications between these components must cross varying network topologies (local homelab LANs, home Wi-Fi networks, mobile laptop connections, and cloud networks) without requiring public IP addresses, inbound firewall port-forwarding, or exposure to the public internet.

Tailscale provides an encrypted, authenticated WireGuard mesh overlay network with NAT traversal and MagicDNS capabilities. Integrating the hub with Tailscale allows secure, authenticated point-to-point communication.

However, using Tailscale introduces critical architectural questions:
1. Which Tailscale control planes are supported?
2. Which components embed the Tailscale stack (`tsnet`) versus using host-level daemons?
3. How is the hub node authenticated to the tailnet without persisting high-privilege pre-shared keys?
4. How are client and agent identities verified and bound to incoming requests?
5. How does Tailscale transport isolate egress traffic from general collector permissions?
6. How are public Certificate Transparency leaks and external log exports prevented?

## Decision

We establish the following architectural decisions governing tailnet transport and hub egress:

- **Tailscale SaaS control plane only**: The tailnet control plane is strictly limited to Tailscale's hosted SaaS service (`https://controlplane.tailscale.com`). Self-hosted or alternative control planes (such as Headscale) are explicitly unsupported. The `ControlURL` configuration field is left at its default value; setting or overriding it via `TS_CONTROL_URL` is prohibited and rejected at startup.
- **Embedded tsnet on hub only**:
  - The hub process embeds the `tailscale.com/tsnet` library directly to join the tailnet as a dedicated virtual node named `hx-hub`.
  - Node state and keys are stored in a dedicated directory (`Dir = "<hub state dir>/tsnet"`) configured with strict filesystem permissions (`0700`) owned exclusively by the service user.
  - The hub node advertises a dedicated tag: `AdvertiseTags: []string{"tag:hx-hub"}` (source verified in [`tailscale.com@v1.104.5/tsnet/tsnet.go#L326-L330`](https://github.com/tailscale/tailscale/blob/v1.104.5/tsnet/tsnet.go#L326-L330)).
  - The hub opens zero listening TCP sockets on the host's physical LAN or public interfaces. Its only remote network listener exists within the virtual tsnet interface.
- **External host Tailscale daemon for clients and agents**:
  - Front-end clients (`hx`, `hx-desktop`) and device agents (`hx-agent`) do not embed tsnet. Instead, they rely on the host machine's already installed Tailscale client daemon and dial the hub via its tailnet MagicDNS address (e.g., `hx-hub.<tailnet-domain>.ts.net:443`).
- **Interactive enrollment only (ambient credential guardrails)**:
  - Initial hub tailnet enrollment must be performed interactively by the operator via the standard Tailscale interactive login URL emitted by tsnet (`UserLogf`), which is surfaced across local administrative IPC and the hub startup log.
  - Pre-shared authentication keys (`TS_AUTHKEY`, `TS_AUTH_KEY`), OAuth client secrets (`TS_CLIENT_SECRET`), OAuth client IDs (`TS_CLIENT_ID`), ID tokens (`TS_ID_TOKEN`), and custom audiences (`TS_AUDIENCE`) are prohibited for hub enrollment.
  - In `tailscale.com@v1.104.5/tsnet/tsnet.go` ([lines 769–812](https://github.com/tailscale/tailscale/blob/v1.104.5/tsnet/tsnet.go#L769-L812)), tsnet inspects ambient environment variables for credentials (`TS_AUTHKEY` at L773, `TS_AUTH_KEY` at L776, `TS_CONTROL_URL` at L783, `TS_CLIENT_SECRET` at L790, `TS_CLIENT_ID` at L797, `TS_ID_TOKEN` at L804, `TS_AUDIENCE` at L811). To prevent unintended or unauthorized credential inheritance, the hub startup sequence explicitly checks for the presence of these environment variables and aborts immediately if any of them are set (governed by [Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19)).
- **Remote RPC transport: TLS + mTLS over tsnet (no ListenTLS)**:
  - The remote RPC listener is created via `tsnet.Server.Listen("tcp", ":443")` and wrapped in standard TLS using a server certificate issued by the hub's internal CA.
  - Mandatory client mutual TLS (mTLS) is enforced for all inbound RPC connections using certificates signed by the hub CA ([Issue #18 (S07)](https://github.com/hndrxc/hx/issues/18)).
  - `tsnet.Server.ListenTLS` is explicitly prohibited and MUST NOT be used: Tailscale's automated HTTPS certificate mechanism publishes node and tailnet names to public Certificate Transparency logs (see [Tailscale KB 1153](https://tailscale.com/kb/1153)), which discloses internal infrastructure names to the public, and introduces an external Let's Encrypt trust root.
  - Multi-layered authorization: On every RPC request, stream, and reconnect, the hub calls `LocalClient().WhoIs(ctx, remoteAddr)` to extract the caller's tailnet node identity, user, and tags. The hub asserts that the client certificate identity matches the verified tailnet node and tag. Tailnet connectivity alone does not constitute authorization; mTLS identity, WhoIs binding, and role permissions must all validate successfully.
- **Telemetry upload disabled**:
  - Outbound Tailscale operational log uploading is permanently disabled by calling `envknob.SetNoLogsNoSupport()` prior to starting the tsnet server (which sets `TS_NO_LOGS_NO_SUPPORT=true`, verified in [`tailscale.com@v1.104.5/envknob/envknob.go#L498-L500`](https://github.com/tailscale/tailscale/blob/v1.104.5/envknob/envknob.go#L498-L500)).
  - When active, `TransportOptions.New` in [`tailscale.com@v1.104.5/logpolicy/logpolicy.go#L894-L896`](https://github.com/tailscale/tailscale/blob/v1.104.5/logpolicy/logpolicy.go#L894-L896) returns a `noopPretendSuccessTransport`, completely preventing log transmission to `log.tailscale.com`.
- **Egress distinction and bootstrap allowlist**:
  - Bootstrap and operational egress for the hub process is strictly distinguished from telemetry collector permissions ([Issue #15 (S04)](https://github.com/hndrxc/hx/issues/15)). Egress policy governs telemetry collector HTTP traffic, while the host OS firewall (e.g., nftables in [Issue #43 (O01)](https://github.com/hndrxc/hx/issues/43)) enforces tsnet bootstrap egress.
  - The hub's required network connectivity (per [Tailscale KB 1082](https://tailscale.com/kb/1082)) is restricted to:
    - TCP ports 443 and 80 to `controlplane.tailscale.com` and `login.tailscale.com` (coordination and interactive login).
    - TCP port 443 to Tailscale DERP relay servers.
    - UDP port 3478 to Tailscale STUN servers.
    - UDP to WireGuard peer endpoints (local port 41641 default).
    - Outbound traffic to `log.tailscale.com` is omitted and blocked.
- **Example Tailscale ACL configuration**:
  The following Tailscale ACL policy demonstrates least-privilege network access, restricting access to the hub port exclusively to authorized client and agent tags. Tailnet administrators can define operator groups such as `group:admin` (e.g. containing `operator@example.com`) or rely on Tailscale defaults (`autogroup:admin`):
  ```json
  {
    "groups": {
      "group:admin": ["operator@example.com"]
    },
    "acls": [
      {
        "action": "accept",
        "src": ["tag:hx-client", "tag:hx-agent"],
        "dst": ["tag:hx-hub:443"]
      }
    ],
    "tagOwners": {
      "tag:hx-hub": ["group:admin"],
      "tag:hx-client": ["group:admin"],
      "tag:hx-agent": ["group:admin"]
    }
  }
  ```
  This illustrative tailnet policy requires no broad or overlapping wildcard accepts. Nodes tagged `tag:hx-client` and `tag:hx-agent` can initiate connections to `tag:hx-hub:443`. All other tailnet traffic to the hub is dropped at the WireGuard layer.

## Consequences

### Positive
- Zero public exposure: The hub does not listen on LAN or WAN IP addresses, eliminating public port scans and router port-forwarding.
- Dual-barrier security: WireGuard network access control is paired with application-layer mTLS and `WhoIs` identity binding.
- High privacy: Omits public Certificate Transparency publication and suppresses transmission of telemetry logs to external servers.
- Minimal operational footprint: Only the hub process embeds tsnet; workstations and client devices use existing host Tailscale instances.

### Negative / Trade-offs
- Dependency on Tailscale SaaS: Node coordination and DERP relaying depend on Tailscale's hosted infrastructure availability.
- No vendor support logs: Disabling telemetry uploads prevents Tailscale customer support from inspecting diagnostic connection logs.
- Interactive onboarding: Initial hub deployment requires an operator to view and authorize the interactive login URL.

### Residual Risks
- **Tailscale control plane dependency**: Tailscale Inc. functions as a trusted third party for routing and peer discovery. While end-to-end mTLS and `WhoIs` checks prevent Tailscale from inspecting plaintext data or impersonating nodes with valid mTLS certificates, a Tailscale control plane or service outage may degrade performance or prevent new connection establishment (existing direct WireGuard sessions may persist until rekeying or node changes).
- **DERP relay trust**: Relayed traffic through DERP nodes is protected by WireGuard and TLS encryption, but relay saturation or downtime can degrade performance if direct peer-to-peer UDP paths cannot be negotiated.

## Verification

This decision is planned for verification through:
- **Build feasibility spike**: Demonstrated in [Build Feasibility Spike (2026-11)](../spikes/2026-11-build-feasibility.md) via `cmd/hub`, proving that `tsnet.Server` with `AdvertiseTags` compiles cleanly under `CGO_ENABLED=0` in pure Go.
- **Transport security tests ([Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19))**: Automated test suites verifying:
  - Startup termination when `TS_AUTHKEY` or other prohibited environment variables are present.
  - Successful handshake when presented with a valid hub-CA-signed client certificate.
  - Connection rejection when presented with an invalid or untrusted client certificate.
  - Correlation of client certificate identity against `WhoIs` node and tag metadata.
- **Host packaging and egress verification ([Issue #43 (O01)](https://github.com/hndrxc/hx/issues/43))**: Validation of the Debian systemd service unit, `0700` directory permissions, and host firewall rules enforcing the KB 1082 egress policy.

## References

- Tailscale tsnet package documentation, checked 2026-11-06: https://pkg.go.dev/tailscale.com/tsnet
- Tailscale tsnet.go source at v1.104.5, checked 2026-11-06: https://github.com/tailscale/tailscale/blob/v1.104.5/tsnet/tsnet.go#L326-L330 and https://github.com/tailscale/tailscale/blob/v1.104.5/tsnet/tsnet.go#L769-L812
- Tailscale logpolicy.go source at v1.104.5, checked 2026-11-06: https://github.com/tailscale/tailscale/blob/v1.104.5/logpolicy/logpolicy.go#L894-L896
- Tailscale envknob.go source at v1.104.5, checked 2026-11-06: https://github.com/tailscale/tailscale/blob/v1.104.5/envknob/envknob.go#L498-L500
- Tailscale KB 1082: What network ports does Tailscale require?, checked 2026-11-06: https://tailscale.com/kb/1082
- Tailscale KB 1153: Enabling HTTPS, checked 2026-11-06: https://tailscale.com/kb/1153
- hx Egress Policy and Collector Isolation Issue #15 (S04), checked 2026-11-06: https://github.com/hndrxc/hx/issues/15
- hx Client/Device Enrollment Issue #18 (S07), checked 2026-11-06: https://github.com/hndrxc/hx/issues/18
- hx tsnet Transport and WhoIs Authentication Issue #19 (S08), checked 2026-11-06: https://github.com/hndrxc/hx/issues/19
- hx Debian Systemd Service and Packaging Issue #43 (O01), checked 2026-11-06: https://github.com/hndrxc/hx/issues/43