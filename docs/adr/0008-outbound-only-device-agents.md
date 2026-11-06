# ADR-0008: Outbound-only device agents
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

`hx-agent` is a lightweight telemetry collector deployed on workstations, laptops, servers, and edge devices (such as Raspberry Pi SBCs) to collect host-level performance metrics, resource utilization (CPU, memory, disk, network), and hardware status.

Traditional infrastructure monitoring agents often operate as network servers, opening local or network TCP/UDP ports to listen for polling requests from a centralized server or scraping system. Inbound-listening agents introduce severe security and operational challenges:
1. **Network attack surface**: Every listening socket exposed on an endpoint represents an attack vector for remote code execution, unauthenticated buffer overflows, or local privilege escalation.
2. **Firewall and NAT traversal**: Monitored endpoints frequently reside behind corporate NATs, consumer routers, mobile hotspots, or guest Wi-Fi networks. Inbound polling requires complex port forwarding, reverse SSH tunnels, or VPN hole-punching.
3. **Privilege creep**: Agents configured to accept inbound RPC commands are frequently targeted for remote command execution or remote management escalation.

We must define an architectural model for `hx-agent` that minimizes endpoint attack surface while maintaining reliable telemetry delivery across dynamic network topologies.

## Decision

We establish the following architectural invariants for `hx-agent`:

- **Zero inbound listening sockets**: `hx-agent` MUST NEVER open any listening socket of any kind. There is no inbound HTTP server, gRPC/ConnectRPC listener, TCP socket, UDP port, local Unix domain socket, or Windows named pipe. The agent's network stack operates exclusively in client mode for outbound connections.
- **Outbound-only push over host tailnet**: Telemetry data is pushed outbound from the agent to the hub. The agent connects to the hub's tsnet listener over the host operating system's existing Tailscale daemon, dialing the hub's MagicDNS address (`hx-hub.<tailnet-domain>.ts.net:443`).
- **Ingest-only role restriction**:
  - The client mTLS certificate issued to `hx-agent` during enrollment ([Issue #18 (S07)](https://github.com/hndrxc/hx/issues/18)) is strictly constrained to the `ingest` role.
  - The hub's authorization layer ([Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19)) verifies that an agent certificate can only submit observation batches for the exact device ID embedded within and cryptographically bound to its certificate.
  - An agent certificate cannot query hub status, read inventory, inspect metrics from other devices, access audit logs, or enroll new endpoints.
- **Strict credential isolation**: The agent holds zero third-party provider credentials, zero API tokens, and zero hub vault material. The agent holds only its own local enrollment private key, its client certificate, and the hub CA certificate for verifying the hub's identity.
- **Least-privilege execution**: The agent is designed to execute as an unprivileged service or user account without root or administrator privileges, utilizing standard unprivileged OS APIs (via `gopsutil`) where supported. Any metric requiring elevated privileges must be decoupled or documented as an optional system capability rather than requiring the agent daemon to run as root.
- **Bounded buffering, backoff, and jitter**:
  - Telemetry is buffered in a strictly bounded local queue and pushed to the hub in bounded batches.
  - The agent implements backoff with jitter when reconnecting or retrying failed pushes to the hub to prevent thundering-herd reconnect storms during hub restarts or network reconvergence.
  - Queue overflow behavior, buffer persistence options, and metrics drop policies are owned and determined by [Issue #61 (A01)](https://github.com/hndrxc/hx/issues/61) and [Issue #62 (A02)](https://github.com/hndrxc/hx/issues/62).
## Consequences

### Positive
- Reduced network attack surface on monitored machines: `hx-agent` exposes no open listening ports to local or remote networks.
- Mobile connectivity resilience: Outbound-only design allows agents on laptops or roaming devices to push metrics across varying networks without inbound firewall or NAT reconfiguration.
- Strict privilege containment: Compromise of an individual agent device exposes zero secrets belonging to cloud providers, the hub vault, or any other enrolled endpoint.
- Hub load stability: Bounded batches and jittered backoff protect the hub against traffic spikes during system restarts.
### Negative / Trade-offs
- No ad-hoc on-demand polling: The hub cannot prompt an agent to execute an immediate diagnostic probe or trigger real-time actions; all metrics flow asynchronously according to the agent's scheduled cadence.
- Buffer loss on extended disconnects: Long offline periods result in dropped historical metrics once buffer limits are reached.

### Residual Risks
- **Telemetry spoofing on host compromise**: An attacker with root/administrator access on an agent host can extract the agent's enrollment key and submit fabricated telemetry observations. This risk is strictly localized to that single device ID; the hub's authorization layer prevents the compromised credential from impersonating other nodes or accessing stored hub data.
- **Privileged metric gaps**: Running as an unprivileged service may restrict access to certain kernel or hardware sensor statistics on hardened operating systems.

## Verification

This decision is planned for verification through:
- **Zero-socket audit ([Issue #62 (A02)](https://github.com/hndrxc/hx/issues/62))**: Integration test suites inspect active host ports and file descriptors to verify that `hx-agent` opens zero listening sockets across TCP, UDP, Unix domain sockets, and named pipes.
- **Ingest authorization tests ([Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19), [Issue #61 (A01)](https://github.com/hndrxc/hx/issues/61))**: Automated RPC tests asserting that:
  - An agent certificate can submit observations for its own device ID.
  - Submissions attempting to record observations for an alternate device ID fail with permission denied.
  - Any read or administrative RPC attempted with an agent certificate fails with permission denied.
- **Queue and backoff tests ([Issue #61 (A01)](https://github.com/hndrxc/hx/issues/61), [Issue #62 (A02)](https://github.com/hndrxc/hx/issues/62))**: Unit tests verifying backoff with jitter and bounded queue handling upon network disruption.

## References

- gopsutil repository, checked 2026-11-06: https://github.com/shirou/gopsutil
- ConnectRPC Protocol specification, checked 2026-11-06: https://connectrpc.com/docs/protocol
- hx Device Agent Models and Ingest Protocol Issue #61 (A01), checked 2026-11-06: https://github.com/hndrxc/hx/issues/61
- hx Agent Service Lifecycle and Packaging Issue #62 (A02), checked 2026-11-06: https://github.com/hndrxc/hx/issues/62
- hx Client/Device Enrollment Issue #18 (S07), checked 2026-11-06: https://github.com/hndrxc/hx/issues/18
- hx tsnet Transport and WhoIs Authentication Issue #19 (S08), checked 2026-11-06: https://github.com/hndrxc/hx/issues/19