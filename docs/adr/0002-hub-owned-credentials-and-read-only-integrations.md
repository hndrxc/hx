# ADR-0002: Hub-owned credentials and read-only integrations
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

`hx` collects observability telemetry, status metrics, and audit events from homelab infrastructure (iDRAC, ESXi, TrueNAS, Home Assistant, Kopia) and external cloud providers (Supabase, Vercel, GitHub, Cloudflare, Tailscale). Connecting to these platforms requires sensitive credentials, such as API tokens, private keys, service accounts, and session secrets.

If provider credentials are distributed across multiple front-end clients, CLI binaries, device agents, or configuration files, the surface area for credential exfiltration expands dramatically. Furthermore, granting write or mutative privileges to automated collection processes introduces severe blast radiuses in the event of an implementation vulnerability, prompt injection, or SSRF flaw.

We must define an architectural invariant establishing where provider secrets are stored, how they are entered, who can access them, and what operational capabilities integrations are granted.

## Decision

We establish the following architectural principles for credential ownership and integration capabilities:

- **Hub-owned stored provider credentials**: Provider credentials are stored exclusively in the hub vault. At rest, credentials reside only within the encrypted vault data structures. Collectors receive plaintext credentials only via scoped in-memory handles at execution time. Under no circumstances do provider credentials ever exist in or transfer through remote RPC responses, local IPC responses, application logs, test fixtures, or client configuration files.
- **Explicit client/agent credential exception**: Each client (`hx` CLI/TUI, `hx-desktop`) and device agent (`hx-agent`) holds only its own local enrollment private key, its client certificate issued by the hub CA, and the hub CA certificate for verifying the hub's identity (per [Issue #18 (S07)](https://github.com/hndrxc/hx/issues/18)). Clients and agents never hold provider credentials, vault material, or cryptographic keys belonging to any other identity.
- **Local secure prompt entry only**: Provider secrets must be entered strictly through a local secure interactive prompt on the hub host (via standard terminal TTY with echo disabled during local administrative CLI operations). Entering provider secrets via configuration files, environment variables, command-line flags/arguments, or remote RPC is prohibited.
- **Strict read-only integration policy through Phase 3**: All telemetry collectors and third-party integrations are strictly read-only through Phase 3. No integration is permitted to execute write actions, state modifications, resource creations, or destructions against external services or infrastructure.
- **Separately scoped operational capabilities**: Local administration, device metrics ingestion, outbound notification delivery (ntfy on the tailnet), and backup transport are distinct, separately scoped operational permissions. None of these operational capabilities grant or imply any provider write authority.
- **Phase 4 write barrier**: Any future automated or operator-directed write capabilities (remediation, power cycling, configuration changes) are deferred to Phase 4 and must cross an isolated execution partition protected by explicit FIDO2 WebAuthn operator authorization (governed by [Issue #72 (X01)](https://github.com/hndrxc/hx/issues/72) and [Issue #73 (X02)](https://github.com/hndrxc/hx/issues/73)).

## Consequences

### Positive
- Substantially reduces credential exposure: compromising a desktop client, device agent, or network stream exposes no provider credentials because clients and agents hold only their own enrollment material.
- Limits operational blast radius: read-only collector policy ensures telemetry collection compromises cannot issue mutating API requests, though provider privileges are ultimately bounded by the provider's true privilege floor (see [ADR-0010](0010-provider-permission-gaps.md)) and in-process execution risks remain (see [ADR-0003](0003-in-process-collector-trust-boundary.md)).
- Reduces accidental credential leakage into shell histories, process listings (`/proc`), and world-readable configuration files by requiring interactive TTY entry.
- Provides a clean separation of concerns: clients consume sanitized domain models from the hub rather than interacting directly with external APIs.

### Negative / Trade-offs
- Operators cannot configure provider credentials from remote client interfaces; credentials must be provisioned directly on the hub host via local terminal access.
- Providers lacking granular read-only scopes or separate audit roles may expose broader data if an integration is compromised; true privilege floors vary by provider ([ADR-0010](0010-provider-permission-gaps.md)).
- In-process collectors execute in the hub memory space, meaning runtime compromise of a collector could expose in-memory secrets across integrations ([ADR-0003](0003-in-process-collector-trust-boundary.md)).
- Requires robust local IPC mechanisms ([Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19)) on the hub host for administrative vault commands.
## Verification

This architectural invariant is planned to be enforced and verified through:
- **Vault security tests ([Issue #14 (S02)](https://github.com/hndrxc/hx/issues/14))**: Automated tests verify that stored provider secrets are encrypted with XChaCha20-Poly1305 under Argon2id wrapping keys and cannot be serialized or exported via external interfaces.
- **Client credential boundaries ([Issue #18 (S07)](https://github.com/hndrxc/hx/issues/18))**: Enrollment integration tests verify that client credential storage contains only client mTLS certificates/keys and hub CA roots.
- **RPC contract tests ([Issue #22 (D01)](https://github.com/hndrxc/hx/issues/22))**: Protocol buffer schemas and RPC handler tests assert that no RPC response message definition contains provider tokens, secrets, or raw credentials.
- **Static code analysis ([Issue #20 (F04)](https://github.com/hndrxc/hx/issues/20))**: Linters and import graph analysis ensure client and agent packages cannot import the hub vault or provider secret management packages.
## References

- hx Vault Storage and Locked-Start Issue #14, checked 2026-11-06: https://github.com/hndrxc/hx/issues/14
- hx Client/Device Enrollment Issue #18, checked 2026-11-06: https://github.com/hndrxc/hx/issues/18
- hx Provider Permission Floors ADR-0010, checked 2026-11-06: 0010-provider-permission-gaps.md
- hx In-Process Collector Trust Boundary ADR-0003, checked 2026-11-06: 0003-in-process-collector-trust-boundary.md
