# ADR-0009: Vault locked-start and unlock
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

The `hx` hub maintains sensitive third-party provider credentials (such as API keys, service account credentials, management tokens, and private certificates) required by telemetry collectors to query homelab appliances and cloud services. To protect these credentials against cold disk extraction, unencrypted backup leaks, and unauthorized host inspection, credentials must be encrypted at rest in a dedicated vault.

Traditional server software often handles encrypted secrets through automated daemon startup flags, environment variables, or auto-unsealing keys. However, ambient passphrases or unsealed encryption keys persisted on local disks defeat the security boundary of at-rest encryption if the host machine or its storage volume is compromised.

We must define an architectural model for the vault lifecycle: how the vault behaves upon service startup, the security boundaries and mechanisms for unlocking it, how locked states affect ongoing service operations, and how key material is protected in process memory.

## Decision

We establish the following architectural invariants for the hub vault lifecycle:

- **Default locked-start posture**: Upon every process startup (including system boots, systemd service restarts, crash recoveries, and upgrades), the hub vault initializes strictly in the `Locked` state. Key material remains in encrypted ciphertext form on disk, and no provider secrets are accessible in process memory.
- **Local TTY-only interactive unlock**:
  - The transition from `Locked` to `Unlocked` is permitted exclusively through the administrative CLI command `hx hub unlock` executed locally on the hub host.
  - Communication between the CLI and the hub daemon takes place over a local administrative Unix domain socket ([Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19)). The socket is restricted to filesystem mode `0660` owned by the service user and administrative group, and access is enforced at the kernel level via `SO_PEERCRED` checks verifying caller UID and GID.
  - The operator must enter the vault passphrase interactively on a controlling terminal (TTY) with echo disabled.
  - Supplying the passphrase via environment variables, command-line arguments, configuration files, standard input pipes (`stdin`), or remote RPC invocations is strictly prohibited and unsupported in Phases 0–3. Remote unlock capabilities are explicitly excluded.
- **Explicit locking and termination cleanup**:
  - An operator can return the vault to the `Locked` state at any time by executing `hx hub lock` over the local administrative IPC socket.
  - Receipt of termination signals (`SIGTERM`, `SIGINT`) or normal process exit transitions the vault state to `Locked`. Plaintext key lifetimes in memory are minimized, and buffers are cleared on transition where feasible.
- **Operational continuity during Locked state (secret-free service)**:
  - Entering the `Locked` state does not halt the hub daemon. The hub remains online and functional for all operations that do not require third-party provider secrets:
    - The tsnet listener remains active and accepts incoming client and agent connections.
    - Device agents continue pushing telemetry observations, which are ingested, validated, and stored normally.
    - Health checks, readiness probes, and status query RPCs/IPCs respond continuously.
    - Internal metrics and secret-free collectors continue running.
  - Telemetry collectors that require provider secrets DO NOT run while the vault is locked. Their monitored resources report an explicit unknown state with the structured reason `vault_locked` (domain representation and protobuf encoding governed by [Issue #22 (D01)](https://github.com/hndrxc/hx/issues/22)).
  - The locked state is exposed through status RPC and IPC responses and recorded in the audit log.
- **Authentication failure handling and auditing**:
  - If an unlock attempt provides an incorrect passphrase or encounters corrupt ciphertext, the attempt is immediately rejected, the vault remains in the `Locked` state, and an authenticated security audit record is written to the audit log ([Issue #14 (S02)](https://github.com/hndrxc/hx/issues/14)).
- **Cryptographic format**:
  - The vault utilizes an authenticated envelope encryption scheme ([Issue #14 (S02)](https://github.com/hndrxc/hx/issues/14)): XChaCha20-Poly1305 data encryption keys wrapped by an Argon2id-derived key. The Argon2id parameters are tuned for memory hardness.
- **Deferral of unattended unlock**:
  - Automated or unattended unlock mechanisms (such as TPM/vTPM sealing or remote secret stores like OpenBao) are explicitly out of scope for Phases 0–3 and deferred as optional future research in [Issue #81 (E03)](https://github.com/hndrxc/hx/issues/81).
- **Go runtime memory limitation recorded**:
  - Pure Go does not offer architectural guarantees that sensitive plaintext key bytes are never copied by the Go runtime, compiler, or garbage collector during stack growth or heap management. Plaintext key lifetime in memory is minimized, but the possibility of runtime copies in memory represents an inherent residual risk.

## Consequences

### Positive
- Strong at-rest protection: Cold storage disks, VM backups, and off-host image snapshots contain only encrypted ciphertexts, protecting provider secrets from offline theft.
- No ambient credential leakage: Eliminating environment variables and CLI flags prevents passphrase leaks into `/proc/<pid>/environ`, process tables (`ps aux`), and shell histories.
- High service resilience: Hub reboots do not cause a total observability blackout; device agents continue pushing metrics and status queries remain operational.
- Deterministic error visibility: Resources requiring locked secrets report clear `vault_locked` reasons instead of misleading timeouts or authentication error alerts.

### Negative / Trade-offs
- Operational latency on host reboot: If the hub host reboots unexpectedly, secret-dependent collector runs halt until an operator connects to the host console and runs `hx hub unlock`.
- Local access requirement: Remote operators cannot unlock the hub through remote client applications or Web UIs; SSH or physical console access to the hub host is required.

### Residual Risks
- **Availability interruption following host reboot**: In the event of an unattended host reboot (e.g., automated kernel update or power outage), secret-requiring provider telemetry is suspended until an operator intervenes. Mitigated by continuous reporting of the `vault_locked` status over authenticated and encrypted client RPC channels.
- **Runtime memory copying in Go**: The Go runtime and garbage collector may duplicate memory slices during execution. Plaintext exposure is minimized, but residual copies in process memory cannot be eliminated with absolute certainty in Go.

## Verification

This decision is planned for verification through:
- **Build feasibility spike**: Demonstrated in [Build Feasibility Spike (2026-11)](../spikes/2026-11-build-feasibility.md) via `cmd/hub`, proving Argon2id key derivation and XChaCha20-Poly1305 encryption in pure Go under `CGO_ENABLED=0`.
- **Vault state machine tests ([Issue #14 (S02)](https://github.com/hndrxc/hx/issues/14))**: Automated tests verifying:
  - Startup initialization in `Locked` state.
  - Successful unlock with valid passphrase and transition to `Unlocked`.
  - Rejection and audit emission on invalid passphrase.
  - Immediate return to `Locked` upon `hx hub lock`.
  - In-memory buffer clearing upon lock transition.
- **Local IPC permission tests ([Issue #19 (S08)](https://github.com/hndrxc/hx/issues/19))**: Validation of Unix domain socket permissions (`0660`) and `SO_PEERCRED` caller credential validation.
- **Domain status tests ([Issue #22 (D01)](https://github.com/hndrxc/hx/issues/22))**: Protobuf schema and handler tests asserting that collectors emit `vault_locked` state for secret-dependent resources while in the locked state.

## References

- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols, checked 2026-11-06: https://datatracker.ietf.org/doc/html/rfc8439
- RFC 9106: Argon2 Password Hashing Function, checked 2026-11-06: https://datatracker.ietf.org/doc/html/rfc9106
- Go `golang.org/x/crypto/chacha20poly1305` package, checked 2026-11-06: https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
- Go `golang.org/x/crypto/argon2` package, checked 2026-11-06: https://pkg.go.dev/golang.org/x/crypto/argon2
- hx Vault Storage and Locked-Start Issue #14 (S02), checked 2026-11-06: https://github.com/hndrxc/hx/issues/14
- hx tsnet Transport and WhoIs Authentication Issue #19 (S08), checked 2026-11-06: https://github.com/hndrxc/hx/issues/19
- hx Domain Models and Protocol Buffer Schemas Issue #22 (D01), checked 2026-11-06: https://github.com/hndrxc/hx/issues/22
- hx Debian Systemd Service and Packaging Issue #43 (O01), checked 2026-11-06: https://github.com/hndrxc/hx/issues/43
- hx Unattended Vault Unlock Research Issue #81 (E03), checked 2026-11-06: https://github.com/hndrxc/hx/issues/81