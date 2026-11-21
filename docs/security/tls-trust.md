# Private TLS Trust (S05)

Status: implemented as leaf package `internal/egress/tlstrust` ([#16](https://github.com/hndrxc/hx/issues/16), [ADR-0006](../adr/0006-private-tls-trust-without-verification-bypass.md)). **No CLI, hub, or collector runtime is wired to it.** Live wiring and WebSocket helpers belong to [#25](https://github.com/hndrxc/hx/issues/25).

## 1. Model

Private destinations (homelab services, internal CAs, self-signed devices) are trusted only through an **exact binding** of one origin to one operator-approved trust record. Verification is never disabled: standard Go TLS verification of chain, canonical host/IP SAN, and certificate validity runs on every handshake. Approval only decides *which* roots/leaf are acceptable for that origin.

- `Origin{Scheme, Host, Port}`: canonical host, explicit port, scheme `https`, `wss`, or `tls` only. A binding matches exactly one origin (`Binding.Matches`); a different host, port, or scheme never uses it.
- `Candidate{Mode, Certificates, LeafPin}` carries DER certificates only.
  - `private-ca` (`PrivateCA`): the supplied certificates are trust anchors. `LeafPin` is an optional extra SPKI pin on the presented leaf; zero means none.
  - `pinned-leaf` (`PinnedLeaf`): the supplied certificate is an exact self-signed leaf; its pin derives from the leaf (`LeafPin` is ignored).
- `Pin` is a 32-byte SHA-256 SPKI fingerprint.

## 2. Operator Flow

1. **Quarantined discovery.** `Discover(candidate)` computes SPKI fingerprints for supplied certificates. It performs no network I/O, activates nothing, and never opens an unverified connection. Operators import certificate files obtained through a channel they trust. Discovery output is **not** evidence of identity: it only shows what the file contains. It is never fed automatically into approval.
2. **Independent out-of-band comparison.** The operator obtains the expected fingerprints from a separate source (device console, the CA's own records, a second administrator) and compares them with what discovery reported.
3. **Approval.** `Approve(origin, candidate, outOfBand)` requires the out-of-band pins to match the SPKI of **every** supplied trust anchor, in supplied order, and, for `private-ca` with a nonzero `LeafPin`, the leaf pin as a final witness. A fingerprint mismatch fails with `ErrPinMismatch`; wrong counts, zero pins, bad mode, or malformed/invalid certificates fail with `ErrInvalid`. Nothing is stored on failure. `Approve` is only for a first-time origin: on an already configured origin it fails with `ErrInvalid`, and changes go through `BeginRotation`. Hooks run on trusted administrative paths only; no endpoint supplies identity.
4. **Use.** `Store.Bind(origin)` returns an opaque `*Binding`; `Binding.TLSConfig()` yields a `*tls.Config` built from the approved state read for that call. Callers must read it per connection. To use a private origin, explicitly set `egress.Destination.Trust = Store.Bind(origin)`; the binding must match the destination origin exactly. A nil `Trust` explicitly selects normal system-root verification. Binding an unapproved origin is allowed, but handshakes then fail closed with `ErrUnapproved`. No custom context, callback, or verifier is exposed through egress other than this store-approved binding.

## 3. Verification Rules

Every handshake enforces: chain to the approved anchors (or exact leaf), canonical host or IP SAN match, validity period, and (when configured) the SPKI pin, all on the same verified chain. Failures are fail-closed with these categories:

| Error | Meaning |
| :--- | :--- |
| `ErrUnapproved` | No approved record for the origin. |
| `ErrInvalid` | Malformed input, bad mode, bad counts, or an unusable administrative request (for example `Approve` on a configured origin). |
| `ErrPinMismatch` | Out-of-band fingerprint mismatch at approval/rotation, or a presented certificate that does not match the approved pin/leaf at handshake. Handshake mismatches are audited as `PinMismatch`. |
| `ErrStore` | Store unreadable, corrupt, or not securely persisted. |
| `ErrAudit` | The audit hook failed; the guarded change did not occur. |

Wrong chain, SAN, or validity-time failures surface through egress as the fixed `egress.ErrCertificate`. Raw TLS diagnostics (certificate names, chain details, x509 messages) are never exposed to callers. There is **no silent fallback to public trust** and no downgrade to unverified TLS: an approved private origin is never verified against system roots, and an unapproved origin never gets an implicit trust path.

## 4. Rotation and Overlap

`BeginRotation(origin, candidate, outOfBand, overlap)` stages a replacement record next to the active one after the same out-of-band checks as approval. The candidate must keep the active mode and the same optional-leaf-pin presence. Prepare and validate a known-good replacement certificate before starting; there is no operation to abandon or abort a pending rotation.

- `overlap` is bounded by `MaxOverlap = 24h`; larger or non-positive values are `ErrInvalid`. The cutoff is a UTC instant computed from the trusted host clock when the rotation begins and compared with that clock at each handshake, so a wrong or manipulated host clock moves the cutoff.
- During overlap both old and new records are acceptable, each only as a complete pair (its own root and leaf condition on the same chain). At the cutoff, **verification selects the staged record only**; the old one stops being accepted without anyone calling `Replace`. The deadline is enforced in the handshake, not by a timer.
- A pending rotation cannot be extended or chained: `BeginRotation` fails with `ErrInvalid` until `Replace` promotes it.
- `Replace(origin)` explicitly promotes the staged record, either early or after overlap, and is audited as `Replacement`. It is not required for the staged certificate to take over at the cutoff; it finalizes the store state.
- Established streams are unaffected; a new record applies at the next reconnect/handshake.

## 5. Persistence and Audit

- The store is a secure Linux directory (private permissions, owned by the caller, no symlink traversal, atomic writes). `Open` secures and locks the directory and fails with `ErrStore` if it is unsafe; it does not reload or validate all approved state. Each origin's record is read and validated per connection (`TLSConfig`) and per administrative operation, and fails closed with `ErrStore` if unreadable or corrupt.
- **Audit first.** Every administrative action emits an `AuditEvent{At, Origin, Action, Allowed}` (`Approval`, `Rotation`, `Replacement`, `PinMismatch`) through the hook given to `Open`. Authorization events are emitted *before* the change is persisted; if the hook errors, the change is not applied (`ErrAudit`). Rejected administrative requests emit a denied event for the attempted action, and a handshake pin mismatch emits a `PinMismatch` denial after the failure. Events contain no certificate or key material. Public logs must retain opaque identifiers only, never hostnames or origins from the event.

## 6. Recovery and Rollback

- **Bad approval or rotation:** the old record stays active until the cutoff or `Replace`, and a pending rotation cannot be cancelled. Do not edit store records by hand, and do not call `Approve` on an already configured origin. Rollback after finalization (`Replace`, or the cutoff followed by `Replace`) is a fresh `BeginRotation` with the previous known-good certificates, then `Replace` once their out-of-band pins are validated.
- **Corrupt or unsafe store:** affected private origins fail closed (`ErrStore`) until the operator restores the directory from backup or removes it and re-approves each origin. Deleting the store never widens trust.
- **Code rollback:** revert the `tlstrust` package and its docs, but retain the updated audit verifier so events from this package still validate. Nothing in shipped commands depends on the package.

## 7. Limitations

- Discovery cannot verify identity; it only reveals contents. The operator is responsible for the independent comparison.
- A compromised administrator path or host defeats the store; this is a cooperative in-process control ([ADR-0003](../adr/0003-in-process-collector-trust-boundary.md)).
- No live connections, network certificate discovery, CLI import commands, or hub wiring exist yet; those land with their owners ([#25](https://github.com/hndrxc/hx/issues/25) for helpers).
