# ADR-0006: Private TLS trust without verification bypass
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

`hx` collects observability metrics and telemetry from on-premises homelab infrastructure, such as iDRAC, ESXi, TrueNAS, Home Assistant, switches, PDUs, and Kopia backup endpoints. In homelab and private enterprise environments, these management interfaces routinely serve self-signed TLS certificates or certificates issued by private internal Certificate Authorities (CAs) rather than publicly trusted WebPKI roots.

Disabling TLS certificate validation lets an on-path attacker impersonate a management endpoint, harvest credentials, or alter telemetry.

`hx` requires a design that accommodates private CAs and self-signed certificates without ever disabling or bypassing TLS certificate verification.

## Decision

We establish the following architectural decisions governing TLS trust and verification:

- **No verification bypass**: `InsecureSkipVerify` is never set anywhere in hx code. Disabling certificate validation or bypassing verification is prohibited. [F04 (#20)](https://github.com/hndrxc/hx/issues/20) owns a scan enforcing this rule; upstream dependencies are reviewed separately.
- **Two explicit endpoint trust modes**: Each monitored endpoint requiring private TLS trust must be explicitly configured during onboarding in one of two supported modes:
  1. `private-ca`: The operator supplies one or more private root/intermediate CA certificates. These certificates populate the endpoint's dedicated `tls.Config.RootCAs` pool. Go's standard library `crypto/tls` validates the presented certificate chain against this custom pool, enforcing standard X.509 validity periods and matching the server's Subject Alternative Names (SANs) against the configured hostname or IP address. An optional SHA-256 Subject Public Key Info (SPKI) fingerprint pin can be supplied as a secondary constraint.
  2. `pinned-leaf`: Designed for appliances utilizing standalone self-signed certificates. The endpoint's self-signed leaf certificate is explicitly approved by the operator after verifying its SHA-256 SPKI fingerprint out-of-band (e.g., via the physical appliance console, out-of-band management interface, or direct display). This approved leaf certificate is installed as the sole entry in `tls.Config.RootCAs`. The connection's `tls.Config.ServerName` is set to an explicit DNS or IP SAN present within that certificate. Standard Go certificate verification checks the certificate's validity dates (rejecting expired or premature certificates) and hostname/SAN matching. Additionally, a `VerifyConnection` callback computes `sha256(peerCert.RawSubjectPublicKeyInfo)` on the presented leaf and requires an exact match against the approved SPKI pin.
- **Strict SAN requirement**: Certificates lacking usable DNS SANs or IP SANs are unsupported. The required remediation is to reissue the device certificate with proper SAN extensions. This requirement is treated as a capability limitation of the target device, never as a justification to bypass hostname validation or disable SAN checks.
- **Strict expiration enforcement**: Expired certificates fail validation immediately and close the connection. There is no "accept expired" or "ignore expiration" configuration.
- **Separation of discovery from approval**: An automated or operator-initiated discovery workflow may retrieve a presented leaf certificate from an endpoint for operator inspection, but that certificate remains unapproved and quarantined. Monitored connections fail closed until the operator explicitly marks the SPKI pin as approved.
- **Fail-closed on pin mismatch**: If an endpoint presents a certificate whose SPKI pin does not match the approved pin, the connection is terminated immediately, collection fails closed, and a security audit event is logged.
- **Bounded rotation overlap**: To enable zero-downtime certificate rotation on monitored appliances, an endpoint configuration may hold a secondary approved SPKI pin during a planned transition period. The maximum overlap window and rotation ergonomics are defined in [Issue #16 (S05)](https://github.com/hndrxc/hx/issues/16).
- **Scope of application**: This trust architecture applies across all shared outbound HTTP and WebSocket client transports utilized by integrations (governed by [Issue #25 (I02)](https://github.com/hndrxc/hx/issues/25)).

## Consequences

### Positive
- Significant reduction of on-path man-in-the-middle (MITM) risks across homelab management endpoints, contingent on operator out-of-band approval diligence and private key security.
- Consistent zero-bypass posture: no special-case exceptions or debug flags allowing `InsecureSkipVerify`.
- Reuses Go's standard library `crypto/tls` verification pipeline without custom forks, custom verification overrides, or fragile monkey-patching.
- Provides cryptographic assurance of endpoint identity through strict out-of-band SPKI fingerprint pinning.

### Negative / Trade-offs
- Monitored devices running legacy firmware with certificates missing SANs cannot be monitored until their certificates are re-generated.
- Device onboarding requires active operator involvement to verify and approve SPKI fingerprints out-of-band.
- Expired appliance certificates cause telemetry collection to halt until renewed, increasing operational maintenance for poorly managed infrastructure.

### Residual Risks
- **Trust-on-first-use without out-of-band verification**: If an operator bypasses the out-of-band verification step and blindly approves a discovered SPKI pin, an attacker already positioned on the network could present an imposter certificate. Mitigated by tooling requiring explicit fingerprint acknowledgment.
- **Legacy device incompatibility**: Certain legacy or proprietary hardware cannot issue SAN-compliant certificates. Mitigated by documenting this gap as an unmonitored device capability failure rather than relaxing security bounds.

## Verification

This decision is planned for verification through:
- **Build feasibility spike**: Demonstrated in [Build Feasibility Spike (2026-11)](../spikes/2026-11-build-feasibility.md) via `cmd/tlspin`, proving that standard library `crypto/tls` in Go enforces hostname SAN matching under `pinned-leaf` mode with `VerifyConnection` without setting `InsecureSkipVerify`. Expiry validation under this mode is planned for verification in [Issue #16 (S05)](https://github.com/hndrxc/hx/issues/16).
- **Static analysis scanner ([Issue #20 (F04)](https://github.com/hndrxc/hx/issues/20))**: Continuous integration gate using static AST inspection to prohibit `InsecureSkipVerify` across the repository.
- **Integration test harness ([Issue #16 (S05)](https://github.com/hndrxc/hx/issues/16), [Issue #25 (I02)](https://github.com/hndrxc/hx/issues/25))**: Unit and integration test suites validating:
  - Acceptance of valid certificates matching custom `private-ca` roots.
  - Acceptance of valid self-signed certificates matching approved `pinned-leaf` SPKI pins.
  - Rejection of certificates with mismatched SPKI pins.
  - Rejection of certificates with mismatched hostnames/SANs.
  - Rejection of expired certificates.
  - Rejection of certificates lacking SANs.

## References

- Go `crypto/tls` package documentation, checked 2026-11-06: https://pkg.go.dev/crypto/tls
- RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile, checked 2026-11-06: https://datatracker.ietf.org/doc/html/rfc5280
- RFC 7469: Public Key Pinning Extension for HTTP, checked 2026-11-06: https://datatracker.ietf.org/doc/html/rfc7469
- hx Custom Trust Roots and Pinning Issue #16 (S05), checked 2026-11-06: https://github.com/hndrxc/hx/issues/16
- hx Static Analysis and Verification Issue #20 (F04), checked 2026-11-06: https://github.com/hndrxc/hx/issues/20
- hx Shared HTTP and WebSocket Transports Issue #25 (I02), checked 2026-11-06: https://github.com/hndrxc/hx/issues/25