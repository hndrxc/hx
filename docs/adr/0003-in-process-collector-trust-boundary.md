# ADR-0003: In-process collector trust boundary
- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

The `hx` hub binary executes collectors for a wide array of homelab and cloud providers. Designing the integration runtime requires deciding whether built-in integrations run within the main hub Go process or are isolated into external processes, sandboxes, WebAssembly runtimes, or separate containers.

Running integrations in-process minimizes operational complexity, deployment footprints, binary distributions, and serialization overhead on resource-constrained homelab hardware (such as single-board computers or low-power servers). However, Go's runtime executes goroutines within a single address space with no memory segmentation, hardware isolation, or kernel boundary separation between distinct packages or goroutines.

We must decide the security boundary and trust posture for built-in collectors, clearly defining what guarantees the architecture makes and what guarantees it explicitly does not make.

## Decision

We establish the following trust boundary and architecture for collector runtimes:

- **In-process execution of built-in collectors**: Built-in collectors are compiled directly as internal Go packages within the `hx hub` binary. They execute inside the hub's single operating system process and address space.
- **No memory or OS privilege isolation claim**: Because built-in collectors execute in-process, they share the hub's heap memory, file descriptors, network sockets, runtime context, and operating system privileges. `hx` explicitly makes NO security isolation claim between built-in collectors or between built-in collectors and the hub core. A compromised or malicious built-in collector has the capability to inspect process memory, read vault data structures, or exhaust host resources.
- **Cooperative manifests and scoped handles**: Collector manifests and scoped handles (e.g., scoped secret handles, restricted egress context) are cooperative engineering controls designed to prevent accidental programming mistakes, configuration errors, and unintentional scope creep. They are not security sandboxes and must not be treated as security boundaries.
- **Strict third-party code policy**: Untrusted, third-party, or user-supplied collector code must NEVER be loaded or executed in-process. All built-in collector packages must be first-party code thoroughly reviewed during the repository code review process.
- **Hard isolation reserved for external plugin tier**: Hard security isolation, sandboxing, and defense against adversarial plugin code are explicitly deferred to the external-process plugin tier ([Issue #79 (E01)](https://github.com/hndrxc/hx/issues/79)). Issue #79 (E01) owns the isolation design and implementation mechanism; no specific protocol (IPC, gRPC, or otherwise) is mandated here.
- **Review gate for built-in integrations**: Adding a new built-in integration requires a formal review of its manifest, dependencies, egress destinations, and credential access patterns in accordance with [Issue #24 (I01)](https://github.com/hndrxc/hx/issues/24).

## Consequences

### Positive
- Greatly simplifies runtime architecture, binary distribution, single-binary deployment (`hx hub`), and cross-platform compilation.
- Eliminates multi-process management, IPC protocol maintenance, serialization latency, and complex child-process supervision in early milestones.
- Eliminates misleading "sandbox" claims by honestly communicating security capabilities to operators and auditors.

### Negative / Trade-offs
- A vulnerability (such as remote code execution via a parsed provider response) in any built-in collector compromises the entire hub process and all resident vault material in memory.
- Third-party extensions cannot be installed dynamically or safely run inside the core binary.
- Relies heavily on static analysis, dependency vetting, egress network filtering ([Issue #15 (S04)](https://github.com/hndrxc/hx/issues/15)), and pre-merge code review to protect the hub core.

## Verification

The boundaries and operational invariants of in-process collectors are planned to be enforced and verified through:
- **Collector runtime contract tests ([Issue #24 (I01)](https://github.com/hndrxc/hx/issues/24))**: Automated tests verify that collector packages implement the unified `Collector` interface, access secrets strictly through scoped runtime handles, and operate cooperatively within context timeouts and cancellation signals.
- **Egress enforcement ([Issue #15 (S04)](https://github.com/hndrxc/hx/issues/15))**: Network egress policy tests verify that collector HTTP clients route strictly through the egress controller and adhere to manifest destination declarations.
- **Dependency and vulnerability scanning ([Issue #20 (F04)](https://github.com/hndrxc/hx/issues/20))**: Continuous vulnerability auditing (`govulncheck`) scans all third-party dependencies used across integration packages to detect vulnerable libraries before release.
## References

- hx Collector Interface and Runtime Issue #24, checked 2026-11-06: https://github.com/hndrxc/hx/issues/24
- hx External Process Plugin Architecture Issue #79, checked 2026-11-06: https://github.com/hndrxc/hx/issues/79
- hx Hub Egress Policy and Firewall Issue #15, checked 2026-11-06: https://github.com/hndrxc/hx/issues/15
