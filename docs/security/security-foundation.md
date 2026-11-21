# Security Foundation Gate (S09)

**Status:** Gate for Issue [S09 (#21)](https://github.com/hndrxc/hx/issues/21), which merges only after [S08 (#19)](https://github.com/hndrxc/hx/issues/19). This document describes a fixture-only test gate; its code is test source only. It records no run results, grants no approval, and makes no audit, compliance, or regulatory claim. No live tailnet or live provider is used. Reviewer sign-off and run evidence belong on the #21 pull request, not in this document.

---

## 1. What the Gate Runs

Check name: `security-foundation` in `.github/workflows/security.yml` (`ubuntu-24.04`, pinned `actions/checkout` and `actions/setup-go` already used by the other security jobs, Go `1.27.4`, read-only `GITHUB_TOKEN`, no secrets, `persist-credentials: false`). Trigger: `pull_request` and `push` to `main`. The job changes no repository setting; making it a required check is a separate owner action.

```bash
CGO_ENABLED=1 go test -tags securityfoundation -race -count=1 -timeout 8m -v \
  -run '^TestSecurityFoundation' ./internal/hub/rpc ./internal/egress
```

The `securityfoundation` build tag selects the fixture-only test files. The ordinary suite (`go test ./...` without the tag) does not compile them and has no dependency on their test interfaces.

| Test | Scope |
| --- | --- |
| `TestSecurityFoundation` | End-to-end on a supported Linux hub against in-process fixtures: real approve/enroll flow for a read-role client, authorized mTLS read over HTTP/2, revocation denying both the reused and a fresh connection without running the handler, and the on-disk audit hash chain verified (including rejection of tampered logs). |
| `TestSecurityFoundationFailClosed` | Vault fail-closed paths: initialize refused without an audit sink; audit sink failure denies unlock/release while lock still erases the key; storage failure (invalid sealed image) refuses writes and unlock, stays locked across restart, and is audited per integration with no credential released or leaked. |
| `TestSecurityFoundationProvider` | Synthetic HTTPS provider: guarded happy path and wrong-credential refusal; a rogue (unapproved) CA and a same-CA leaf with the wrong pin are refused at TLS before any HTTP request; loopback and metadata (SSRF) destinations are denied even when declared. |
| `TestSecurityFoundationRebinding` | With injected resolution and dial, a second DNS answer mixing allowed and forbidden addresses (loopback, metadata, IPv4-mapped private) is rejected. |
| `TestSecurityFoundationSanitization` | The provider sample is sanitized identically by `sanitize.Log` and `sanitize.Label`. |

mTLS, egress, and sanitization negative cases are covered by the happy/negative fixtures in `TestSecurityFoundation`, `TestSecurityFoundationProvider`, `TestSecurityFoundationRebinding`, and `TestSecurityFoundationSanitization`, not by `TestSecurityFoundationFailClosed`.

Native transport coverage (Unix socket and `tsnet` listener behavior) stays in the S08 tests and is not duplicated here.

### Fixtures and stubs

- All inputs are synthetic. The only design stubs are in `_test.go` files and are never compiled into a binary.
- No live provider credentials, production provider endpoints, collectors, or tailnet. `tsnet` is not joined.
- The synthetic HTTPS fixture binds the runner's own private IPv4 address. CI relies on the hosted runner already having one assigned. The fixture accepts connections only from that same address and accepts exactly one synthetic credential.
- Each test has a hard time bound (`-timeout 8m`, job `timeout-minutes: 15`, per-operation contexts in the tests) and releases its listeners, files, and goroutines through `t.Cleanup`.

## 2. Sanitized Output

Test failures and logs report a safe category only (for example `egress: destination denied`, `mtls: certificate revoked`, `vault: locked`). They must never print:

- request or response payloads, or the synthetic credential;
- certificate or key bytes (PEM or DER);
- host or runner IP addresses.

When a failure needs more detail, reproduce it locally with the same command. Do not paste raw output into an issue or pull request without checking it against the list above.

## 3. Threat Crosswalk

The table maps each test to the [threat model](threat-model.md) rows it exercises. A row listed here has fixture coverage only; it is not a statement that the threat is eliminated.

| Threat ID | Test | Safe failure category |
| --- | --- | --- |
| T-TB2-S, T-TB2-I | `TestSecurityFoundation` (mTLS read, revocation on reused and fresh connections) | `mtls` |
| T-TB2-R | `TestSecurityFoundation` (audit chain, tamper rejection) | `audit` |
| T-TB7-R | `TestSecurityFoundation` (tamper rejection), `TestSecurityFoundationFailClosed` (unconfigured or failed audit sink refuses vault actions) | `audit` |
| T-TB2-E | `TestSecurityFoundation` (revoked client denied, handler not run) | `authz` |
| T-TB7-I | `TestSecurityFoundationFailClosed` (no credential in output, vault dir, or audit dir) | `vault` |
| T-TB7-D | `TestSecurityFoundationFailClosed` (storage failure locks; locked after restart) | `vault` |
| T-TB8-I | `TestSecurityFoundation` (same-named scopes resolve only within each integration; undeclared or absent scopes do not release a value), `TestSecurityFoundationFailClosed` (no release after failed storage write) | `vault`, `secret` |
| T-TB4-T | `TestSecurityFoundationRebinding` (mixed/forbidden answers), `TestSecurityFoundationProvider` (loopback, metadata) | `egress` |
| T-TB4-I, T-TB5-I | `TestSecurityFoundationProvider` (credential sent only over pinned TLS; rogue CA, same-CA wrong pin) | `egress`, `secret` |
| T-TB4-E, T-TB11-T | `TestSecurityFoundationSanitization` | `sanitize` |

## 4. Before Any Live Collector Is Enabled

No live collector may be enabled until both of these hold:

1. #21 has been reviewed and merged, and only after #19 was merged.
2. `security-foundation` is green on the commit that enables the collector.

Reviewers must check:

- The five tests above exist under the exact names and run with `-tags securityfoundation -race`.
- Inputs are synthetic; no real token, certificate, provider host, or tailnet node appears in the diff or the logs.
- Failure messages show categories only (Section 2).
- Every crosswalk row points at an assertion that exists.
- The fixture only accepts same-address connections and the one synthetic credential.
- Each residual risk in Section 5 is acknowledged by the owner by name.

**Stop and roll back:** if the gate goes red, flakes, or prints anything listed in Section 2, do not enable or keep any live collector. Revert the enabling change. If a credential might have appeared in output, rotate it and remove the affected logs, then rerun the gate before trying again.

## 5. Residual Risks

These require explicit owner review. This document does not record that review.

- Fixtures run on one hosted Linux runner. They do not cover other platforms, real providers, real network paths, or a joined tailnet.
- Passing tests show the tested paths behave as asserted on that run. They do not prove the absence of other defects. `-race` only detects races on executed paths.
- The fixture depends on the runner's private IPv4 address. A runner without one fails the gate; it does not skip it.
- The [threat model residual risks](threat-model.md#residual-risks) (shared collector memory, Go runtime secret copies, audit truncation, Tailscale control-plane trust, locked start after reboot) are unchanged by this gate.
