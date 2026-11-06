# ADR-0010: Provider Permission Gaps and Explicit Privilege Floors

- Status: Accepted
- Date: 2026-11-06
- Issue: https://github.com/hndrxc/hx/issues/9
- Supersedes: none

## Context

`hx` collects observability and health telemetry from diverse third-party SaaS services and homelab infrastructure components. Access to these endpoints requires credentials. However, provider permission models are heterogeneous, coarsely grained, or poorly documented with respect to least privilege. Operators frequently face a temptation to supply administrative credentials or high-privilege tokens (e.g. database master passwords, root access keys, or administrative personal access tokens) to bypass access friction or undocumented permission requirements.

If `hx` were to accept or fall back to high-privilege credentials when read-only permissions fail, or if it were to report empty/healthy metrics when an API call fails due to insufficient permissions, operators would either over-privilege the monitoring system or operate under false security assumptions.

## Decision

1. **Principle of narrowest read-only credential**: Each integration collector must use the provider's narrowest read-only credential. Falling back to administrative credentials, write-capable tokens, or database passwords is strictly prohibited.
2. **Explicit failure on missing permissions**: When an integration encounters missing permissions or unsupported capability scopes, it must yield an explicit `permission_denied` or `unsupported` status for the affected resource. It must never mask errors, synthesize placeholder values, or report healthy data.
3. **Privilege floor documentation and verification**: Each provider issue documents the true privilege floor with dated primary references. Verification relies on verified documentation and credential-free fixtures or contract tests; live API testing is optional and authorized only.

### Provider Status Matrix

| Provider | Issue | Intended credential | Known/suspected gap | Status |
| --- | --- | --- | --- | --- |
| Supabase | https://github.com/hndrxc/hx/issues/36 | Scoped Management API access + current logs endpoint | Never DB password | unverified — verify in https://github.com/hndrxc/hx/issues/36 |
| Vercel | https://github.com/hndrxc/hx/issues/37 | Scoped read-only token | Token scope granularity | unverified — verify in https://github.com/hndrxc/hx/issues/37 |
| GitHub | https://github.com/hndrxc/hx/issues/38 | GitHub App installation tokens (short-lived) | Short-lived installation token scope boundaries | unverified — verify in https://github.com/hndrxc/hx/issues/38 |
| Cloudflare | https://github.com/hndrxc/hx/issues/39 | Scoped API token | DNS read permission does not imply security analytics/events; plan-dependent features | unverified — verify in https://github.com/hndrxc/hx/issues/39 |
| iDRAC Redfish | https://github.com/hndrxc/hx/issues/45 | Dedicated read-only account | Read-only role availability per firmware | unverified — verify in https://github.com/hndrxc/hx/issues/45 |
| ESXi | https://github.com/hndrxc/hx/issues/46 | Dedicated read-only account | Read-only role | unverified — verify in https://github.com/hndrxc/hx/issues/46 |
| TrueNAS | https://github.com/hndrxc/hx/issues/47 | Dedicated read-only API key | API roles differ by version | unverified — verify in https://github.com/hndrxc/hx/issues/47 |
| Kopia | https://github.com/hndrxc/hx/issues/48 | Repository/server credential | Repository/server credential grants broader access than freshness reading | unverified — verify in https://github.com/hndrxc/hx/issues/48 |
| Tailscale API | https://github.com/hndrxc/hx/issues/49 | Scoped OAuth client credentials | API key vs OAuth client scopes | unverified — verify in https://github.com/hndrxc/hx/issues/49 |
| Home Assistant | https://github.com/hndrxc/hx/issues/50 | Long-lived access token | Long-lived access tokens carry the issuing user's full privileges | unverified — verify in https://github.com/hndrxc/hx/issues/50 |

## Consequences

- Integration collectors cannot use administrative tokens or database passwords to circumvent permission hurdles.
- Collector runtimes must handle partial-permission environments where only a subset of APIs respond with valid telemetry, yielding explicit `permission_denied` or `unsupported` resource status.
- Each provider issue documents the true privilege floor with dated primary references.
- Credential privilege cannot be inferred from token bytes or arbitrary secret strings; enforcement relies on verified docs, credential-free fixtures, and contract tests.
- The vault storage and configuration models remain strictly partitioned from database credentials or write tokens.

## Verification

Enforced during integration development and CI testing for each provider implementation (issues #36, #37, #38, #39, #45, #46, #47, #48, #49, #50):
- Verified documentation and credential-free fixtures/contract tests verify collector behavior without requiring live provider credentials; optional live testing is performed only when authorized.
- Integration tests assert that collectors fail closed with explicit `permission_denied` or `unsupported` status when permissions are missing or unsupported.
- Configuration schemas and documentation prohibit database credentials and administrative write tokens.

## References

- [ADR-0002: Hub-Owned Credentials and Read-Only Integrations](0002-hub-owned-credentials-and-read-only-integrations.md)
- Issue #9: Architecture, threat model and supported-platform decisions: https://github.com/hndrxc/hx/issues/9 (checked 2026-11-06)
- GitHub REST API Authentication and Permissions: https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens (checked 2026-11-06)
- Cloudflare API Tokens Permissions: https://developers.cloudflare.com/fundamentals/api/reference/permissions/ (checked 2026-11-06)
- DMTF Redfish Specification: https://www.dmtf.org/standards/redfish (checked 2026-11-06)
- TrueNAS API Documentation: https://www.truenas.com/docs/ (checked 2026-11-06)
- Tailscale OAuth Clients: https://tailscale.com/kb/1215/oauth-clients (checked 2026-11-06)
- Home Assistant Authentication: https://developers.home-assistant.io/docs/auth_api/ (checked 2026-11-06)
