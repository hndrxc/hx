# Dependency updates (Renovate)

`renovate.json` configures [Renovate](https://docs.renovatebot.com/) to propose
dependency updates as pull requests. Renovate never merges anything: a human
reviews and merges every PR.

## Configuration summary

| Setting | Value | Why |
| --- | --- | --- |
| `automerge` | `false` globally, in `packageRules`, `lockFileMaintenance` and `vulnerabilityAlerts` | No update lands without human review. |
| `dependencyDashboard` | `true` | The dashboard issue is for review and visibility, not approval. `dependencyDashboardApproval` is `false`, so PRs open without clicking a dashboard checkbox. |
| `pinDigests` | `true` | Docker images and GitHub Actions are pinned by digest. `helpers:pinGitHubActionDigests` pins `uses:` refs to commit SHAs. |
| `enabledManagers` | `gomod`, `github-actions`, `custom.regex` | Only Go modules, workflow actions (including `docker://` and container images Renovate extracts from workflows) and the Semgrep image pin. |
| `postUpdateOptions` | `gomodTidy` | Renovate runs `go mod tidy` so `go.mod` and `go.sum` stay consistent in the PR. |
| `lockFileMaintenance` | enabled, monthly, `automerge: false` | Explicit scheduled refresh that opens a normal PR for a human. |
| `vulnerabilityAlerts` | enabled, `automerge: false`, label `security`, suffix `[SECURITY]` | Fast path: alert PRs skip schedule and concurrency limits, but need the same review. |

The custom regex manager keeps
`semgrep/semgrep:<version>@sha256:<digest>` in `scripts/security.sh` and
`.github/workflows/security.yml` current (version and digest move together).
Go tool versions installed by `scripts/security.sh` (govulncheck, gosec,
staticcheck), the Go security-patch toolchain and the Renovate validator
version are not covered by a manager; update them by hand in a normal PR.

Notes on limits, from the Renovate docs:

- `lockFileMaintenance` lists supported lock file managers; Go (`go.sum`) is
  not among them. Enabling it is explicit and harmless, but `go.sum` is
  refreshed through ordinary module update PRs plus `gomodTidy`.
- `vulnerabilityAlerts` only works for GitHub repositories with the Dependency
  graph and Dependabot alerts enabled and read access for the Renovate app.
  Those are repository/app settings and were **not** changed by this repo
  change.
- Renovate by default skips indirect Go modules except for vulnerability-fix
  PRs.

## Review scope

Reviewers of a Renovate PR check:

1. **Version**: the new version is the intended one (no unexpected major jump
   or downgrade); read upstream release notes for breaking or security
   changes. For `go.mod`, the `go`/`toolchain` directives must not change as a
   side effect.
2. **Sum**: `go.sum` changes only contain the updated module and its
   transitive dependencies; no unrelated modules appear. `go mod tidy` yields
   no further diff.
3. **Generated files**: any generated code or fixtures affected by the update
   are regenerated and committed by a human; Renovate does not run generators
   (`goGenerate` is intentionally not enabled).
4. **Digests**: Docker and Action digests correspond to the stated tag
   upstream; Action SHAs must come from the upstream repository.
5. **CI**: the full CI and the `security.yml` jobs (`security-go`,
   `security-policy`, `fuzz-smoke`, `dependency-config`) pass before merge.

Renovate PRs never get privileged CI: workflows must not expose secrets to
them or use `pull_request_target`.

## Urgent patches

When a vulnerability fix is urgent:

1. A GitHub Dependabot alert (if enabled) causes Renovate to open a
   `[SECURITY]` PR immediately, ignoring schedule and concurrency limits. The
   owner may also tick the update on the Dependency Dashboard to trigger it, or
   make the bump by hand.
2. The owner reviews it with the same gates as above, with priority; there is no
   automerge and no privileged approval shortcut.
3. If an upstream fix is not available, record the finding (see
   `SECURITY.md`) rather than suppressing the scanner.

## Onboarding

Installing or enabling the Renovate GitHub App (or a self-hosted Renovate) is
an external repository/organization action and was **not** performed here. Until
the owner onboards Renovate, `renovate.json` is inert; the `dependency-config`
CI job validates it with `renovate-config-validator` (renovate 44.257.5).

## Sources

- Configuration options: <https://docs.renovatebot.com/configuration-options/>
  (`automerge`, `dependencyDashboard`, `pinDigests`, `postUpdateOptions`,
  `lockFileMaintenance`, `vulnerabilityAlerts`, `enabledManagers`,
  `customManagers`, `managerFilePatterns`, `prConcurrentLimit`)
- Dependency Dashboard: <https://docs.renovatebot.com/key-concepts/dashboard/>
- GitHub Actions manager: <https://docs.renovatebot.com/modules/manager/github-actions/>
- Go modules manager: <https://docs.renovatebot.com/modules/manager/gomod/>
- Custom regex manager: <https://docs.renovatebot.com/modules/manager/regex/>
- Helper presets: <https://docs.renovatebot.com/presets-helpers/>
