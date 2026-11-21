# Security CI Gates

**Status:** Specification for the security gates of Issue [F04 (#20)](https://github.com/hndrxc/hx/issues/20). This document describes the configured gates; it records no execution results. Evidence for any run is recorded by the change owner in the pull request, not here.

The gates are defensive only. They run unprivileged on the standard `pull_request` and `push` triggers, use a read-only `GITHUB_TOKEN`, reference no secrets, and make no repository-setting or bot-installation changes. See [docs/ci.md](../ci.md) for the baseline workflow model.

---

## 1. Workflow and Check Names

Workflow file: `.github/workflows/security.yml`. Stable job (check) names:

| Check | Command | Trigger | Purpose |
| --- | --- | --- | --- |
| `security-go` | `bash scripts/security.sh go` | PR, push to `main` | `govulncheck`, `gosec`, `staticcheck` on the patched Go toolchain |
| `security-policy` | Semgrep (pinned Docker image) with `.semgrep.yml` | PR, push to `main` | Repository policy rules over the tree and the annotated fixtures |
| `fuzz-smoke` | `bash scripts/security.sh fuzz-smoke` | PR, push to `main` | Short, bounded fuzz run of existing fuzz targets |
| `security-foundation` | `go test -tags securityfoundation -race -count=1 -timeout 8m -v -run '^TestSecurityFoundation' ./internal/hub/rpc ./internal/egress` | PR, push to `main` | Fixture-only S09 (#21) race tests (`TestSecurityFoundation`, `TestSecurityFoundationFailClosed`, `TestSecurityFoundationProvider`, `TestSecurityFoundationRebinding`), test source only, review required; no credentials, live provider, or tailnet; the ordinary suite does not depend on the tag; hosted result pending; see [security-foundation.md](security-foundation.md) |
| `fuzz-long` | `bash scripts/security.sh fuzz-long` | Schedule and manual dispatch only | Longer fuzzing; never runs on PRs and is not a required check |
| `dependency-config` | Renovate config validator | PR, push to `main` | Validates the Renovate configuration |

`scripts/security.sh` subcommands: `install` (installs the pinned Go tools), `go`, `fuzz-smoke`, `fuzz-long`.

Local use (Go tool installs need network access to the module proxy):

```bash
bash scripts/security.sh install
bash scripts/security.sh go
bash scripts/security.sh fuzz-smoke
bash scripts/security.sh fuzz-long   # long; normally scheduled/manual only
```

### Trigger budgets

- `security-go`, `security-policy`, `fuzz-smoke`, `security-foundation` and `dependency-config` are the only security jobs on pull requests; `fuzz-smoke` and `security-foundation` are time-bounded so PR latency stays small.
- `security-go`, `security-policy`, `fuzz-smoke`, `security-foundation` and `dependency-config` run only on `pull_request` and `push` to `main`; they do not run on `schedule` or `workflow_dispatch`.
- `fuzz-long` runs only on `schedule` and on `workflow_dispatch` from `main` (it checks out `main` with `persist-credentials: false`), so unbounded fuzzing cannot block a PR.
- All jobs run on `ubuntu-24.04`, consistent with the baseline `CI` workflow.
- Fuzz targets (five, exact): `./cmd/hx FuzzParseCheckpoint`, `./internal/hub/audit FuzzVerifyAnchoredFrame`, `./internal/sanitize FuzzLogProperties`, `./internal/sanitize FuzzLabelProperties`, `./internal/secret FuzzRedactionIndependence`. `fuzz-smoke` runs each for `-fuzztime 100x`; `fuzz-long` runs each for `-fuzztime 60s`.
- The exact timeouts and fuzz durations are defined in `.github/workflows/security.yml` and `scripts/security.sh`; those files are authoritative.

---

## 2. Pins

| Component | Pin |
| --- | --- |
| Go toolchain for the security scan | Go `1.27.4` (security patch), see [Section 3](#3-patched-go-toolchain-and-gomod-minimum) |
| `govulncheck` | `v1.9.0` (`golang.org/x/vuln/cmd/govulncheck`) |
| `gosec` | `v2.30.0` (`github.com/securego/gosec/v2/cmd/gosec`) |
| `staticcheck` | `v0.8.2` (`honnef.co/go/tools/cmd/staticcheck`) |
| Semgrep | Docker `semgrep/semgrep:1.186.0@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1` |
| Renovate config validator | `44.257.5` (`renovate` npm package, `renovate-config-validator`) |
| Node (for the Renovate validator) | `26.13.0` via `actions/setup-node` pinned to upstream commit SHA `949feb2413d6458794dcd2491c4babbbce0c15c1` (v7.1.0) |

Actions in the workflow are pinned to full commit SHAs as described in [docs/ci.md Section 7](../ci.md#7-action-pins-and-authoritative-references). Update pins only through a reviewed change following the [dependency update policy](dependency-updates.md).

Primary upstream references:

- govulncheck: <https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck> and <https://go.dev/doc/security/vuln/>
- gosec: <https://github.com/securego/gosec>
- staticcheck: <https://staticcheck.dev/docs/>
- Semgrep: <https://semgrep.dev/docs/> (rule syntax: <https://semgrep.dev/docs/writing-rules/rule-syntax>; testing rules with annotations: <https://semgrep.dev/docs/writing-rules/testing-rules>)
- Renovate: <https://docs.renovatebot.com/config-validation/>
- Go fuzzing: <https://go.dev/doc/security/fuzz/>
- Go release history (security patches): <https://go.dev/doc/devel/release>

---

## 3. Patched Go Toolchain and `go.mod` Minimum

The security workflow scans with Go `1.27.4`, which carries standard-library security fixes. The standard library is part of what `govulncheck` reports on, and the baseline advisory report in PR [#90](https://github.com/hndrxc/hx/pull/90) found standard-library findings fixed in the newer patch release. The scan therefore uses the patched toolchain so that findings reflect the repository's own code and dependencies rather than a known-stale toolchain.

The application `go.mod` now declares `go 1.27.4`, so the module minimum matches the patched scan toolchain. Consequences:

- The patched workflow toolchain (`1.27.4`) is what the security gates analyze.
- The `go.mod` minimum describes the oldest toolchain the module supports; raising it to `1.27.4` means builds no longer accept the toolchain with the standard-library issues fixed in that release. It is not a claim that the module is free of other issues.
- Raising the `go.mod` minimum again is a separate, security-reviewed decision under the [dependency update policy](dependency-updates.md).

---

## 4. Semgrep Policy Gate

Rules live in `.semgrep.yml`. The scan runs in the pinned Docker image above, against the checkout of the event's commit (`persist-credentials: false`, no credentials in the workspace), with `--network none`, `--read-only` and the workspace mounted read-only.

The full-repository scan uses `--no-git-ignore` (so gitignore rules cannot hide files) and `--exclude security/testdata` (the fixture tree is intentionally violating and is covered by the rule tests instead). Semgrep's default ignore patterns (for example `test/`, `tests/`, `vendor/`, `node_modules/` and similar) still apply, because no custom `.semgrepignore` replaces them; the scan scope is not otherwise narrowed or widened.

### Cooperative scope

Semgrep here is a **cooperative** guard: it catches accidental or well-intentioned violations of repository policy (for example, forbidden identifiers or unsafe patterns) by contributors who follow the conventions. It is not a sandbox and does not defend against an adversarial contributor who can restructure code to evade pattern matching, nor does it replace review of security-sensitive paths (see [CONTRIBUTING.md](../../CONTRIBUTING.md#4-pull-request-requirements)). Findings are blocking; correct the code rather than the rule.

### No inline suppressions

Inline ignores are disabled (`--disable-nosem`), so `// nosemgrep` comments have no effect. Rules carry no suppressions, and no broad path or rule exclusions are used. Any needed exception must be a narrowly scoped, reviewed change to `.semgrep.yml` itself.

### Annotated fixture proofs

Rule behavior is proven with inert fixtures under `security/testdata`. Fixtures use Semgrep's `ruleid:` / `ok:` annotations (<https://semgrep.dev/docs/writing-rules/testing-rules>) and are harmless: they are test data that is never built into binaries and never executed as an attack.

Semgrep CLI 1.186.0 crashes `--test` when given the config file together with a target directory, so the test is invoked once per exact fixture file (a config/target-file pair is supported): `collector.go`, `logging.go`, `render.tsx`, `tls.go`. Reproduce locally with the same pinned image:

```bash
for fixture in collector.go logging.go render.tsx tls.go; do
  docker run --rm --network none --read-only --tmpfs /tmp \
    -e HOME=/tmp -e SEMGREP_SEND_METRICS=off -e SEMGREP_ENABLE_VERSION_CHECK=0 \
    -v "$PWD:/src:ro" -w /src \
    semgrep/semgrep:1.186.0@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1 \
    semgrep scan --test --strict --metrics=off --disable-version-check \
      --config .semgrep.yml "security/testdata/$fixture"
done
```

`security-policy` is the authoritative definition of how CI invokes the scan; the command above is for local reproduction.

### Go probe commands

The scanner probe is an inert, committed fixture, `security/testdata/scanners/probe.go`. It uses a weak digest (`G401`/`G501`) and an invalid regular expression (`SA1000`). It is outside production scan targets and never executed. Both commands below should exit 1 with those findings:

```bash
export GOBIN="$(mktemp -d)"
bash scripts/security.sh install
export PATH="$GOBIN:$PATH" GOTOOLCHAIN=go1.27.4
staticcheck ./security/testdata/scanners
gosec ./security/testdata/scanners
```

Because `go.mod` now requires `go 1.27.4`, the earlier `GOTOOLCHAIN=go1.27.3 govulncheck ./...` negative check no longer applies: the older toolchain refuses to load the module. The workflow uses the patched toolchain and the live advisory database. Results depend on the source tree and current advisories.

---

## 5. gosec Exception: F04-001 (G304)

| Field | Value |
| --- | --- |
| ID | F04-001 |
| Rule | gosec `G304` (file inclusion via variable) |
| Location | `cmd/hx/audit.go` only |
| Justification | The operator explicitly selects a local audit file for **offline verification**. The path comes from the operator's own command-line choice; there is no replay path and no provider-supplied path reaches the open call. |
| Scope | One narrowly reviewed site. No directory, package, or rule-wide exclusion. |
| Expires | **2027-02-20** |
| Renewal | Must be eliminated, or renewed in a security-reviewed change (reviewed by @hndrxc) before the expiry date. |

No other `G304` finding, and no other gosec rule, is excepted. Broad exclusions (whole files, directories, or rules) are not permitted. Any new exception requires the same justification, owner, scope and expiry, recorded here in a security-reviewed change. See [docs/security/audit-log.md](audit-log.md) for the audit log design.

---

## 6. Boundaries

- No repository settings, rulesets, or required-check configuration are changed by these gates; making a check required is a separate owner action (see [docs/ci.md Section 6](../ci.md#6-self-service-ruleset-setup--repository-protection-configuration)).
- No bots or GitHub Apps are installed. `dependency-config` only validates the Renovate configuration file; it does not enable Renovate.
- Release signing, provenance and SBOM publication remain with Issue #41 (F05).
