# Contributing to hx

Thank you for your interest in contributing to `hx`.

`hx` is designed as a secure, read-only-first infrastructure monitoring system for hybrid cloud and homelab environments. Development follows an issue-driven, dependency-verified roadmap where every change is independently reviewable and verifiable.

---

## 1. Ground Rules & Scope

1. **One Focused PR per Issue:** Every pull request must address exactly one assigned issue (e.g., `Closes #<issue>` for full scope, or `Refs #<issue>` for partial draft work). Do not combine unrelated features, refactors, dependency updates, or documentation cleanup into a single pull request.
2. **Issue & Direct Dependency Readiness:** An issue is only ready to be worked on when:
   - An open tracking issue exists with defined outcome, scope, acceptance criteria, and validation requirements.
   - All direct blocker issues listed in the issue's `Dependencies` section have been **merged** into the default branch (`main`) and their acceptance evidence verified. A prerequisite issue being closed or in a separate draft branch is **insufficient**.
3. **No Phantom Guarantees:** Do not make forward claims of completed operational monitoring, cryptographic security, production readiness, or GUI capability before the owning issues have been implemented and verified.
4. **MIT License & Clean Attribution:** All contributions are made under the [MIT License](LICENSE). Do not introduce proprietary headers, artificial assistant/generated code signatures, or non-permissive code snippets. Required third-party copyright notices and license attributions must be preserved in compliance with applicable licenses.

---

## 2. Branch Naming & Workflow

Work on branches created from an up-to-date `main` branch.

### Branch Naming Convention

Use prefixes matching the issue intent, followed by the issue number and a descriptive hyphenated slug:

- `feat/<issue>-<slug>` — New features, subsystems, or capabilities (e.g., `feat/11-contribution-workflow`).
- `fix/<issue>-<slug>` — Bug fixes or defect remediation (e.g., `fix/42-nil-pointer-check`).
- `docs/<issue>-<slug>` — Documentation improvements, ADRs, or architectural guides (e.g., `docs/9-architecture-records`).

### Workflow Rules

- **No Force-Pushes Over Others:** Force-pushing (`git push --force`) to shared branches or pushing over another contributor's branch without explicit coordination is forbidden.
- **Squash / Rebase Policy:**
  - Pull requests are integrated into `main` using **Squash and Merge** by default to maintain a clean linear Git history with descriptive commit summaries linked to the issue.
  - **Rebase and Merge** is permitted at the discretion of the human maintainer when clean individual atomic commits provide valuable historical context.
  - Merge commits (`git merge --no-ff`) are prohibited by project policy to maintain a linear Git history, though repository settings currently remain permissive.
- **No Inferred Merge Authorization:** Automated tools, CI bots, and agent contributors must never self-merge or presume authorization to merge. All merge decisions remain strictly with the human repository owner (@hndrxc).

---

## 3. Local Verification Checks

Before submitting a pull request, run the standard verification script `scripts/check.sh`. Checks run with local Go toolchain commands without requiring live credentials or third-party linters (first run or module downloads may require network access for Go module proxy and checksum verification):

Stage intended edits (`git add ...`) or commit them before running `generated` or `all`: generation is compared against the index, and unrelated unstaged or untracked files also fail the check. Never stage unexpected generated output merely to silence a failure; review and correct its cause.

```bash
# 1. Go formatting checks (standard gofmt)
bash scripts/check.sh formatting

# 2. Build verification across supported targets (linux/amd64, windows/amd64, linux/arm64)
bash scripts/check.sh build

# 3. Unit and architecture policy test execution (CGO_ENABLED=0 go test ./...)
bash scripts/check.sh test

# 4. Generated file verification, go.mod consistency, and index-baseline cleanliness
bash scripts/check.sh generated
```

To run all four checks in sequence:
```bash
bash scripts/check.sh all
```

For detailed specifications on each check and CI environment variables, see [docs/ci.md](docs/ci.md).

---

## 4. Pull Request Requirements

When opening a pull request, complete all sections in the pull request template:

1. **Issue Linkage:** Include `Closes #<issue>` in the description when completing the issue scope (or `Refs #<issue>` for partial draft work).
2. **Acceptance Evidence:** Provide concrete terminal output, execution logs, or test command results proving each acceptance criterion of the issue is met.
3. **Test Commands:** Document the exact commands used to verify the change locally.
4. **Residual Risks & Rollback Notes:** Explicitly note known limitations, untested platform tiers, and rollback instructions (e.g., clean revert command or commit SHA).
5. **Security Review:** Any pull request modifying security-sensitive areas requires explicit review from the repository owner (@hndrxc):
   - Redacted secrets and scoped handles (`internal/secret/*`).
   - Hub vault, audit log, operator enrollment, RPC, and IPC handlers (`internal/hub/vault/*`, `internal/hub/audit/*`, `internal/hub/enroll/*`, `internal/hub/rpc/*`, `internal/hub/ipc/*`).
   - Client configuration, hub RPC client, or enrollment credential storage (`internal/client/*`).
   - Network boundaries, egress policy enforcement, and TLS trust/pinning (`internal/egress/*`, `docs/security/*`).
   - Collector runtime context, collector interface, and provider integration manifests (`internal/collector/*`, `internal/integrations/*`).
   - CI workflows, verification scripts, release configurations, or repository rules (`.github/*`, `scripts/*`).
   - Dependency manifests and lockfiles (`go.mod`, `go.sum`).

---

## 5. Platform Limitations & Honest Claims

When contributing platform-specific code or documentation, adhere to the platform tiers defined in [ADR-0005](docs/adr/0005-supported-platforms-and-build-targets.md) and [docs/compatibility.md](docs/compatibility.md):
- **Supported:** Validated with recorded execution evidence on real hardware.
- **Build-verified:** Successfully compiled for the target `GOOS`/`GOARCH` in CI or headless environments, but not executed on real target hardware.
- **Build-unverified:** Intended architectural target not yet compiled or tested in CI.
- **Unsupported:** Explicitly out of scope.

Never claim a target is "Supported" or "Verified" based solely on compilation success or hypothetical compatibility. Document platform boundaries and headless limitations honestly.
