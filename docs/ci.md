# Continuous Integration & Repository Protection Guide

**Status:** Specification and implementation of CI verification workflow and repository protection ruleset established in Issue [F03 (#11)](https://github.com/hndrxc/hx/issues/11).

This document specifies the continuous integration (CI) architecture, check definitions, execution security model, generated-file policy, and repository ruleset requirements for `hx`.

---

## 1. CI Workflow Architecture & Execution Model

The repository CI workflow is defined in `.github/workflows/ci.yml` under the workflow name `CI`. It enforces four independent, stable verification checks across all pull requests and pushes to `main`.

### Workflow Invariants

1. **Independent Execution:** The workflow defines four separate jobs: `formatting`, `build`, `test`, and `generated`. Jobs declare no inter-job dependencies (`needs:`), allowing them to run concurrently and isolate failures to specific quality dimensions.
2. **Stable Check Names:** Check run names match their job IDs exactly (`formatting`, `build`, `test`, `generated`). These names provide permanent anchors for branch protection and ruleset enforcement.
3. **Trigger Behavior & Limitations:** Triggers are configured for `pull_request` (running by default on `opened`, `synchronize`, and `reopened` activity types) across all branches, and for `push` to `main`. No path filters (`paths:` or `paths-ignore:`) are used. Note that GitHub Actions requires first-time outside contributor fork PRs to be manually approved by a repository maintainer before workflows execute, and PR merge conflict states can prevent pull request merge ref evaluation.
4. **Toolchain Version Alignment:** Go versioning in CI is driven from `go.mod` (`go 1.27.3`) via `actions/setup-go` (`go-version-file: 'go.mod'`), ensuring CI chooses the declared Go version. Local development environments may have a newer patch or minor release of Go installed, so `go-version-file` ensures CI adheres to the declared floor/version rather than guaranteeing identical toolchains across all local machines.
5. **Runner Environment:** All jobs run on standard GitHub-hosted `ubuntu-24.04` Linux runners.

---

## 2. Fork Security & Privilege Minimization

To protect the repository against supply-chain compromise, unauthorized writes, and credential exfiltration from untrusted pull requests (e.g., forks):

- **Read-Only Permissions:** Top-level workflow permissions explicitly enforce read-only token scope:
  ```yaml
  permissions:
    contents: read
  ```
- **Standard `pull_request` Trigger (No `pull_request_target`):** The workflow strictly uses the `pull_request` event. It explicitly rejects `pull_request_target`, which runs in the context of the base branch and receives read/write repository tokens by default (subject to workflow permissions) along with repository secrets. In contrast, standard `pull_request` runs for fork pull requests execute in the context of the fork with a read-only `GITHUB_TOKEN` and receive no repository secrets from the target repository.
- **No Secret References:** No repository secrets, deployment tokens, or API credentials are exposed or referenced in the CI workflow, and no repository secrets are provided to fork PRs by this workflow.
- **Git Credential Hygiene:** The repository checkout action sets `persist-credentials: false`, ensuring the temporary authentication token is not persisted in the runner's git configuration or temp credentials store.
- **SHA-Pinned Actions:** External actions are pinned to full immutable 40-character commit SHAs with version comments (see [Section 7](#7-action-pins-and-authoritative-references)), significantly reducing mutable-tag tampering and supply-chain risks.

---

## 3. Verification Checks Specification

All CI checks are implemented in `scripts/check.sh` and are executable locally using standard `bash` without relying on the file's executable permission bit.

```bash
# Run individual checks
bash scripts/check.sh formatting
bash scripts/check.sh build
bash scripts/check.sh test
bash scripts/check.sh generated

# Run all checks sequentially
bash scripts/check.sh all
```

### Check 1: `formatting`

- **Stable Check Name:** `formatting`
- **Command:** `bash scripts/check.sh formatting`
- **Purpose:** Verifies that all tracked Go source code complies with standard `gofmt` formatting rules without mutating files.
- **Scope & Mechanics:**
  - Enumerates all tracked Go source files using `git ls-files '*.go'`.
  - Directly inspects files including those with build tags (e.g., `//go:build desktop` or `//go:build ignore`), which package-oriented formatters skip.
  - Non-mutating: runs `gofmt -l -e` to detect unformatted files and outputs a unified diff using `gofmt -d -e`. Files on disk are never modified.
- **Failure Conditions:** Any unformatted Go file or syntax error exits 1 with the list of offending files and a unified diff.

### Check 2: `build`

- **Stable Check Name:** `build`
- **Command:** `bash scripts/check.sh build`
- **Purpose:** Verifies pure Go compilation feasibility across all defined tier platforms without native CGO dependencies.
- **Compilation Matrix (7 Targets):**
  1. `linux/amd64`: `cmd/hx` (CLI / hub entrypoint)
  2. `linux/amd64`: `cmd/hx-agent` (telemetry daemon)
  3. `linux/amd64`: `cmd/hx-desktop` (headless scaffold)
  4. `windows/amd64`: `cmd/hx` (`hx.exe`)
  5. `windows/amd64`: `cmd/hx-agent` (`hx-agent.exe`)
  6. `windows/amd64`: `cmd/hx-desktop` (`hx-desktop.exe`)
  7. `linux/arm64`: `cmd/hx-agent` (`hx-agent-arm64`)
- **Flags & Environment:** `CGO_ENABLED=0`, `-trimpath`.
- **Workspace Isolation:** Binaries are compiled into a temporary directory outside the repository checkout (`mktemp -d`), which is trapped and removed upon completion or exit. Build artifacts never pollute the working tree.
- **Failure Conditions:** Any compiler error or failure to generate a target binary exits 1.

### Check 3: `test`

- **Stable Check Name:** `test`
- **Command:** `bash scripts/check.sh test`
- **Purpose:** Executes the repository test suite, including command routing tests, version reporting tests, and ADR-0011 package architecture boundary enforcement.
- **Flags & Environment:** `CGO_ENABLED=0 go test ./...`.
- **Failure Conditions:** Any unit test failure, panic, or architecture boundary violation exits with the Go test runner's non-zero status.

### Check 4: `generated`

- **Stable Check Name:** `generated`
- **Command:** `bash scripts/check.sh generated`
- **Purpose:** Enforces module tidiness, checksum verification, and generated-file consistency.
- **Execution Sequence:**
  1. `go mod tidy -diff`: Verifies that `go.mod` and `go.sum` require no additions, removals, or formatting adjustments.
   2. `go mod verify`: Checks that cached dependency module ZIPs and extracted directories have not changed since download, using cached download hashes. Module downloads are authenticated against `go.sum` and, when applicable, the checksum database by Go module download operations; `go mod verify` is not a replacement for that authentication.
  3. `go generate ./...`: Executes any code generators declared across repository packages.
  4. Working Tree Cleanliness Check:
     - `git diff --exit-code`: Verifies that no tracked files were modified or deleted by generation commands against the git index.
     - `git ls-files --others --exclude-standard`: Verifies that no new untracked files were emitted.
- **Local Developer Workflow:** Because `check_generated` compares the working tree against the git index, developers should stage intended edits (`git add ...`) before running `bash scripts/check.sh generated` or `bash scripts/check.sh all`. Staged changes supply a clean baseline, ensuring that only actual generation drift or unexpected untracked artifacts trigger failure.
- **Failure Conditions:** Any `go.mod` discrepancy, checksum mismatch, modified tracked file, or untracked generated output exits 1 and displays the corresponding diff and status.

---

## 4. Generated-File & Scaffolding Policy

To prevent silent build drift and hidden generator requirements:

1. **Committed Output:** If code generation tooling (`go generate`) is introduced in future milestones, all generated files must be committed to source control.
2. **Drift Detection:** The `generated` CI check detects any drift between generators and committed files. If running `go generate ./...` produces uncommitted modifications or new untracked files, CI fails immediately.
3. **No Dummy Generators:** In accordance with the F02/F03 minimal bootstrap contract, no fake, dummy, or placeholder generator scripts are added. Currently, `go generate ./...` executes cleanly as a no-op across all packages.
4. **Ignored Directories:** `.gitignore` restricts root-level exclusions to `/bin/` (for local manual binary builds) to avoid masking unexpected untracked files.

---

## 5. Security Gates Boundary (F03 vs. F04)

- **F03 Scope (This Work):** Establishes the foundational contribution workflow, pull request templates, CODEOWNERS file, repository protection documentation, and the four baseline CI checks (`formatting`, `build`, `test`, `generated`).
- **F04 Scope (Issue #20, Security Gates and Vulnerability Baseline):** Security analysis gates—including static analysis (`staticcheck`), vulnerability scanning (`govulncheck`), secret scanning, and forbidden-identifier AST inspection (e.g. `InsecureSkipVerify` prohibitions)—are owned by Issue #20 (F04). This is distinct from downstream release artifact signing, SLSA provenance generation, and release SBOM publishing, which are owned by Issue #41 (F05). F03 does not couple CI to premature security gates.

---

## 6. Self-Service Ruleset Setup & Repository Protection Configuration

### Critical Enforcement Notice

> **Important:** The presence of `.github/workflows/ci.yml` and `.github/CODEOWNERS` in the repository does **not** automatically enforce check requirements or review gates on GitHub.
>
> Repository rulesets and branch protection settings must be configured explicitly in GitHub repository settings by a repository administrator. The current repository ruleset enforces **only branch deletion and non-fast-forward protections**. Required reviews, Code Owner approval, and required status checks are **not yet enforced in repository settings** until configured as documented below.

### Administrator Setup Guide: Main Branch Protection Ruleset

To activate branch protection and enforce CI checks and Code Owner approvals, a repository administrator must configure the following ruleset:

1. Navigate to **Settings** > **Rules** > **Rulesets** in the GitHub repository.
2. Select **New branch ruleset** (or edit the existing `main` ruleset).
3. Set **Ruleset Name** to `protect-main` and **Enforcement status** to `Active`.
4. Under **Target branches**, add the default branch: `Include default branch` (`main`).
5. Configure the following rules:
   - **Restrict deletions:** Enabled (prevents accidental or malicious deletion of `main`).
   - **Block force pushes:** Enabled (ensures non-fast-forward push protection and linear commit integrity).
   - **Require a pull request before merging:** Enabled.
     - **Required approvals:** `1` minimum. (Note on repository eligibility: GitHub rulesets mandate that the most recent review approval cannot be from the pull request author or the pusher of the latest commit. Because repository collaborator `@hndrxc` is currently the sole maintainer and author, enforcing mandatory review approvals requires onboarding an additional distinct eligible reviewer or collaborator before pull requests can satisfy this rule; no settings changes are enforced in F03).
     - **Dismiss stale pull request approvals when new commits are pushed:** Enabled (ensures new pushes reset approval state).
     - **Require review from Code Owners:** Enabled (requires approval from the designated owner in `.github/CODEOWNERS` for protected paths).
     - **Require approval of the most recent push:** Enabled (prevents merging when commits are added after approval).
   - **Require status checks to pass before merging:** Enabled.
     - **Require branches to be up to date before merging:** Enabled (recommended).
     - **Required status checks:** Add each stable check name individually:
       - `formatting`
       - `build`
       - `test`
       - `generated`
   - **Bypass List:** Leave the ruleset bypass list empty (no roles, teams, or apps granted bypass permissions), ensuring rules apply uniformly.
6. **Merge Strategy & Policy:** Pull requests are merged manually via Squash and Merge or Rebase and Merge per maintainer review. Auto-merge is not enabled as a repository policy.

---

## 7. Action Pins and Authoritative References

### Immutable Action SHAs (Resolved via GitHub API on 2026-11-07)

The CI workflow pins actions to immutable commit SHAs rather than mutable tags to mitigate tag-mutation and supply-chain tampering risks:

| Action | Tag | Immutable Commit SHA | Resolved Date | Source Reference / Commit URL | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-11-07 | [actions/checkout@3d3c42e5...](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1) | Repository checkout with `persist-credentials: false` |
| `actions/setup-go` | `v7.0.0` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | 2026-11-07 | [actions/setup-go@b7ad1dad...](https://github.com/actions/setup-go/commit/b7ad1dad31e06c5925ef5d2fc7ad053ef454303e) | Toolchain setup using `go-version-file: 'go.mod'` |

### Official Documentation Citations

The configuration and security policies in this guide are derived from authoritative GitHub documentation (checked 2026-11-07):

1. **Automatic Token Authentication and Permissions:**
   - URL: [https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token)
   - Fact: Demonstrates scoping `GITHUB_TOKEN` permissions to `contents: read` to enforce the principle of least privilege.
2. **Security Hardening for GitHub Actions (`pull_request` vs. `pull_request_target`):**
   - URL: [https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#pull_request-vs-pull_request_target](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#pull_request-vs-pull_request_target)
   - Fact: Confirms that workflows triggered by `pull_request` from forks execute with read-only permissions and receive no repository secrets, whereas `pull_request_target` grants write permissions and access to secrets.
3. **Repository Rulesets and Available Rules:**
   - URL: [https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
   - Fact: Details the configuration of branch rulesets including deletion restriction, non-fast-forward protections, required status checks, and Code Owner review enforcement.
4. **Protected Branches and Required Status Checks:**
   - URL: [https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-merge-box-for-pull-requests/about-protected-branches#require-status-checks-before-merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-merge-box-for-pull-requests/about-protected-branches#require-status-checks-before-merging)
   - Fact: Documents that status checks are enforced by their exact check run name and must pass before pull requests can be merged.
5. **About Code Owners:**
   - URL: [https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
   - Fact: Explains the syntax and semantics of `.github/CODEOWNERS` and its interaction with branch protection rules requiring Code Owner review.

---

## 8. Verification Record

Observed verification evidence, check execution outputs, and defect probe records will be recorded below upon completion of the verification suite.
