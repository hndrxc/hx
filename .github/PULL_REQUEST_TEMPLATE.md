<!--
  hx Pull Request Template
  Before opening, ensure all prerequisites and acceptance criteria are satisfied.
  Never commit, paste, or expose secrets, tokens, private keys, or credentials.
-->

## Linked Issue

<!--
  Requirement: Every PR must link to an existing issue.
  Use "Closes #<issue>" ONLY when this PR fully satisfies the entire issue scope and acceptance criteria.
  If this PR only partially addresses an issue, use "Relates to #<issue>".
-->
- Issue: Closes #

## Merged Prerequisites

<!--
  List prerequisite PRs or issues that must be merged before this change can land.
  Draft prototypes may use fixtures, but production gates require merged dependencies.
  If none, explicitly state "None".
-->
- [ ] Prerequisites merged:

## Acceptance Evidence

<!--
  Requirement: Provide concrete evidence for EACH acceptance criterion defined in the linked issue.
  Never substitute assertions or plans for observed output.
-->
- [ ] Criterion 1:
  - Evidence:
- [ ] Criterion 2:
  - Evidence:

## Checks and Verification

<!--
  Requirement: List the exact check commands executed locally, their results, and any intentional omissions.
  Reference stable CI checks: `bash scripts/check.sh <formatting|build|test|generated>`.
-->
- Commands executed:
  - `bash scripts/check.sh formatting`: [Pass / Fail / Skipped]
  - `bash scripts/check.sh build`: [Pass / Fail / Skipped]
  - `bash scripts/check.sh test`: [Pass / Fail / Skipped]
  - `bash scripts/check.sh generated`: [Pass / Fail / Skipped]
- Omissions & rationale:
  - None

## Security and Permission Review

<!--
  Requirement: If this change touches manifests, collector/integrations, secret/vault/auth/enrollment,
  egress/network/RPC/IPC paths, GitHub workflows/actions, release config, or dependency locks,
  request explicit security and permission review from @hndrxc.
-->
- [ ] Security/permission-sensitive paths modified: [Yes / No]
- [ ] Review requested from `@hndrxc` (required if Yes): [Yes / N/A]
- [ ] No secrets, credentials, tokens, or private material are included in this PR: [Confirmed]

## Compatibility and Migration

<!--
  Document compatibility impacts across supported platforms (linux/amd64, windows/amd64, and linux/arm64 agent; macOS is unsupported).
  Note breaking changes, migration requirements, schema changes, or protocol updates.
-->
- Compatibility impact: None / Details below
- Migration steps: None / Details below

## Risks

<!--
  Document technical, operational, or security risks introduced by this change.
-->
- Identified risks:

## Rollback Plan

<!--
  Document how this change can be safely reverted or mitigated if a defect is identified post-merge.
-->
- Rollback procedure:
