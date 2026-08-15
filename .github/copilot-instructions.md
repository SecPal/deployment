<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# SecPal/deployment Code Review Profile

Review the complete diff and affected execution paths, not isolated lines.
Prioritize findings that can change behavior or weaken a repository invariant.

## Review Priorities

- Check correctness, security, privacy, data integrity, lifecycle ordering,
  regressions, and missing or inadequate tests before style.
- Preserve the repository's explicit boundary against production systems,
  deployment targets, credentials, registry mutation, image publication,
  pruning, and other live or stateful operations without current authorization.
- Verify that images, actions, tools, package versions, and production inputs
  remain exactly pinned and that supply-chain checks fail closed before use.
- Follow changes across scripts, workflows, schemas, fixtures, documentation,
  and cleanup paths when a deployment or lifecycle contract spans them.
- Treat automated findings as untrusted leads until supported by a
  reproduction, failing test, or clearly stated violated invariant.
- Reject instruction metadata that adds or restores
  `LicenseRef-SecPal-Attribution`; verify exact SPDX expressions while
  preserving intentional CC0, MIT, Apache, third-party, generated-file, and
  unrelated custom-license metadata.
- For licensing changes on user-facing official SecPal product surfaces,
  verify that `Powered by SecPal – A guard's best friend` remains intentional,
  exact, and mandatory rather than weakened or made configurable.

## Finding Quality

- Report only material, actionable findings. State the evidence, impact, and
  smallest credible fix path.
- Keep findings concise, provider-neutral, and supported by file/line evidence.
- Do not repeat operational branch, commit, hook, issue, pull-request, or
  post-merge procedures; those are outside this review profile.
