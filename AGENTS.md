<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# SecPal/deployment agent instructions

## Scope and work boundaries

- Write only inside `SecPal/deployment` unless a current user instruction
  explicitly authorizes a cross-repository change.
- Treat sibling repositories as read-only references by default.
- Preserve existing worktrees and changes; never overwrite work you do not own.
- Never use destructive Git commands, force-push, or bypass hooks.
- Keep one coherent topic per branch and pull request.

## Canonical work graph

- Follow `SecPal/.github/docs/work-graph-contract.md` as the single authority
  for work-graph, delivery, replanning, and evidence semantics. This repository
  adds only deployment-specific implementation and security constraints.
- Follow `SecPal/.github/docs/evidence-architecture-contract.md` as the
  authoritative companion for evidence-pipeline and external-system
  architecture. Do not create independent generic definitions of its
  observation, normalization, admission, assembly, invariant-ownership,
  diagnosability, or anti-loop rules here. Deployment-specific constraints in
  this baseline may strengthen those rules at deployment trust boundaries but
  do not replace their canonical definitions.
- The native GitHub graph state is authoritative. Human-readable diagrams and
  prose are explanatory only and must not duplicate native relationship or
  progress state.
- A leaf owns one reviewable contract and one primary delivery pull request,
  linked with `Fixes #<leaf>`. A leaf inside an epic also carries
  `Part of: #<parent>` as canonical delivery linkage, not graph authority.
- Promote a leaf to a sub-epic when it needs multiple independently reviewable
  contracts or delivery pull requests. Preserve parallelism: use dependencies
  only for genuine prerequisites and native sibling order for preference.

## Security boundaries

Without current explicit authorization, do not access the Docker daemon,
container registries, package registries, live systems, production endpoints,
cloud providers, DNS, deployment targets, registry logins, image pushes,
Docker pruning, or secrets. Package-network access is allowed only when it is
necessary for the specifically ordered local validation.

Always forbidden:

- committing secrets or `.env` files with real values;
- committing private keys, certificates, tokens, or credentials;
- mounting the Docker socket into a container;
- using `latest` tags or unpinned production images;
- running production database operations or `docker system prune`;
- force-pushing, bypassing hooks, or creating unsigned commits.

Never print secret values to logs.

## Development contract

- Observable behavior or validator-contract changes require failing-first
  contract or behavior evidence, followed by the minimum implementation and a
  refactor with the tests green.
- Behavior-preserving refactors may rely on unchanged behavior tests,
  characterization, structural, source-shape, security, or pinned-equivalence
  evidence. Do not manufacture a failing-first test when behavior is preserved.
- If a leaf promises a real-system or cloud outcome, repository-authored
  fixtures cannot replace real-system evidence. Do not require a real-system
  run when the leaf promises no real-system outcome.
- One scenario or evidence artifact may satisfy several acceptance criteria.
  Stop at the smallest non-redundant evidence set; do not create one test per
  finding or one evidence leaf per seam.
- Run all relevant validation before committing and report exact commands and
  results.
- Maintain SPDX headers and REUSE compliance.
- Use ShellCheck and `set -euo pipefail` for Bash.
- Use POSIX shell only when portability is intentional and tested.
- Use secure temporary files and directories with restrictive permissions.
- Never evaluate untrusted input with `eval` or `source`.
- Never expose secrets in logs.
- Pin versions and image digests exactly in production deployment paths.
- Current non-production cloud conformance follows the Rocky Linux 10.2+ and
  SELinux contracts owned by #117-#123. It remains isolated from production,
  records resolved provider and package identities in closed schema-validated
  evidence, and never treats a disposable integration fixture as production
  infrastructure.

## Validator and evidence design

- When deployment independently enforces a canonical invariant at a cloud,
  host, registry, or migration trust boundary, that enforcement must name the
  canonical owner and include executable agreement evidence; it does not
  become a second definition of the invariant.
- Apply the canonical evidence-architecture companion before dispatching any
  deployment-owned cloud, host, registry, migration, or conformance operation.
  Deployment preflight must fail closed when its reachable trusted operations
  cannot produce the required bounded semantic diagnostics.
- Prefer standard-library, language, runtime, and platform primitives over
  hand-written equivalents. Python scope analysis uses `symtable` for this
  reason. Custom deployment-domain validation remains legitimate where no
  standard owns the rule. Do not add a dependency when the standard library or
  platform suffices.
- Use allowlists when the valid set is finite, closed, and known, and reject
  unknown values. Do not force an allowlist onto an open-ended domain.
- Cloud evidence remains closed-schema, bounded, target-SHA-bound, and
  independently revalidated. Repository-authored fixtures prove repository
  behavior; only provider/system evidence proves a promised real-system result.

## Licensing, REUSE, and Branding

- Use `AGPL-3.0-or-later` for SecPal-owned material intentionally covered by
  the AGPL. Never add or restore `LicenseRef-SecPal-Attribution` after the
  licensing rollout.
- Preserve deliberately different licenses, including `CC0-1.0`, `MIT`,
  `Apache-2.0`, third-party and generated-file licenses, and unrelated custom
  license references. Do not rewrite third-party copyright or license metadata.
- Use `SecPal Contributors` where the project copyright convention applies.
  Preserve each file's first-publication year and extend its year range through
  the current year when an edited file requires a copyright-year update.
- Run the relevant REUSE or license validation after changing copyright or
  license metadata.
- On user-facing official SecPal product surfaces, preserve
  `Powered by SecPal – A guard's best friend` where it is intentionally present.
  A licensing change must not remove, weaken, parameterize, genericize, or make
  that SecPal branding optional.
- Do not add fork-oriented `Based on SecPal` guidance to AI instructions, and
  do not introduce white-label or fork-branding configuration as part of a
  licensing change.

## Future deployment invariants

- API and frontend remain separate images.
- Product Containerfiles are never duplicated here.
- `activity-hash-chain worker: exactly one`.
- `scheduler: exactly one`.
- Migrations are explicit and run exactly once, never from an entrypoint or
  health check.
- Production PostgreSQL 18 is host-native systemd/SELinux infrastructure, not a
  SecPal product container; integration PostgreSQL remains disposable test data.
- PostgreSQL provides relational state, sessions, durable queues, and shared
  cache; the current production and integration topology has no Valkey.
- Host-native HAProxy owns public TLS and routing with external Certbot;
  product containers remain private and do not expose public TLS.
- Security is layered across SELinux/rootless confinement, nftables, CrowdSec
  host decisioning, AppSec/Coraza, and socketless runtime detection.
- PostgreSQL recovery uses Barman, `single` private-file recovery uses Borg, and
  Recovery Sets bind database, file/object, crypto-generation, and provenance
  evidence. Disposable integration storage is never backup evidence.

## Communication

- Keep GitHub-facing communication in English.
- Do not add AI attribution, generated-by wording, or AI co-author trailers.
- Report exact commands and their results.
- Never describe a check as successful unless it actually ran and passed.
