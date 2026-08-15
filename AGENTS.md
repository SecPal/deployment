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

- Use test-driven development for executable scripts and validation logic:
  write the smallest failing test first, implement the minimum behavior, then
  refactor with the tests green.
- Run all relevant validation before committing and report exact commands and
  results.
- Maintain SPDX headers and REUSE compliance.
- Use ShellCheck and `set -euo pipefail` for Bash.
- Use POSIX shell only when portability is intentional and tested.
- Use secure temporary files and directories with restrictive permissions.
- Never evaluate untrusted input with `eval` or `source`.
- Never expose secrets in logs.
- Pin versions and image digests exactly in production deployment paths.
- A non-production conformance workflow may resolve one closed official OS slug
  and current Debian packages only when it is isolated from production, records
  the resolved provider image ID and exact installed package versions in closed
  schema-validated evidence, and re-admits their expected Debian provenance.

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
- Product Dockerfiles are never duplicated here.
- `activity-hash-chain worker: exactly one`.
- `scheduler: exactly one`.
- Migrations are explicit and run exactly once, never from an entrypoint or
  health check.
- The edge owns TLS and public routing; product containers do not expose public
  TLS.
- CrowdSec belongs at the public edge.
- PostgreSQL and private file storage require explicit backup contracts.
- Valkey never replaces PostgreSQL as the source of truth.

## Communication

- Keep GitHub-facing communication in English.
- Do not add AI attribution, generated-by wording, or AI co-author trailers.
- Report exact commands and their results.
- Never describe a check as successful unless it actually ran and passed.
