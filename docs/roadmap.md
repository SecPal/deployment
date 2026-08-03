<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment roadmap

The phases below are acceptance-driven. They do not imply dates or releases.

## Phase A — Governance bootstrap (complete)

**Goal:** Establish a trustworthy public repository without deployment code.

**Expected artifacts:** Governance instructions, licensing and REUSE metadata,
scope and roadmap documentation, a local repository contract, deterministic
preflight checks, minimal quality CI, a signed initial commit, and protected
`main` governance.

**Entry criteria:** An empty public `SecPal/deployment` repository exists and
the maintainer has signing and repository-administration capability.

**Completion criteria:** Local checks pass; the single signed bootstrap commit
is on `main`; repository settings and branch protection are verified; no
deployment implementation exists.

**Deferred:** Every runnable stack, image, edge, secret, data-service, backup,
update, rollback, and production concern.

## Phase B — Local container integration stack (complete)

**Goal:** Prove local API/frontend integration from pinned source revisions.

**Expected artifacts:** A test-only local orchestration contract, pinned build
inputs, health checks, distinct app/API HTTPS origins, explicit worker roles,
shared disposable private storage, browser tests, and a hosted real-Compose
integration check.

**Entry criteria:** Phase A is complete and the Step A absence contract is
deliberately updated through a regular pull request.

**Completion criteria:** Static contracts and the real Compose lifecycle prove
Valkey queue/cache use, correct worker ownership, singleton cardinality, shared
private storage, separate frontend/API HTTPS origins, exact credentialed CORS,
Sanctum CSRF and secure-cookie behavior in Chromium, one migration, and full
project cleanup without public exposure or production secrets. The hosted
`Local Integration / Compose Contract` check must pass on the current pull
request head.

**Completion evidence:** Static repository and Phase B contracts passed. The
real Compose lifecycle passed with Valkey queue and cache probes, correct
general and hash-chain worker ownership, singleton cardinality, shared private
storage, separate app/API HTTPS origins, exact credentialed CORS, Sanctum CSRF
and secure-cookie behavior, Chromium CSP and service-worker checks, one
explicit migration, and complete project-scoped cleanup. The technical
implementation head passed `Local Integration / Compose Contract`, and that
check is enforced for `main`; every subsequent pull-request head must pass it
again.

**Deferred:** Frontend publication, a production edge, public exposure, tenant
provisioning, durable storage, and production operations.

## Phase C — Immutable image publishing (in progress)

**Goal:** Define reproducible publication and consumption of product images.

**Implemented:** API publication and the fail-closed API digest consumption
target contract are implemented. The public local integration contract pins
the verified SecPal API image by canonical OCI index digest, anonymously pulls
that digest, and requires its GitHub Artifact Attestation before API execution.
The current GitHub CLI still requires authentication, so the real token-free
integration stops at that gate and the phase remains incomplete.

**Expected artifacts:** Completed API and frontend version and digest
contracts, provenance policy, image signing policy, and publication
verification. Frontend publication remains outstanding.

**Entry criteria:** Phase B proves the product integration contract.

**Completion criteria:** Published API and frontend artifacts are immutable,
verifiable, and bound by digest with no `latest` dependency. The API half does
not complete the whole phase.

**Deferred:** Frontend publication, Phase D, public reference deployment,
production host automation, and managed-hosting automation.

## Phase D — Public Compose reference deployment

**Goal:** Provide a reproducible public self-hosting reference.

**Expected artifacts:** Compose orchestration, service dependencies, persistent
volume contracts, secret mounts, health checks, and operator guidance.

**Entry criteria:** Immutable image contracts exist.

**Completion criteria:** The reference deployment is reproducible and validates
all service-role, persistence, and secret-handling invariants.

**Deferred:** Final public-edge security and operational lifecycle automation.

## Phase E — Public edge, TLS, and CrowdSec

**Goal:** Define secure public ingress separate from product containers.

**Expected artifacts:** Selected edge configuration, TLS lifecycle, routing,
CrowdSec integration, and public-exposure tests.

**Entry criteria:** Phase D is stable and an edge technology has been selected
through a documented decision.

**Completion criteria:** Only the edge is public; TLS and CrowdSec contracts are
verified; product and data containers remain private.

**Deferred:** Full backup and update lifecycle automation.

## Phase F — Backup, restore, update, and rollback

**Goal:** Make public operations recoverable and safely maintainable.

**Expected artifacts:** Backup scope, restore drills, update sequencing,
migration procedure, rollback boundaries, and operator runbooks.

**Entry criteria:** The public reference deployment and edge are validated.

**Completion criteria:** Recovery and lifecycle procedures are repeatable,
tested, and preserve PostgreSQL and private-storage integrity.

**Deferred:** Customer-specific and private managed-hosting automation.

## Phase G — Private managed-hosting automation

**Goal:** Build private automation from the public technical contract.

**Expected artifacts:** Private inventory, credential, provider, and operations
automation outside this repository.

**Entry criteria:** The public contract is stable and operationally verified.

**Completion criteria:** Defined only in the authorized private repository.

**Deferred:** All private artifacts remain permanently outside this public
repository.
