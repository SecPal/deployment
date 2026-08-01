<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment roadmap

The phases below are acceptance-driven. They do not imply dates or releases.

## Phase A — Governance bootstrap (current milestone)

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

## Phase B — Local container integration stack

**Goal:** Prove local API/frontend integration from pinned source revisions.

**Expected artifacts:** A test-only local orchestration contract, pinned build
inputs, health checks, explicit service roles, and local integration tests.

**Entry criteria:** Phase A is complete and the Step A absence contract is
deliberately updated through a regular pull request.

**Completion criteria:** The local stack validates API/frontend integration,
singleton roles, private data services, and a test-only TLS gateway without
public exposure or production secrets.

**Deferred:** GHCR, immutable public images, a production edge, public exposure,
and production operations. This phase is not complete.

## Phase C — Immutable image publishing

**Goal:** Define reproducible publication and consumption of product images.

**Expected artifacts:** Version and digest contracts, provenance policy, image
signing policy, and publication verification.

**Entry criteria:** Phase B proves the product integration contract.

**Completion criteria:** Published artifacts are immutable, verifiable, and
bound by digest with no `latest` dependency.

**Deferred:** Public reference deployment and managed-hosting automation.

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
