<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## Unreleased

### Added

- The authoritative production persistence matrix, deterministic rootless host
  ownership mapping, fail-closed state/secret preparation, and checked native
  Quadlet bind declarations for PostgreSQL, application storage, and Valkey.
- Stable file-backed application, PostgreSQL, Valkey, and raw tenant-KEK secret
  contracts with atomic initial publication, bounded APP key history, exact
  consumers, explicit environment-free PostgreSQL initialization, negative
  mutation coverage, and leak-surface validation.
- A documented coordinated D.7 recovery boundary and durable Valkey AOF policy
  without adding backup jobs, live secrets, or a production deployment.

- A constrained native Quadlet renderer and rootless Podman/systemd-user
  lifecycle that transfer the disposable Phase B/C integration contract
  without rewriting its historical Docker/Compose evidence.
- Fail-closed static and lifecycle contracts for exact service roles,
  dependency health, one-shot migration, runtime security, registry policy,
  signals, parallel fixtures, stale state, and exact non-pruning cleanup.
- Real runtime inspection, browser parity, restart/persistence fixtures, and
  bounded non-secret resource observations in the active integration runner.
- A main-controlled, root-owned Quadlet fixture bridge for disposable cloud
  hosts. Its separate fixed install and cleanup requests admit only one closed,
  bounded filename set, snapshot regular files without following symlinks,
  retain exact root-side digests, serialize crash-resumable state transitions,
  publish only closed rejection reasons, bound the non-persistent trigger
  lifecycle and removal retries, keep untrusted staging read-only to root, and
  never execute target content as root.
- A manual, protected Debian 13 cloud-conformance workflow for an immutable
  full target SHA with separate credentialed apply, uncredentialed remote test,
  bounded evidence, and independent exact cleanup phases.
- A locked DigitalOcean OpenTofu root for one allowlisted Intel or AMD host,
  per-run Ed25519 access, deterministic ownership/TTL tags, and restricted
  ingress from the active runner.
- A fail-closed scheduled TTL janitor for expired, completely revalidated
  owned Droplets plus static mutation tests for credential, input, provider,
  SSH-state, metadata, cleanup, action-pin, and evidence boundaries.
- Schema-validated, failure-atomically published bootstrap-failure evidence
  with orchestration timestamps and bounded native-bootstrap diagnostics when a
  disposable host fails before the full conformance collector can run.
- Closed native-bootstrap package, kernel, reboot-continuation, and host-setup
  failure phases that identify the active failed phase without exposing logs,
  commands, or environment data.
- A common strict-Bash host payload delivered through DigitalOcean user data
  and GCP's native `startup-script`, with a root-owned, closed host-setup stage
  marker that diagnoses early failures without raw logs or credentials.

- A provider-neutral production host and inventory contract.
- A versioned, non-secret production inventory schema, a closed synthetic
  host-facts schema, and examples for both supported architectures.
- Fail-closed inventory and synthetic host-prerequisite validation without
  host access or production mutation.
- An exact Debian 13/trixie host identity and reviewed security-update, reboot,
  rootless Podman/Quadlet maintenance, and major-release lifecycle contract.
- A closed subordinate-ID, systemd user-manager, local Podman graphroot,
  runtime-API denial, and registry-redirection denial contract while preserving
  the historical Docker/Compose integration evidence.
- Effective runtime-package suite, mapping-helper, user-runtime-directory, and
  administrator-only Quadlet search-path evidence.
- Shared path-access admission for host policy and rootless runtime paths,
  explicit AppArmor enforcement evidence, and distinct host-name versus
  public-origin rules.

### Changed

- The Debian 13 fixture bridge now makes trusted service-pin augmentation part
  of the target-visible published snapshot, preserving the target's exact
  source-to-install comparison. The root installer independently ensures that
  the exact trusted service-pin suffix is present and last without duplicating
  it.
- The exact-target Debian 13 conformance protocol now implements its closed
  workload prepare and cleanup phases. Target code verifies and stages both
  product images before publishing the fixed root-owned Quadlet set through
  the trusted fixture client; the main-controlled collector remains the sole
  activator and evidence authority.
- Cloud-only one-shot units use direct reviewed process identities and retain
  their completed containers until exact cleanup, allowing the independent
  collector to bind one migration execution to Podman and systemd evidence.
- The active required integration workflow uses explicit Ubuntu 26.04 amd64
  and arm64 hosted evidence for Podman 5 and native Quadlet. The completed
  Compose workflow and stack remain historical evidence.
- Parallel Quadlet fixtures isolate Playwright output and last-run state by
  instance, and cleanup still removes the private fixture root when runtime
  resource verification itself fails.
- Runtime admission now requires effective cgroup v2, Aardvark DNS, and trusted
  runtime-component paths, while every generated container disables Podman's
  automatic host-proxy inheritance.

### Not included

- D.1a does not implement production orchestration, persistence, secrets,
  public edge, DNS, ACME/TLS lifecycle, CrowdSec, backup, update, rollback,
  provider provisioning, or other D.2+ work.

### Fixed

- Installed and admitted the required `catatonit` package in disposable Debian
  cloud hosts so D.1a runtime admission no longer fails before image staging
  because the required init binary is missing. The local integration runtime
  continues to require the same component.
- Corrected the disposable cloud host's root-owned Quadlet search-path policy
  filename to match the exact target admission path after DigitalOcean Intel
  run `31913150786` exposed the mismatch following successful `catatonit`
  admission.
- Cloud target-phase failures now retain one bounded diagnostic summary with
  the last closed runtime, attestation, dependency-image, gateway, Quadlet,
  host, or cleanup stage plus a closed failure reason and optional command
  status in the Actions log. Arbitrary target output remains private and is
  discarded before exact VM cleanup.
- Trusted Quadlet normalization now records one closed mode, substep, failure
  class, and optional command status in schema-validated evidence and its
  summary after DigitalOcean Intel run `31948450941` exposed an otherwise
  undifferentiated status `1`. Command output remains discarded.
- Trusted Quadlet normalization now skips absent exact units, admits the
  fragment, drop-in, dependency, environment, and lifecycle-hook provenance of
  every loaded unit before stopping it, and uses one admitted root-owned user
  environment generator so `daemon-reload` cannot regenerate units under a
  different manager environment. Reload or activation drift fails closed, as
  diagnosed independently by DigitalOcean Intel run `31954465244`.
- Trusted Quadlet normalization now distinguishes closed generator inventory,
  presence, file, content, and metadata failures as well as the separate
  post-reload and post-activation manager-environment read and admission
  checkpoints. Schema-version-3 evidence retains its legacy stage vocabulary
  for existing artifacts after DigitalOcean Intel run `31967061955` exposed
  that the former shared stages could not identify the failing checkpoint.
- Trusted Quadlet normalization now includes the fixed `USER`, `LOGNAME`, and
  `SHELL` login identity inherited by the user manager in its exact reviewed
  environment. It admits that complete set before generation and after reload
  and activation while still clearing mutable client overrides; DigitalOcean
  Intel run `31974004519` exposed the previously omitted fixed assignments.
- Generated-service admission now treats the exact user-manager environment as
  inherited state while the trusted root-owned fixture installer appends the
  exact `CONTAINERS_CONF`, override, modules, and `PODMAN_USERNS` execution-time
  pins to every Quadlet source. Container services additionally admit only the
  deterministic service name produced when systemd expands Quadlet's
  generator-owned `PODMAN_SYSTEMD_UNIT=%n`. DigitalOcean Intel run
  `31976423374` exposed the former impossible requirement that inherited
  manager assignments also appear in systemd's unit-local `Environment`
  property; every unreviewed unit-local assignment remains rejected.
- D.1a workload evidence admits the fixed root-owned Debian 13 GnuPG and
  OpenSSH agent socket/service pairs with exact `dpkg-query` owning-package
  provenance (including Keyboxd's Debian `gpg` ownership) while
  continuing to reject unknown units, user-controlled drop-ins or services,
  unexpected triggers, and every effective Podman API service, listener,
  connection, or process.
- Cloud cleanup now fails closed when the trusted fixture removal request is
  rejected or unavailable instead of treating that boundary as best effort.
- Updated the cloud-conformance evidence record after the first successful GCP
  Axion lifecycle, including verified absence of a VM cloud identity, bounded
  evidence publication, and exact cleanup. All three implemented provider/CPU
  profiles now have real successful foundation runs; the documentation keeps
  their differing tested target SHAs explicit.
- Aligned final GCP cloud-identity evidence with the already admitted bootstrap
  gate: Compute Engine returns HTTP 200 with an empty service-account directory
  when no identity is attached. The collector now admits only that bounded
  empty-body response, treats a non-empty body as identity presence, and fails
  closed on every incomplete or ambiguous probe without recording its body.
- Re-resolved and strictly admitted GCE's current public IPv4 only after the
  identity-removal stop/start completed. GCE can replace an ephemeral external
  address during that transition, so remote SSH no longer consumes the stale
  pre-stop OpenTofu output; missing, private, or ambiguous live addresses now
  fail closed before target execution.
- Prevented GCE's privileged default service account from reaching the
  disposable guest by explicitly attaching a dedicated role-free bootstrap
  identity with no API scopes. The native startup script defers all host-access
  setup until both identity absence and a trusted instance admission marker are
  observable, and a separately authenticated trusted
  control step stops the exact fixture, removes every service account, verifies
  the stopped and restarted states, and only then admits uncredentialed target
  execution. The project role still excludes `iam.serviceAccounts.actAs`; a
  separate resource-level binding permits it only for the inert bootstrap
  identity.
- Kept exact cloud-state artifact selection bound to the original validated
  resource attempt across GitHub failed-job reruns, rejected targeted provider
  reruns that could duplicate that identity, and bounded transient provider
  download retries to under six minutes before exact cleanup falls back to the TTL
  janitor.
- Authenticated the disposable host's current architecture-specific Debian 13
  kernel from refreshed signed APT indexes, then continued trusted setup after
  one state-bound reboot only when both the boot ID changed and the exact
  expected kernel was running. The continuation reconstructs restricted
  diagnostics, retains its provider-reentry guard until host setup commits, and
  then retires persistent state without adding production reboot automation.
- Kept the command-restricted diagnostic SSH service and its public-only inputs
  available across that authenticated reboot, while preserving the runner-IP,
  run-bound key, forced-command, and no-forwarding boundaries and removing all
  diagnostic state after trusted operator SSH commits. The service now creates
  its own runtime directories, starts before the reboot continuation, and keeps
  the closed failure channel available from initial state validation through
  the final operator handoff. A root-owned atomic selector now gives diagnostic
  and operator SSH complementary boot gates before either transition can race a
  reboot. An independent recovery unit restores that selector after an
  interrupted handoff, while the completion marker is published only after the
  operator listener is verified active and then prevents later recovery. The
  initial transition, operator handoff, and timed recovery now share one
  kernel-released, root-owned lock, preventing a timer expiry from racing the
  final listener verification and setup commit.
- Normalized disposable hosts to the exact Debian 13 Stable, Updates, and
  Security source set before package installation; corrected bounded APT
  provenance and merged-policy collection for real Debian output; and
  distinguished active Podman API listeners from stale socket files. APT list
  cleanup now preserves and runs under APT's own lock, unexpected release
  metadata fails closed, truncated listener scans cannot prove API absence, and
  the intentionally absent legacy APT source file no longer aborts collection.
  Kernel packages rotated out of current mirror indexes now fail closed instead
  of treating local dpkg state as proof of Debian origin, and only Netavark's
  exact network-proxy socket is excluded from Podman API listener detection.
- Kept guest-visible memory as exact cloud evidence without enforcing the
  previous unmeasured universal 8 GiB D.1 floor; inventories continue to carry
  an explicit positive memory requirement until workload evidence establishes
  a defensible minimum.
- Added an independent, delayed, command-restricted SSH diagnostic path for
  native-bootstrap failures, without exposing root or target execution.
- Deferred disposable-operator SSH-key activation until trusted host setup has
  finished, preventing remote bootstrap observation from racing subordinate-ID
  normalization while retaining bounded diagnostic access after setup failure.
- Fail-closed effective SSH-policy admission, a prioritized provider-independent
  drop-in, and username-scoped authorized-key publication before operator access.
- Closed alternate OpenSSH key and certificate sources, actual runner/listener
  `Match`-context admission, and persistently masked bootstrap SSH until that admission
  succeeds.
- Restrictive `0700`/`0600` SSH-key staging through atomic publication and an
  exact run-bound Ed25519 key-comment contract across the workflow and providers.
- Made diagnostic fallback preparation idempotent across partial installer
  failures, committed host readiness before opening operator SSH, and applied
  one absolute bootstrap deadline across host-key and operator readiness.
- Kept diagnostic unit staging private, made the closed failure reader usable
  by its forced command, and revalidated the complete effective SSH policy on
  initial activation and reboot, including deny/group gates, Ed25519 admission,
  and exclusive service-based activation.
- Published the root-owned diagnostic public key read-only so the restricted
  account can authenticate without gaining write access, and fail closed unless
  every published diagnostic artifact retains its exact ownership and mode.
- Kept manually dispatched cloud profiles in a bounded FIFO queue, opened the
  command-restricted diagnostic listener immediately after masking bootstrap
  SSH without disarming recovery until systemd received OpenSSH's listener
  readiness notification, restarted the unit to load every refreshed runtime
  configuration, preserved the same timer invariant during the final
  operator-SSH handoff, and derived closed host-key reachability counters from
  bounded TCP error codes instead of unstable scanner diagnostics for
  actionable, non-secret bootstrap evidence. Root-SSH denial now requires a
  successful operator transport recheck instead of parsing localized SSH
  error text.
- Kept both disposable SSH identities public-key-accessible by replacing Linux
  account locks with a verified impossible password marker, and made reboot
  admission revalidate the complete operator identity before trusting its
  persistent setup marker.

## 2026-08-08 - Consume Verified Frontend Image Digest

### Added

- A canonical SecPal frontend OCI index digest and fixed publisher identity.
- Anonymous frontend digest pull, raw OCI index and registry-header binding,
  and offline GitHub Artifact Attestation verification before container
  execution.
- Static, mutation, OCI, credential-isolation, lifecycle, update, and rollback
  contracts for Phase C.4.

### Changed

- Compose now consumes the verified public frontend image and no longer builds
  frontend source or accepts a frontend image override.
- The hardened image verifier receives explicit image, digest, repository,
  workflow, ref, source, signer, and registry-path identities for both API and
  frontend without weakening the existing API contract.
- The integration runner builds only the project-scoped test gateway after
  both published SecPal images have passed verification.

### Post-merge evidence

- Deployment PR `SecPal/deployment#6` merged as
  `4fc2796409b7c37a541f515ccf29236f143fc132`.
- Push-triggered Repository Quality run `31264563173` and Local Integration
  run `31264562902`, Compose Contract job `93120504279`, passed on `main`.
- The hosted integration run verified frontend OCI index digest
  `sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077`
  and API OCI index digest
  `sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e`
  before runtime, then passed the real Compose lifecycle, Playwright, and
  complete project cleanup.
- Phase C is complete. Phase D has not started.

### Not included

- Production deployment, registry writes, API digest updates, Phase D
  implementation, and public infrastructure remain outside this work.

## 2026-08-03 - Consume Verified API Image Digest

### Added

- A canonical SecPal API OCI index digest shared by all API-based roles.
- An anonymous digest pull and GitHub Artifact Attestation gate before any API
  execution.
- Static and lifecycle contracts for digest identity, signer identity,
  fail-closed ordering, credential absence, and temporary configuration
  cleanup.
- Reviewed digest update and rollback documentation.

### Changed

- The local integration runner builds only the pinned frontend and test
  gateway inputs; the API source-build and project-local API tag are removed.
- The public OCI Sigstore bundle and raw digest-matching index are retrieved
  through GHCR's anonymous Distribution flow. GitHub CLI verifies the private
  local index without reopening the registry.
- GHCR blob redirects use their real, tightly validated CDN path shape, and the
  verifier fixes `github.com`, removes inherited GitHub host and token inputs,
  logs the effective GitHub CLI version, and requires the attestation command.
- The anonymous API pull uses an empty private Docker configuration and removes
  inherited `DOCKER_AUTH_CONFIG` from the exact pull process.
- The hosted verifier uses the official GitHub CLI 2.97.0 release archive,
  pinned by its published SHA-256 checksum and enforced again at runtime.
- The one-shot migration uses Compose's explicit non-interactive mode so the
  same lifecycle runs without a TTY on hosted CI.

### Not included

- Frontend publication, Phase D, production host automation, real
  infrastructure changes, and production readiness remain outside this work.

## 2026-08-01 - Local Container Integration Stack

### Added

- A test-only Compose stack built from pinned API and frontend Git revisions.
- An API role, a scalable general worker, a dedicated hash-chain singleton,
  scheduler singleton, and explicit migration role.
- Private PostgreSQL and Valkey services pinned by version and digest.
- A loopback-only TLS gateway with separate app/API origins and a disposable
  internal CA.
- Runtime-only secret initialization and deterministic Phase B contracts.
- Isolated local test projects, image tags, and loopback ports with fail-closed
  process-group signal forwarding and cleanup.
- Port-aware SPA session configuration and immediate-peer proxy trust for the
  local TLS gateway.
- Compose scaling guards and instance-level validation for the singleton worker
  and scheduler.
- Rollback and automatic recovery for interrupted runtime-secret publication.
- Bounded automatic loopback-port reselection after bind collisions, strict
  Compose v2 validation, and absolute runtime-secret path enforcement.
- A shared sensitive-path contract covering tracked, untracked, and ignored
  repository paths.
- Valkey-backed cache and queue contracts with worker-specific runtime probes.
- Shared disposable private storage with cross-role visibility and permission
  checks.
- A real Playwright Chromium contract for CORS, Sanctum CSRF, secure cookies,
  runtime routing, CSP, and service-worker behavior.
- The `Local Integration / Compose Contract` hosted workflow for the actual
  Compose lifecycle.

### Not included

- No public deployment, production edge, GHCR publication, production secret,
  tenant provisioning, durable production storage, backup, update, or rollback
  automation is included.

## 2026-08-01 - Bootstrap Deployment Repository

### Added

- Repository governance and security boundaries.
- SecPal licensing and REUSE metadata.
- Architecture scope and acceptance-driven roadmap documentation.
- A local Step A repository contract and deterministic preflight validation.
- Minimal repository-quality CI without deployment execution.

### Not included

- No deployment, Compose, container, image, edge, secret, or production
  configuration is included.
