<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Native PostgreSQL qualification authority

The maintained `rocky-cloud-qualification.yml` workflow has one closed
`native-postgresql-18` selector for deployment#81. It composes frozen #80 host
admission with a separate PostgreSQL claim. Neither the #119/#126 application
fixture nor this qualification environment is production infrastructure.

The trusted workflow must already be accepted on protected main before it can
qualify a PostgreSQL candidate. The prerequisite implementing this interface
has no real-system completion claim of its own. Its repository fixtures prove
admission behavior, not Rocky/PostgreSQL conformance.

## Candidate and execution boundary

Dispatch accepts the selector, one of the two existing Rocky profiles and the
existing lifecycle operation/continuation identity. PostgreSQL dispatch rejects
a caller-selected target SHA. The accepted controller reads the unique open,
same-repository, main-based primary PR closing #81, authenticates every commit's
GitHub verification (`verified=true`, `reason=valid`), and binds the exact HEAD,
tree, configuration blob and consumer blob. Ambiguous, missing, forked, changed
or incorrectly linked sources fail before provider authority.

The fixed GitHub query selects only Ready and Draft lifecycle events. Pure
`normalize_lifecycle_timeline` treats timeline `totalCount` as provider metadata,
independently requires `hasNextPage=false`, and bounds returned selected nodes at 100. It rejects unknown fields, malformed nodes and other event types before
`select_candidate` enforces zero Draft transitions and zero Ready events for a
Draft candidate or exactly one for a Ready candidate. Other connections retain
their strict count checks. Reviewed GitHub representations in tests remain
fixtures; they establish no qualification PASS.

The candidate supplies `config/production/postgresql-contract.json`, including
its actual `configuration` file bytes. The accepted pure contract rejects
unknown/duplicate keys and admits only the reviewed canonical configuration
forms. SQL, HBA, nftables and systemd text must exactly match those forms; this
is not an arbitrary text execution interface. The sole substitution is a
validated local numeric runtime UID. Package version/release are bounded PG18
Rocky Application Stream values and subsequently re-admitted against installed,
signed RPM observations.
The declaration also binds the fixed `application_runtime` identity owned by
accepted qualification authority. It cannot select another image or executable;
The #81 delivery consumes that same runtime for its native PostgreSQL application path.

`render-native-postgresql.py` consumes those same admitted bytes without host
mutation. Invoke it with isolated Python (`python3 -I`) and a numeric
`--runtime-uid`. The resolver requires its entrypoint and complete local import
closure to match accepted control bytes. A candidate cannot substitute its own
renderer or admission module. General production host construction remains #92;
this interface does not qualify a candidate-owned installer.

Accepted-main root code applies the exact admitted bundle, installs pinned
packages, initializes a fresh native database, places ephemeral test material,
starts the distribution service, and observes its effective state. Candidate
code never receives root, provider credentials, metadata capabilities, an
evidence-write capability or a choice of grader. A root-owned startup binding
captures exact instance/control/profile/access identities before frozen #80
blocks metadata HTTP. PostgreSQL execution does not reopen that boundary.

The existing GCP controller, image profiles, identity-free handoff, readiness,
TTL, concurrency, state ownership and cleanup remain authoritative. Source
confirmation runs without OIDC; provider provisioning consumes only its bound
artifact. No new provider or cloud-control path is introduced.

## Observation and admission

The canonical owner is
[SecPal's evidence architecture contract](https://github.com/SecPal/.github/blob/main/docs/evidence-architecture-contract.md).
Deployment independently enforces its invariants at this host boundary and
uses executable agreement tests. PostgreSQL package admission shares the
installed-RPM/signature primitive with Rocky admission; the frozen 22-package
host claim is unchanged.

Separate closed evidence binds source/control/probe, preparation and
qualification run/attempt, instance, architecture and the frozen host artifact
digest. Observations cover signed AppStream packages, native systemd/process
ownership, PGDATA modes/SELinux, loopback listeners, HBA rules, TLS material
ownership/labels, SCRAM password algorithms, role attributes/memberships and
positive/negative protocol, privilege, readiness and database semantics probes.
Only successful trusted execution and independent workflow admission support
PASS. Caller-authored JSON passing a local schema is never real-system proof.
Server TLS cannot detect a client that skips certificate verification.
Application observations therefore exercise the real PHP/PDO/libpq path,
including the application's production transport guard and actual failures for
wrong hostname, wrong CA and incorrect credentials. Plaintext and insecure
verification modes must be rejected by the application. Successful `psql`
connections cannot substitute for these client observations.

## Application identity and availability

The native qualifier fixes the existing SecPal API publication at source
`7da77556e7a4896940b6c50ccf6ba2c3fb9a8653` and immutable multi-architecture image
`ghcr.io/secpal/api@sha256:ac97416f3feac5c57204421059105389c9add2cfbcda1b063eadf4c6ad7647ab`.
Its accepted source already supports production `DB_SSLMODE=verify-full` and
`DB_SSLROOTCERT`, PostgreSQL-backed runtime state, and separate readiness and
liveness HTTP routes. The older #119 fixture image remains a separate accepted
fixture identity; it does not establish native application transport claims.

Before execution, the qualifier reuses the canonical anonymous OCI bundle
retriever and digest-pinned GitHub CLI. It verifies the signed index against
`SecPal/api/.github/workflows/publish-container.yml`, the exact source commit,
`refs/heads/main`, and GitHub-hosted execution. Both platform descriptors must
match the reviewed index; the pulled image must match the index, child digest,
OS and guest architecture. Caller-selected images, tags, PHP code and probes are
absent from the interface. Probe, bootstrap and verifier bytes are included in
the trusted harness digest.

Trusted probe construction boots the immutable application's actual Laravel
configuration and obtains its PDO connection. It records only closed transport
facts. Hostname and CA failures must come from certificate verification rather
than DNS or unrelated startup failure. Libpq defaults, service files, `PGOPTIONS`
and URI/test overrides are cleared before application boot; an adversarial
environment scenario verifies that they cannot replace the intended policy.

Readiness setup runs only the immutable application's cache, queue and tenant
key migrations, once under separate migration authority. Its real tenant setup
and scheduler heartbeat establish the prerequisites for `/health/ready` using
runtime DML authority. This minimal run-bound state qualifies readiness; it is
not production setup or the broader application integration fixture.

The qualifier starts the real FrankenPHP application with the reviewed API UID,
tmpfs, read-only filesystem and narrow pasta mapping. Independently collected
HTTP status/body observations require readiness and liveness with PostgreSQL
available, readiness `503/not_ready` during PostgreSQL loss, retained
`200/alive` liveness, and restored readiness after PostgreSQL restarts. The
application PID must remain unchanged. A `sleep` process or container-running
flag cannot satisfy the HTTP observations.

Synthetic application keys, KEK and DB passwords are private, run-owned test
inputs. Passwords and application keys enter PHP process memory through a fixed
read-only bootstrap, not environment variables, command arguments or evidence.
Runtime containers never mount migration credentials. No production #100
material is generated or consumed.

The rootless client uses the maintained digest-pinned disposable PostgreSQL
fixture image only for client commands. No database server container runs.
Pasta's explicit host-loopback mapping is address-wide, so a runtime-UID
nftables output boundary admits only PostgreSQL TCP 5432 and rejects other
loopback traffic. A real listening sentinel on another port exercises that
boundary. Gateway mapping and host networking remain absent. See the
[upstream pasta manual](https://passt.top/builds/latest/web/passt.1.html).

Synthetic certificates/passwords belong only to this exact ephemeral run.
Product containers receive a client CA and runtime credential, never a server
key or CA private key. Private test signing material is deleted after issuance.
Production generation, delivery, rotation and recovery remain #100.
The five stable privilege roles are `NOLOGIN`. Qualification issues separate
run-bound, expiring runtime and migration test logins with SCRAM credentials.
HBA matches membership in the stable runtime/migration groups. Runtime inherits
only runtime privileges; migration must explicitly `SET ROLE secpal_owner` for
DDL. Membership admission includes the `ADMIN`, `INHERIT` and `SET` options;
test identities and expiration are independently observed from PostgreSQL.
See [PostgreSQL role grants](https://www.postgresql.org/docs/18/sql-grant.html)
and [HBA group matching](https://www.postgresql.org/docs/18/auth-pg-hba-conf.html).

Subprocess output is bounded while it is collected, both streams are drained,
and timeout/overflow terminates the exact command group. Evidence contains
fixed non-secret facts and statuses, not arbitrary process output or passwords.
Failure artifacts have closed semantic operation/reason plus observed source,
resource, host and run bindings; unobserved source/host facts are explicitly
null and cannot establish PASS. A failure before observer construction still
emits a diagnostic; a null resource is admitted only for an initial admission
failure with no observed source/host binding or completed guest cleanup.
Trusted transport retrieves and independently
admits failures before enforcing the unsuccessful outcome.

Guest cleanup verifies the exact client container and nft table absent, native
service stopped, run-created PGDATA and test/server/client material absent and
in-memory credentials forgotten. It also removes the exact application probe
container, its run-owned image and private image-verification state, and verifies
their absence. In the cloud workflow, control-plane cleanup then destroys only
exact run-owned ephemeral resources and verifies provider absence. Guest cleanup
is separate from provider cleanup. Both cloud architecture runs must succeed and
complete that provider cleanup before a cloud real-system claim is admitted.

## Validation and lifecycle

`scripts/validate-postgresql-qualification.py` checks the deployment-specific
agreement with canonical evidence authority before provider dispatch. It runs
from the existing trusted validation job and local preflight. Focused tests are
`python3 tests/postgresql-qualification-contract.py`; full local validation
remains `scripts/preflight.sh` through the maintained Complete Validation owner.

Keep the existing discovery, provision-and-prepare, qualify and destroy
operations. Preparation authorization expires after at most three hours;
qualification freshly resolves the unique unchanged delivery before resuming.
Retain exact non-secret artifacts and successful hosted run/job identities,
including both provider cleanup results. Any changed candidate HEAD, consumer,
configuration, accepted control/probe or expired continuation invalidates a
pending run. Do not replay stale preparation or substitute repository fixtures
for a required system observation.

The guest consumes the PostgreSQL runtime closure and a closed source-digest
manifest. It does not execute the GitHub candidate resolver, reference SSH
controller or evidence schema validators. Those control-side files remain bound
by the same ordered SHA-256 source identity through the manifest; they are not
copied into the guest startup payload. Before mutation, the root observer verifies
all guest-required files against that manifest and compares the complete digest
to its root-owned candidate authorization. Evidence/schema admission remains on
the authenticated controller. Tests reconstruct the exact guest files and prove
manifest agreement without reducing the 16 KiB candidate allowance, 24 KiB
reserved headroom or byte-accurate metadata ceilings.

## Provider-neutral reference hosts

Issue #81 permits bounded reference-host evidence without GCP qualification.
The reference-host transport is `scripts/ci-cloud/postgresql-reference-host.py`;
it reuses the same source resolver, root PostgreSQL observer, application image,
SQL probes, RPM admission, substantive evidence schema and cleanup. Its two
closed profiles are `reference-rocky-10-2-amd64` and
`reference-rocky-10-2-arm64`. Actual runs on **both** architectures are required.
Contract fixtures establish admission behavior, never installed-host PASS.

The reference representation binds an exact machine ID, canonical SSH address
and Ed25519 host key instead of a GCP instance ID or frozen cloud-host artifact.
The same claim and fact schema admit this representation; a provider name is
neither required nor accepted as authority. OS observations must identify
Rocky 10.2 or a later Rocky 10.x minor, the declared architecture and effective
SELinux Enforcing. Runtime observations reuse the existing pure Rocky
admissions for rootless/local Podman, crun, netavark, seccomp, cgroup v2, an
active user service and absent runtime socket/API authority. The runtime account
must have no sudo or supplementary group authority. Package versions and
signatures remain separately pinned and admitted; accepting an OS minor does not qualify its PostgreSQL supply.

Private operational authority must first designate a disposable **clean** test
host, install the authenticated control bundle at `/opt/secpal-control`, prepare
the rootless runtime baseline, and provide host-specific restricted SSH access
for `secpal-cloud`. This repository does not provision a provider account or
host, select arbitrary commands, or expose a general remote-root installer.
The guest must contain no provider credentials or attached provider API
authority; SSH forwards none. Private provisioning must establish this before
the host is designated for qualification.
The operational `app.secpal.dev` / `api.secpal.dev` server, customer hosts, real
credentials and existing database state are excluded. Preparation must retain
private ownership and teardown authority outside product evidence.

The source resolver prepares one expiring candidate authorization in a private
operation directory. A mode-0600 target JSON contains only `machine_id`,
`address` and `ssh_host_key`. `prepare --architecture amd64|arm64 --run-id N
--reference-host TARGET --operation-directory DIRECTORY` discovers the fixed
candidate for #81 / #286, verifies signed commits and accepted control bytes, and
writes `prepared.json` and the exact `probe-manifest.json`. It performs no host
or provider mutation.

Separately authorized private provisioning delivers that exact prepared
artifact as root-owned mode-0600
`/var/lib/secpal-rocky/postgresql-candidate.json`, plus the exact root-owned
`postgresql-resource-binding.json` lease. The lease contains `control_sha`,
`profile`, `access_run_id`, `access_run_attempt` and `reference_host`, matching
the prepared authorization. It also prepares the existing root-owned `prepared`
marker, evidence directory and non-writable control/state hierarchy. It installs
`probe-manifest.json` as root-owned, non-writable
`/opt/secpal-control/postgresql-probe-manifest.json`. Runtime
accounts cannot alter these artifacts or qualification bytes. SSH authority
must expire with this lease and allow only the two fixed qualification commands;
it grants no fleet, production or reusable general root authority.

`run --identity-file KEY --operation-directory DIRECTORY --apply` reauthenticates
source/control and reserves the local one-use claim before any SSH call. SSH
ignores caller configuration, pins the exact host key, disables agent/password
interaction and forwarding, and bounds connection, output and runtime. The
root `--reference-host-check` command independently observes machine identity,
host key, OS and SELinux, and rejects PostgreSQL packages/data, running
containers, previous claims and existing SecPal material before mutation. Only
an exact matching lease/observation/qualifier digest permits the fixed root
`--reference-host` command. Its root-owned exclusive claim prevents reuse even
if a caller deletes local state. No candidate script or secret enters the guest.

The controller retrieves bounded evidence directly through that authenticated
execution, validates the existing schema and independently admits source,
control, run, host, architecture, packages, application identity, all substantive
probes and cleanup. It retains the observation separately before its final
candidate recheck and admission. There is no caller-file PASS command. Unknown
execution or cleanup state fails closed; bounded diagnostics are retained and
no unchanged strategy is automatically retried. Private host teardown is
separate from the required guest cleanup. A failed or unreachable host requires
its retained diagnostics and separately authorized cleanup, not another run.

This path requires independently authenticated accepted control containing the
reference transport; staging or authorizing candidate source alone does not
make candidate-local tooling a trusted grader or grant external execution.
No run is authorized by these instructions. The original cloud workflow and
its frozen #80 claim remain unchanged for separately authorized cloud work;
GCP dispatch and GCP PASS are not prerequisites for this reference-host claim.
Reference evidence grants no GCP/multi-provider qualification, Managed
Production Acceptance, HA or customer-production acceptance. Synthetic test
PKI proves protocol behavior and never substitutes for #100 production authority.
