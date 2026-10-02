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

The candidate supplies `config/production/postgresql-contract.json`, including
its actual `configuration` file bytes. The accepted pure contract rejects
unknown/duplicate keys and admits only the reviewed canonical configuration
forms. SQL, HBA, nftables and systemd text must exactly match those forms; this
is not an arbitrary text execution interface. The sole substitution is a
validated local numeric runtime UID. Package version/release are bounded PG18
Rocky Application Stream values and subsequently re-admitted against installed,
signed RPM observations.

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
Server TLS cannot detect a client that skips certificate verification. The
negative insecure-client-mode evidence therefore belongs to candidate data
admission; protocol observations prove verified TLS and actual rejection of
plaintext, wrong hostname, wrong CA and incorrect credentials.

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

Subprocess output is bounded while it is collected, both streams are drained,
and timeout/overflow terminates the exact command group. Evidence contains
fixed non-secret facts and statuses, not arbitrary process output or passwords.
Failure artifacts have closed semantic operation/reason plus observed source,
resource, host and run bindings; unobserved source/host facts are explicitly
null and cannot establish PASS. Trusted transport retrieves and independently
admits failures before enforcing the unsuccessful outcome.

Guest cleanup verifies the exact client container and nft table absent, native
service stopped, test/server/client material absent and in-memory credentials
forgotten. The existing control-plane cleanup then destroys only exact
run-owned ephemeral resources and verifies provider absence. Guest cleanup is
not provider cleanup. Both architecture runs must succeed and complete their
provider cleanup before #81 claims real-system acceptance.

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
