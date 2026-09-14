<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Rocky ephemeral-cloud qualification

The current cloud qualification path is a separate Rocky Linux 10.2 contract.
The Debian 13 workflow and evidence remain historical conformance contracts;
their image discovery, APT, package provenance, and AppArmor semantics are not
inputs to Rocky admission.

## Trust boundary

The workflow commit on `main` owns provider authentication, the closed profile,
image discovery, OpenTofu, resource ownership and TTL, SSH rotation, host
preparation, continuation admission, evidence admission, and cleanup. The
current target is the GitHub-verified protected-main #269 merge
`c76742c828fefd71dda2b2d73fda6a0c43969426`; its target-owned production
harness has SHA-256
`436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac`.
The pair is independently enforced by the trusted workflow, target runner,
diagnostic classifier, schema, and repository agreement checks. The target is
fetched by the guest only after every GCP service account has been detached and
access to the metadata credential endpoint has been blocked.

The current harness digest is derived reproducibly from immutable Git bytes
with `git show c76742c828fefd71dda2b2d73fda6a0c43969426:scripts/qualify-production-host.sh | sha256sum`.
The pre-extension target
`b76c24fe59fbe2406d8b84094fc9e6694c57f0c6` and its original harness digest
`f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c`
remains an exact historical binding, including the #233 failure from run
`34876534431/1`. The earlier target
`539d5faa6549be62060c8e20028caf200e5eca01` has that same historical harness
digest but remains historical authority only. Sharing harness bytes does not
allow either target identity or trusted-control identity to be mixed with a
different binding.

The trusted-control SHA for a new lifecycle is the protected-main workflow
commit itself, derived from `GITHUB_SHA`; it is not a workflow input or an
unmerged candidate constant. The canonical #270 merge commit establishes the
initial rebound authority triplet with the current target and harness. A later
protected-main workflow commit derives its own trusted-control identity and can
inherit that pair only while the repository agreement gates remain unchanged.
Continuations bind the exact control SHA that created them. The unconsumed #234
authorization bound to control `a4a4ff415f01421af4f3ddfe0a3542815df42414`,
the pre-extension target, and its historical harness therefore cannot be
consumed by the current authority.

The failed native #234 target/harness pair
`b8f5a505d318d06a64a5975cfaba9f1e5ba0041f` /
`918c992aad9c937fa2639cd345adc849784344574c44da3d7e3dfeb01bd770fa`
remains authenticated historical diagnostic evidence and cannot select a new
qualification.
Preparation run `34716436412` passed, and the one authorized qualification run
`34716784934` failed at `qualify-quadlet-authority / invariant-failed`. Its
admitted failure artifact has SHA-256
`d811a190ae6beb48f85562a1536e57910a5f3d2275095e36c76a2aaa178bb2a2`;
the bound 162 diagnostic bytes have SHA-256
`b41e05e0a6d722b4a824aa71e7c71b5da4dfd3143a4d26033cc59fc4b011bc59`.
The matching cleanup completed with empty retained provider state. Repository
fixtures reproduce the disagreement but do not replace that native evidence,
and #254 performs no provider qualification.
The earlier `293977ae93408a7bb812619de58649ab8a92d438` /
`8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db`
pair and older retained identities remain historical evidence bindings only;
they cannot select current qualification. The earlier target SHA may select
only `destroy` for its exact retained continuation and OpenTofu state. Trusted
cleanup admits that continuation and its matching target before obtaining
provider authority, and it never executes target-owned bytes.

The qualification runner job has no environment, `id-token` permission, WIF
action, provider token, or credential file. It generates an Ed25519 key locally
and publishes only its public key and runner `/32`. Trusted control rotates the
guest key and firewall, verifies the exact retained instance and ownership
metadata, detaches cloud identity, and publishes only the resulting public IP.
The private key never leaves the uncredentialed runner process.

Compute Engine's normal IPv4 resolver and metadata API share
`169.254.169.254`, but they are different security channels. Google requires
that address as the [VM nameserver](https://cloud.google.com/dns/docs/vpc-name-res-order),
while [metadata endpoints](https://cloud.google.com/compute/docs/metadata/overview)
are exposed over HTTP and, for supported Shielded VMs, HTTPS. The guest-owned nftables policy therefore
admits only UDP/TCP port 53 to that exact address and rejects every other
protocol and port to it. The instance service account remains detached, no
credential environment or file reaches target execution, and the target still
proves that the metadata token endpoint is unavailable before resolving
`github.com` and fetching the one exact public repository and target SHA. No
alternate resolver, source mirror, or Git retry is part of the contract.

GCE DHCP documentation also describes an NTP-server option at the metadata
address. The current SecPal target-source and host-qualification contract does
not consume or admit that service, so UDP port 123 remains rejected by the
guest policy; this leaf does not create a time-service dependency.

## Closed profile and image handoff

The closed selector contains exactly two reviewed Rocky profiles. Both fix
Google, `secpal-dev`, `europe-west3`, `europe-west3-a`, one guest, and one
120 GiB `hyperdisk-balanced` disk:

- `gcp-rocky-10-2-arm64` binds `c4a-standard-4`, native `aarch64`, and the
  official `rocky-linux-cloud/rocky-linux-10-arm64` discovery family.
- `gcp-rocky-10-2-x86-64` binds `c3-standard-4`, native `x86_64`, the
  `x86-64-v3` baseline, and the official
  `rocky-linux-cloud/rocky-linux-10` discovery family.

Both families are discovery inputs only. Callers select a reviewed profile
identity, never a profile path, image family, machine type, architecture, or
fixture child.

The discovery operation calls the exact family endpoint through WIF and emits
the returned image name, immutable self-link, provider architecture, creation
timestamp, family, profile, and trusted control SHA. OpenTofu has no image data
source and accepts only an immutable self-link matching the selected profile.
Guest admission separately requires `ID=rocky`, `VERSION_ID=10.2`, and the
profile-bound `uname -m`. The exact target harness additionally admits
`x86-64-v3` on `x86_64`; an official family or machine that cannot satisfy these
facts fails closed rather than changing the qualification contract.

## Lifecycle and retention

The workflow exposes exactly four operations:

- `discover` performs read-only image resolution and creates no state or resource.
- `provision-and-prepare` creates one exact run, removes cloud identity, prepares
  and reboots the guest, admits preparation evidence, and retains the run for no
  more than three hours.
- `qualify` accepts only the exact, unexpired continuation, rotates access, runs
  the target harness only after its digest matches trusted control on the
  identity-free guest, admits its bounded evidence, and then destroys the exact
  saved state.
- `destroy` accepts the exact continuation, including after expiry, solely to
  destroy its saved state.

The continuation binds repository, trusted control SHA, target SHA, provider,
profile, immutable image, instance ID and name, zone, originating run and
attempt, expiry, and exact state artifact. Instance names, prefixes, or
operator-selected resource IDs cannot resume a guest.

Provider `RUNNING`, identity-free restart completion, and the public access
handoff are not guest qualification readiness. Each admitted boot invalidates
prior readiness, installs the current public SSH authority, completes the
trusted idempotent startup path, and only then atomically publishes a bounded
guest-owned record. The record binds the current boot, target, trusted control,
qualification run and attempt, cloud-identity absence, and public-key digest.
Preparation evidence that linger and `runtime.systemd_user` were true on an
earlier boot is not current-boot readiness. Before publication, trusted startup
waits for three independent current-boot observations: active
`user@<runtime-uid>.service`, a socket at `/run/user/<runtime-uid>/bus`, and a
successful non-mutating direct runtime-user `runuser --user secpal-runtime --
env -u CONTAINER_HOST -u CONTAINER_CONNECTION … systemctl --user
show-environment` query. The guest wait is limited to 60 seconds, five-second
cadence, and 13 probes; it never runs the target-owned `daemon-reload`.
Exhaustion publishes no successful readiness: the existing marker carries a
bound negative state that the canonical waiter classifies as
`runtime-user-manager`, `runtime-user-bus`, or `runtime-user-control` with
`not-ready-timeout`.
The uncredentialed target job uses that exact key in a bounded authenticated
probe cadence. Trusted control admits the current-boot record and all three
exact-true runtime-user facts, observes installed packages, and only then
fetches the target revision. The fetched harness executes only when its digest
matches the harness in trusted control. Transport, authentication, missing or
stale state, target disagreement, and binding failure remain separate closed
outcomes.

The exact target harness remains the reviewed workload definition, while
trusted control owns invocation and remains the sole authority for PASS. The
trusted workflow supplies its harness SHA-256 to the root-owned runner, which
requires the fetched target harness to match before invocation. No second
installed harness copy is needed. Trusted control maps only finite reviewed
error messages and Bash failure call sites to a
closed negative diagnostic. That diagnostic can only stop qualification; it
cannot supply or replace success evidence. Unknown, ambiguous, or unbound
failures remain `qualification-harness/unclassified-target-failure`. The
transport retains only the operation, closed reason, exit status, run bindings,
and bounded diagnostic-input hash and length—not target stdout or stderr.

For the immutable line-638 Quadlet start, trusted control closes the formerly
opaque `runuser -> env -> systemctl --user start` boundary without modifying
the target harness. The trace redirects only that exact call through
root-owned `/opt/secpal-control/libexec/rocky-start-runuser`; the runtime-user
steps use root-owned absolute `/usr/bin/env` and `/usr/bin/systemctl` helpers.
The trace matches the immutable argv directly and opens root-owned FD 6 only
for the root helper from a fixed root-owned evidence path; no observation path
is exported into the harness environment. The target harness and its earlier
children never inherit the descriptor. The helper writes one at-most-2,048-byte
closed JSON observation to its root-owned mode-0600 file and closes the
descriptor before any fallback. Runtime-user
Python starts in isolated mode, so user site packages and Python environment
settings cannot become protocol writers. A helper precondition or pre-dispatch
representation failure records only diagnostic unavailability and falls back
to the original operation, so diagnostic code cannot replace the operation it
observes. No exported marker or DEBUG-trap state authorizes helper dispatch, so
a completed operation cannot redirect a later runtime-account call. A post-dispatch
diagnostic failure retains the completed operation's original status without
repeating it.

The admitted start operations distinguish `runuser` exec and invocation,
`env` exec and command exec, `systemctl` exec and user-manager request, and a
service job failure. Facts are limited to the outer `runuser` status, the
`systemctl` client status and, only after a nonzero client result and a
successful bounded `systemctl show`, `Result`, `ExecMainCode`, and
`ExecMainStatus`. A request failure is admitted only when that bounded property
observation succeeds without a failed service result; an unavailable property
observation creates no request/job precision. Service `ExecMainStatus` is never
represented as an executable or client status. Missing, malformed, oversized,
or contradictory observations retain the target status as
`qualify-quadlet-start/diagnostic-unavailable`; no stdout, stderr, environment,
or journal text enters evidence.

The immutable line-639 active-state check has a separate, identically bounded
observer. Only the exact `runuser -> env -> systemctl --user is-active --quiet`
call is redirected through root-owned
`/opt/secpal-control/libexec/rocky-active-runuser`; absolute, root-owned
runtime-user helpers invoke the real `/usr/bin/env` and `/usr/bin/systemctl`
with the original arguments and return the original status. Its fixed
root-owned evidence path is not exported into the target. Root FD 7 exists
only during that exact call, and its at-most-2,048-byte observation contains
only the outer runuser and systemctl client statuses plus a closed process
stage. Trusted admission distinguishes runuser exec/invocation, env
exec/command-exec, and systemctl exec/request failures; missing, malformed,
oversized, or contradictory observations remain
`qualify-quadlet-active-state/diagnostic-unavailable`. The active-state
observer does not change service state, retry the request, or weaken the
target-owned active predicate.

The primary workload call uses the same direct-argv model without an env or
Podman shim layer. The root-only router admits the exact immutable `runuser`
and Podman argv, starts `runuser` with only fixed `PATH` and `LC_ALL`, and calls
the root-owned runtime helper by absolute path. The runtime helper admits the
runtime UID/GID and exact Podman request, discards Podman stdout, preserves
bounded stderr only as transient target output, and emits two closed protocol
records. The outer router retains at most 512 protocol bytes and never replays
the workload after dispatch. Its observation file is selected internally by
one fixed absolute path rather than an inherited environment value. Failure
evidence contains only closed runuser,
environment-preparation, Podman, or OCI/runtime identities and numeric status.

Target stdout and trace consumers retain one byte beyond their admitted limits
while continuing to drain both streams to EOF. Overflow therefore fails
representation admission without closing the producer pipe, imposing a file
limit, or replacing the original target status. A target exit status of zero is
representable only for the closed post-success rejection decisions that the
trusted admission code can emit; schema and classifier reject every other
zero-status identity. The runner's own negative exit remains a separate truth.

Success admission invokes absolute `/usr/sbin/ausearch --input-logs ... -i`
with a strictly parsed C-locale two-digit-year date and time in separate argv
fields. Interpreted audit records must match that exact selected locale and
mode rather than a raw or different-locale grammar. Its concurrent
stdout and stderr drainers retain only 65,536 and 4,096 bytes. A bounded retry
admits only the tool's exact normal no-match representation while auditd makes
the just-completed event visible. A well-formed status-0 snapshot with no exact
candidate also retries; malformed, overfull, ambiguous, warning-bearing, or
other status-1 output fails closed. Only blank lines and the interpreted
format's `----` separator may appear outside typed records. Admission accepts
only the interpreted audit timestamp grammar, correlates by the full timestamp
and serial, and requires one unique event containing exactly one matching AVC
and one decoded PROCTITLE marker. The marker must name the digest-bound harness's
exact in-container `/foreign/marker` path; the AVC must carry the exact source context,
target context, `permissive=0`, and `tclass=file`. Duplicate, malformed,
oversized, unavailable, or ambiguous audit observations fail closed without
entering evidence.

When that admission returns no candidate, the target can now emit one
schema-version-1 AVC-correlation diagnostic projection before cleanup. The
projection is produced by `selinux_isolation_contract`, the existing admission
owner, and contains only closed comparison results, bounded record and candidate
counts, admitted context and MCS values when needed, event identity, PIDs, and
the observed byte count and digest. It distinguishes absent AVCs, each required
AVC-field mismatch, invalid PID, absent/mismatched/duplicate PROCTITLE and
SYSCALL records, event parse or separation failures, multiple candidates,
malformed or oversized input, normal `ausearch` no-result status, and true
capture execution error. It contains no audit record bytes, command output,
journal, environment, provider response, SSH material, or exception string.

Trusted control accepts that projection only for
`qualify-avc-correlation / command-failed / 3` and wraps it in failure schema
version 3. Before writing an artifact, the classifier validates its closed
shape and semantics with the owner contract. `rocky-control.py` then
independently checks the target, control, run, and harness bindings; canonical
projection length and SHA-256; component, event, context, MCS, and event-ID
bounds; duplicate-key-free outer JSON; and recomputed rejection, candidate,
and final-outcome consistency. The target publishes the projection and returns
status 3 through the exact AVC trace stack, keeping the closed
`qualify-avc-correlation / command-failed / 3` classification reachable. A
caller-selected final reason or a diagnostic that identifies an admitted
candidate cannot grant authority. The diagnostic family remains negative-only
and cannot enter success admission.

The exact historical failure artifact from run `34876534431/1`, artifact digest
`sha256:f461479cd43791aa8c1f31034e1af0ea68c8e7b9687ce6878af6be30ed5a2852`,
contains schema-version-1 JSON with SHA-256
`7e19cdf446ed44dde82a45cc6b73fe96e3717f84f7f027788f0d847c124af492`.
It proves only the bound operation, reason, exit status, and its 85-byte
diagnostic-input digest. It has no AVC-correlation projection, so the destroyed
guest's rejecting predicate is unrecoverable. Historical validation preserves
that artifact exactly; it does not infer or retrofit missing native audit
bytes.

Post-target cleanup uses only absolute commands with fixed environment,
ten-second per-command timeouts, and 4,096-byte stdout/stderr drain bounds. The
Podman observer runs from exactly `/home/secpal-runtime` after validating the
runtime UID/GID, owner traversal, and the root-owned non-writable `/home`
parent. Any timeout, overflow, exec failure, residue, or invalid working
directory prevents PASS. Raw start, active, primary, and reload observations
are removed on every runner exit after their bounded facts have been admitted.

For a current `qualification-harness / representation-invalid` result, trusted
control inventories the seven classifier components before that removal:
stdout, trace, trusted marker, reload adjacency, start observation, active
observation, and primary observation. The existing diagnostic hash remains the
authority and continues to cover those components in that order with one NUL
between each pair; its byte count remains the sum of component bytes without
the separators. Schema-version-2 failure evidence carries exact original bytes
only for components independently admitted under their finite producer grammar
or closed observation schema and semantic state machine. Closed start, active,
and primary observations may use any legal JSON whitespace, member order, or
terminal-newline representation; formatting is not authority, and the retained
digest always covers the original bytes rather than a canonical rewrite.
Duplicate keys, extra properties, invalid or contradictory states, arbitrary
payloads, and malformed or oversized inputs remain unavailable. The target
trace admits only complete newline-terminated records from the bounded numeric
producer grammar. Each producer record retains its own status; replay admission
does not relax the classifier's separate aggregate-status coherence rule. If
any component is unavailable, the witness records only its presence, length,
digest, and unavailable state. It never exports that component or presents the
partial inventory as replayable. The independent verifier
decodes the retained bytes, recomputes every available component digest and
length, reruns the grammar/schema and semantic admission, then closes the
aggregate hash and classifier result. This negative-only witness cannot enter
the success evidence path. Historical schema-version-1 failures and unavailable
schema-version-2 witnesses under their exact earlier trusted-control identities
remain immutable and cannot be mixed with the current family.

The destroyed #118 guest retained only outer target status 126 at line 238.
That proves neither a service `ExecMainStatus` nor which process produced 126.
Later native ARM64 and GCP controls passed, and deterministic real-process
probes cover each reachable producer without reproducing a current functional
defect. Because the original guest retained none of the new adjacent facts,
its machine-local cause is `HISTORICAL_INSTANCE_ROOT_CAUSE_UNRECOVERABLE`, not
a presumed transient failure. A future occurrence identifies the remediable
owner in one bounded failure artifact.

The historical #118 `qualify-selinux-storage-fcontext-add` call site at line
250 retains its exact Rocky 10.2 `semanage` diagnostic schema for immutable
historical evidence. The active target uses private relabeling and has no
reachable fcontext-add, restorecon, or matchpathcon source mapping. Presenting
one of those stale mappings as current, mixing a historical target with the
current harness, or supplying an unrecognized pair therefore fails closed.

The trusted Bash trace uses `SECPAL_TARGET_ERR_V2`: each record carries one
numeric inner-command status and at most eight numeric `BASH_LINENO` frames.
The records must agree on that status. It may differ from the final target
process status only for the reviewed AVC observation path that records an
expected inner denial with status 1 before its bounded no-finding path returns 3. The classifier binds that transition to its exact immutable outer call
frames; other status mismatches fail closed. It ignores generic helper
implementation frames and resolves only immutable reviewed outer call sites
under the exact target and harness hashes. Repeated frames agreeing on one
operation are one decision; conflicting statuses, zero mapped operations,
conflicting operations, or conflict with an explicit reviewed message remain
fail-closed. V1 single-frame traces are not a current emission or validation
surface; historical artifacts retain only their already validated input digest
and length.

The exact harness helper audit assigns `read_os_release_value` and unconditional
uses of `run_as_service_account`, `rootless_podman`, and `user_systemctl` to
their semantic callers through that stack. Negated/conditional helper uses
already emit finite target messages when they reject, as does SELinux isolation
admission.
`cleanup` and cleanup-time helper calls are not primary target predicates;
trusted post-harness admission owns cleanup completeness. A generic helper is
never mapped directly because the same helper serves runtime, fixture,
Quadlet, workload, SELinux, AVC, fallback, and cleanup boundaries.

Normal and failure cleanup use `tofu destroy` against the saved state. The Rocky
janitor independently revalidates the complete ownership description or label
set immediately before each ordered deletion. A prefix is never ownership, and
ambiguous or changed metadata results in no deletion.

## Rocky preparation and evidence

Preparation admits only Rocky 10.2 with the selected native architecture, DNF4 releasever 10,
exactly `baseos`, `appstream`, and `extras`, disabled automatic update and reboot
timers, SELinux targeted and Enforcing, rootless Podman with crun, Netavark,
cgroup v2, systemd-user, seccomp, and no Podman socket or API dependency.

The application account is created through host-local system allocation. Its
effective UID, GID, and passwd-selected home are evidence, not global constants.
A deterministic allocator selects the first available aligned
65,536-entry subordinate-ID range that overlaps neither existing subuid nor
subgid ranges. The account has `nologin`, no sudo grant, no supplementary
privileged groups, linger enabled, and no write access to administrator Quadlet
authority.

Administrator preparation binds the user manager's effective
`QUADLET_UNIT_DIRS` to `/etc/containers/systemd/users/<runtime-uid>` through a
root-owned system-service drop-in. Before the qualification harness reloads the user
manager, it walks every component from `/` through that exact directory and the
fixture definition without following symlinks, admits root ownership and the
absence of group/other write permission, and independently proves that the
runtime account cannot write any component. It applies the same check to the
search-path drop-in and observes the effective manager environment, so default
user-writable Quadlet locations cannot replace the admitted input. After reload
and before activation, `quadlet_authority_contract.admit_quadlet_authority` owns
normalization and admission of the effective service representation. The target
observes exactly `FragmentPath`, `SourcePath`, `DropInPaths`, and `ExecStart`;
the owner admits the UID-bound generator and administrator source paths, no
drop-ins, and Rocky systemd 257's complete direct-Podman execution record,
including its safe argv and inactive execution metadata. It emits bounded,
canonical evidence through the closed qualification schema. Trusted control
loads the same root-owned owner, revalidates that evidence independently, and
requires byte-identical target and trusted normalization. A shadowing user unit,
user-owned override, rootful or wrong-UID path, generated argv drift, unsafe
network or privilege setting, or changed systemd execution metadata therefore
fails closed.

The account UID/GID must be nonzero before preparation changes it. Qualification
then admits Podman's effective rootless report and binds both the invoking
process and the active Quadlet unit's main process to that exact account. The
running Quadlet container supplies `/proc/1/status`; one admission function
requires effective UID/GID `65532:65532`, `NoNewPrivs: 1`, zero inherited,
permitted, effective, bounding, and ambient capability masks, and `Seccomp: 2`.
The Quadlet requests these values, but only the observed process state satisfies
qualification.

The fixture input is the immutable Alpine 3.22.1 multi-platform index
`sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1`;
preparation records exactly the selected architecture child: ARM64
`sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192`
or amd64
`sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f`.

Discovery, preparation, continuation, and qualification use separate closed
JSON schemas with `additionalProperties: false`. Preparation is not native
qualification: SELinux process/storage contexts, MCS separation, the unique
enforcing cross-MCS AVC, seccomp workload behavior, and cleanup PASS are
populated only by the trusted-control copy after byte agreement with the exact
target revision's harness. `selinux_isolation_contract.admit_selinux_isolation`
is the single normalization and admission owner consumed by the target harness,
closed schema projection, and trusted validation; the target and controller
bind the canonical normalized result by SHA-256. Before root execution, trusted
control also requires the fetched target copy of that owner to be byte-identical
to its root-owned installed copy. The outer harness deadline retains 180 seconds
after signalling, exceeding the 150-second sum of all cleanup command bounds.

### Host-evidence responsibility and ownership map

The Rocky preparation transport installs two components. The collector owns
only bounded host observation and orchestration. The separately transported
`rocky_preparation_contract.py` owns pure normalization, pure admission, and
closed evidence assembly. The latter imports no process, filesystem, network,
environment, or clock capability. A single transported script would not permit
these responsibilities to collapse.

| Evidence concept                          | External representation / observation owner                                    | Normalization and authoritative admission owner                                                                            | Assembly / schema / independent validation                                                                 | Diagnostic operation family                                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Immutable run, target, and image identity | workflow inputs and exact image self-link                                      | pure Rocky preparation contract                                                                                            | pure assembly; preparation schema; `rocky-control.py`                                                      | `admit-immutable-shas`, `admit-provider-image`                                                                             |
| Guest OS and architecture                 | `/etc/os-release`, `uname` through the collector observer                      | pure OS parser and `admit-guest-identity`                                                                                  | pure assembly; preparation schema; trusted controller                                                      | `read-os-release`, `query-architecture`                                                                                    |
| DNF and enabled repositories              | bounded `dnf4`/RPM observations                                                | pure repository parser and update/repository admission                                                                     | pure assembly; preparation schema; trusted controller                                                      | `query-dnf-version`, `query-releasever`, `query-enabled-repositories`                                                      |
| Installed package provenance              | bounded RPMDB/DNF observations, one reviewed package key at a time             | pure exact NAME/EPOCH/VERSION/RELEASE/ARCH/NEVRA, repository, signature, payload, architecture, and Podman-range admission | pure assembly; preparation schema; trusted-controller agreement validator                                  | closed `query-`, `resolve-`, `inspect-`, `normalize-`, and `admit-package-*` operations                                    |
| SELinux and container labeling            | `getenforce`, `selinuxenabled`, `sestatus`, and bounded container config reads | pure SELinux and label-configuration admission                                                                             | pure assembly; preparation schema; trusted controller                                                      | `query-selinux-*`, `read-container-config`                                                                                 |
| Service account and subordinate IDs       | passwd/group databases plus bounded subuid/subgid reads                        | pure account, range, cardinality, and overlap admission                                                                    | pure assembly; preparation schema; trusted controller                                                      | `resolve-service-account`, `read-subuid`, `read-subgid`, identity operations                                               |
| Rootless Podman/runtime boundary          | bounded Podman JSON, systemd, cgroup, socket, and environment observations     | pure Podman normalization and runtime admission                                                                            | pure assembly; preparation schema; trusted controller                                                      | `query-podman-*`, `query-systemd-user`, `query-cgroup-filesystem`                                                          |
| Immutable architecture fixture identity   | Podman's complete bounded `.RepoDigests` representation                        | `rocky_preparation_contract.admit_fixture_identity` is the sole semantic owner                                             | preparation delegates through the same contract CLI; pure assembly; preparation schema; trusted controller | `inspect-fixture-repo-digests`, `normalize-fixture-repo-digests`, `admit-fixture-arm64-child`, `admit-fixture-amd64-child` |
| Reboot and hardware persistence           | boot ID, CPU, memory, and root filesystem observations                         | pure representation normalization and persistence admission                                                                | pure assembly; preparation schema; trusted controller                                                      | `read-boot-id`, `query-cpu-count`, `read-memory-info`, `query-root-filesystem`                                             |
| Cloud-identity absence                    | identity-transition marker and closed environment facts                        | pure cloud-boundary admission                                                                                              | pure assembly; preparation schema; trusted controller                                                      | `query-cloud-identity-marker`, `query-environment-authority`                                                               |

Every fallible collector operation is selected from `ObservationOperation` and
emits only a closed layer, operation, reason, and, where applicable, a reviewed
package or unit subject. The failure schema rejects command text, arbitrary
stdout/stderr, URLs, environment material, and unreviewed subjects. The trusted
controller independently validates the diagnostic before the preparation shell
publishes it. The workflow exposes only those bounded fields.

`scripts/validate-rocky-evidence-architecture.py` is the pre-provider gate. It
rejects forbidden capabilities in pure surfaces, opaque observer calls,
duplicate declared invariant ownership, semantic four-layer collapse, a
multi-domain collector without its reviewed coherent contract, fixture
admission outside the authoritative owner, and diagnostic operations absent
from the closed schema. Mutation tests prove each guard is live. The workflow's
non-OIDC validation job runs this gate before any job with provider identity or
OpenTofu resource authority can start.

## Historical evidence-architecture findings and binding lesson

The Rocky implementation must not treat the historical Debian cloud work as
irrelevant merely because Debian/APT/AppArmor semantics are obsolete. The old
track already identified a reusable architecture failure mode that is independent
of operating-system semantics.

Historical issue #64 identified that `collect-workload-evidence.py` combined
side-effecting collection, representation normalization, provenance checks, and
admission in one large module; that the same semantic contract was restated
across collector, schema, independent validator, static validator, tests, and
documentation; and that tests could pass one layer without proving that an
accepted real representation crosses the complete evidence boundary. Historical
issue #67 elevated one authoritative definition per semantic invariant to an
explicit invariant. Issue #68 owns pure layer-boundary enforcement from that
design, while #72 required replay of reviewed real-system evidence because
repository-authored fixtures cannot prove external representation compatibility
by themselves. PRs #63, #66, #73, and #74 are the implementation and review
history for those findings.

The earlier Rocky rebaseline retained the historical lessons but allowed the
host/preparation evidence path in #118 to be implemented before equivalent
structural protection became binding. Issues #120, #121, and #122 remain scoped
to #119 workload evidence, so they did not protect #118 from recreating the same
structural failure mode. Current #117 identifies #64/#68 and PRs #73/#74 as
reusable design evidence and current #117 requires explicit observation,
normalization, admission, and assembly ownership before further #118
real-provider qualification. Current #150 is the concrete architecture
prerequisite blocking #118 until that host evidence pipeline has enforceable
layered ownership.

The real Rocky remediation history demonstrates the recurrence. PR #145 and
PR #146 successively exposed and repaired adjacent unbounded preparation
failures;
PR #147 then had to add narrower diagnostics after real-provider runs reached
broad repository and fixture phases. PR #148 corrected fixture-child admission from
Podman's ambiguous singular `.Digest` representation to bounded exact
`.RepoDigests` membership. PR #149 was then required because
`collect-rocky-preparation.py` had independently reimplemented the same semantic
fixture-child invariant and still used the obsolete singular `.Digest`
predicate. Real run `33021568439` subsequently failed again only at the broad
`evidence-collection` boundary, with no bounded sub-operation identifying which
collector observation failed.

This history is therefore the source record for applying the organization-wide
`SecPal/.github/docs/evidence-architecture-contract.md` to deployment. That
canonical companion owns the resulting pipeline-responsibility,
invariant-ownership, representation, diagnosability, and anti-loop rules; this
document does not redefine them. Current dependency and scheduling decisions
remain exclusively in the native GitHub work graph; this historical record
explains the structural omission and does not prescribe issue order.

## Installed Rocky package provenance

Runs `33090958348` and `33093312770` independently reached the same
`download-official-package` boundary after installation and then failed during
the first of 22 post-install mirror transfers. Rocky 10.2 experiments showed no
deterministic selector, plugin, destination, architecture, or permission defect.
The repeated failure instead exposed an unnecessary availability dependency in
the evidence design: provenance of an installed artifact was being conditioned
on a second copy remaining downloadable from a live mirror later.

The admitted invariant is about the installed artifact, not current mirror
payload availability. For every reviewed package, evidence proves:

- its exact installed NEVRA;
- its RPMDB-observed NAME, EPOCHNUM, VERSION, RELEASE, and ARCH fields, with a
  canonical NEVRA reconstructed from those fields and bound to the requested
  package key;
- successful RPM verification of the preserved immutable installed header,
  including its RSA signature and SHA-256/SHA-1 header digests;
- the SHA-256 payload digest and algorithm stored in that signed header;
- the exact reviewed Rocky 10 signing-key packet and fingerprint; and
- exact current NEVRA membership in one of `baseos`, `appstream`, or `extras`,
  using repository metadata without transferring the RPM payload.

The admitted package architecture must equal the observed host architecture;
an exact `noarch` package is also valid on either admitted host architecture.
`x86_64` and `aarch64` are never interchangeable. Duplicate, missing,
wrong-key, malformed, or contradictory package observations fail at the named
normalization, admission, schema, or trusted-controller agreement boundary.

Podman runtime version has one source of truth: the VERSION field of the exact
admitted installed `podman` RPM. Native admission accepts `>= 5.8.2` and
`< 6.0.0`; the separately bound RPM epoch remains part of the exact NEVRA. It
rejects a malformed version, a lower version, or 6.0.0 and newer. `podman
--version` text and fixture input are not admission authority.

Immediately before target checkout or workload execution, the existing
root-owned controller runner re-observes this package/RPMDB contract and binds
it to the exact target SHA, trusted-control SHA, qualification run and attempt,
Rocky 10.2 identity, and host architecture. Collection failures use the
existing closed collection diagnostic contract. The controller then fetches
the target and requires its harness digest to match the trusted workflow copy
before execution. The harness reports only target-workload success. Only the
controller combines that result with its retained observation and independently
validates exact equality; candidate-authored evidence cannot match the
authenticated binding. Generic schema validation confirms representation only and cannot
promote a caller-authored document, `classification` label, or equivalent field
into native evidence.

RPM v4 immutable regions preserve the original signed header when
installation-specific fields are added, specifically so installed metadata can
still be verified. Header signatures cover the main header, while the
`PAYLOADDIGEST`/`PAYLOADSHA256` tag is in that header. See the upstream
[immutable-header description](https://rpm.org/docs/4.19.x/manual/hregions.html),
[RPM v4 format](https://rpm.org/docs/6.0.x/manual/format_v4.html), and
[signature/digest ranges](https://rpm.org/docs/6.0.x/manual/signatures_digests.html).

The reviewed Rocky 10.2 representation is exercised against RPM 4.19.1.1 and
DNF4 4.20.0. A single `rpm -qvv` read returns NEVRA, payload digest and
algorithm, SHA-256 header digest, and RSA header signature while RPM verifies
the same installed header. Admission requires the closed Rocky `OK` markers;
exit status alone is insufficient because a missing key can produce `NOKEY`
with status zero. A copied RPMDB with its key removed is rejected, and a
byte-mutated immutable header produces `BAD` and non-zero status. The installed
Rocky public-key packet is decoded and matched by exact SHA-256 to the reviewed
full fingerprint rather than trusting a display string.

Actual transaction characterization also established the limits of auxiliary
DNF facts. A package installed by the current reviewed transaction records a
reviewed `from_repo`, while a package already present in the official base image
may retain an opaque image-build repository identifier. DNF documents
`from_repo` as empty when history is unavailable and exposes repository checksum
and installed-header checksum on different package representations; see the
[DNF Package API](https://dnf.readthedocs.io/en/latest/api_package.html).
Transaction history is therefore supporting evidence only. Default
`keepcache=False` removes downloaded RPMs after a successful transaction, and
even `keepcache=True` cannot provide the artifact for an unchanged base-image
package; see the
[DNF configuration reference](https://dnf.readthedocs.io/en/latest/conf_ref.html).

| Architecture                                          | Provenance and artifact binding                                                                                                                              | Availability and applicability                                                                     | Decision |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | -------- |
| Post-install re-download                              | Compares installed signed-header facts with a later mirror copy, adding temporal equality but not stronger evidence about the installed artifact             | Adds 22 live payload transfers and fails when a current mirror payload is unavailable              | Rejected |
| RPMDB immutable header plus exact repository metadata | Directly verifies the installed artifact's preserved signed header, exact NEVRA, payload digest, reviewed signer, and current reviewed-repository membership | No post-install payload transfer; applies equally to base-image and transaction-installed packages | Selected |
| Retained DNF transaction artifacts                    | Verifies the transaction's downloaded files                                                                                                                  | Does not cover unchanged base-image packages; adds cache ownership and stale-artifact semantics    | Rejected |
| Pre-staged transaction bundle                         | Can bind installation to staged files                                                                                                                        | Retains the initial availability dependency and adds bundle lifecycle and substitution surfaces    | Rejected |

A same-NEVRA artifact published later by a mirror is a different temporal
observation. The selected contract admits the installed artifact only when its
own immutable header verifies under the reviewed Rocky key. It does not claim
that today's mirror payload is byte-identical, and losing that comparison does
not weaken provenance of what is installed. The architecture gate rejects any
collector mutation that restores a post-install `dnf4 download` observation.

## Post-merge evidence

Repository validation cannot claim provider success. After this trusted control
plane is reviewed and merged to `main`, the outstanding evidence is WIF-backed
image discovery, exact Rocky ARM image resolution, one real
create→prepare→observe→destroy lifecycle (or its bounded retained continuation),
and the later target-owned native ARM qualification. Missing protected authority
or provider availability remains outstanding and must not be simulated.
The reviewed custom role must first be reconciled to include the bounded list
permissions used by the Rocky janitor; that IAM change is not performed by PR
validation.

The first real `provision-and-prepare` run (`32944693955`) created the exact
run-owned infrastructure but failed closed before identity mutation: Compute
represented the reviewed empty bootstrap scope set as an omitted/null field,
while the original Rocky validator required literal object equality. Exact-state
cleanup destroyed all seven resources. That run produced neither preparation
PASS nor native ARM qualification PASS.
