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
preparation, continuation admission, evidence admission, and cleanup. A target
revision is accepted only as a full commit SHA. It is fetched by the guest only
after every GCP service account has been detached and access to the metadata
credential endpoint has been blocked.

The qualification runner job has no environment, `id-token` permission, WIF
action, provider token, or credential file. It generates an Ed25519 key locally
and publishes only its public key and runner `/32`. Trusted control rotates the
guest key and firewall, verifies the exact retained instance and ownership
metadata, detaches cloud identity, and publishes only the resulting public IP.
The private key never leaves the uncredentialed runner process.

## Closed profile and image handoff

`gcp-rocky-10-2-arm64` is the only current Rocky profile. It fixes Google,
`secpal-dev`, `europe-west3`, `europe-west3-a`, `c4a-standard-4`, one native
ARM64 guest, and one 120 GiB `hyperdisk-balanced` disk. The official
`rocky-linux-cloud/rocky-linux-10-arm64` family is a discovery input only.

The discovery operation calls the exact family endpoint through WIF and emits
the returned image name, immutable self-link, ARM64 architecture, creation
timestamp, family, profile, and trusted control SHA. OpenTofu has no image data
source and accepts only an immutable self-link matching the official Rocky ARM64
shape. Guest admission separately requires `ID=rocky`, `VERSION_ID=10.2`, and
`uname -m=aarch64`; an official family that has moved to another minor therefore
fails closed after provisioning rather than changing the qualification contract.

## Lifecycle and retention

The workflow exposes exactly four operations:

- `discover` performs read-only image resolution and creates no state or resource.
- `provision-and-prepare` creates one exact run, removes cloud identity, prepares
  and reboots the guest, admits preparation evidence, and retains the run for no
  more than three hours.
- `qualify` accepts only the exact, unexpired continuation, rotates access, runs
  the target-owned harness on the identity-free guest, admits its bounded
  evidence, and then destroys the exact saved state.
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
The uncredentialed target job uses that exact key in a bounded authenticated
probe cadence. Target revision code executes exactly once only after the
current-boot record is admitted; transport, authentication, missing/stale state,
and binding failure remain separate closed outcomes.

Normal and failure cleanup use `tofu destroy` against the saved state. The Rocky
janitor independently revalidates the complete ownership description or label
set immediately before each ordered deletion. A prefix is never ownership, and
ambiguous or changed metadata results in no deletion.

## Rocky preparation and evidence

Preparation admits only Rocky 10.2 with native `aarch64`, DNF4 releasever 10,
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

The prior Alpine digest was the architecture-specific `amd64` child. The Rocky
ARM input is the immutable Alpine 3.22.1 multi-platform index
`sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1`;
preparation also records the resolved ARM64 child
`sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192`.

Discovery, preparation, continuation, and qualification use separate closed
JSON schemas with `additionalProperties: false`. Preparation is not native
qualification: SELinux process/storage contexts, MCS separation, negative
cross-MCS access, AVC, seccomp workload behavior, and cleanup PASS are populated
only by the exact target revision's harness.

### Host-evidence responsibility and ownership map

The Rocky preparation transport installs two components. The collector owns
only bounded host observation and orchestration. The separately transported
`rocky_preparation_contract.py` owns pure normalization, pure admission, and
closed evidence assembly. The latter imports no process, filesystem, network,
environment, or clock capability. A single transported script would not permit
these responsibilities to collapse.

| Evidence concept                          | External representation / observation owner                                    | Normalization and authoritative admission owner                                | Assembly / schema / independent validation                                                                 | Diagnostic operation family                                                                   |
| ----------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Immutable run, target, and image identity | workflow inputs and exact image self-link                                      | pure Rocky preparation contract                                                | pure assembly; preparation schema; `rocky-control.py`                                                      | `admit-immutable-shas`, `admit-provider-image`                                                |
| Guest OS and architecture                 | `/etc/os-release`, `uname` through the collector observer                      | pure OS parser and `admit-guest-identity`                                      | pure assembly; preparation schema; trusted controller                                                      | `read-os-release`, `query-architecture`                                                       |
| DNF and enabled repositories              | bounded `dnf4`/RPM observations                                                | pure repository parser and update/repository admission                         | pure assembly; preparation schema; trusted controller                                                      | `query-dnf-version`, `query-releasever`, `query-enabled-repositories`                         |
| Installed package provenance              | bounded RPM/DNF/rpmkeys observations, one reviewed package subject at a time   | pure package normalization and repository/signature/payload admission          | pure assembly; preparation schema; trusted controller                                                      | closed `query-`, `resolve-`, `download-`, `inspect-`, and `verify-package-*` operations       |
| SELinux and container labeling            | `getenforce`, `selinuxenabled`, `sestatus`, and bounded container config reads | pure SELinux and label-configuration admission                                 | pure assembly; preparation schema; trusted controller                                                      | `query-selinux-*`, `read-container-config`                                                    |
| Service account and subordinate IDs       | passwd/group databases plus bounded subuid/subgid reads                        | pure account, range, cardinality, and overlap admission                        | pure assembly; preparation schema; trusted controller                                                      | `resolve-service-account`, `read-subuid`, `read-subgid`, identity operations                  |
| Rootless Podman/runtime boundary          | bounded Podman JSON, systemd, cgroup, socket, and environment observations     | pure Podman normalization and runtime admission                                | pure assembly; preparation schema; trusted controller                                                      | `query-podman-*`, `query-systemd-user`, `query-cgroup-filesystem`                             |
| Immutable ARM64 fixture identity          | Podman's complete bounded `.RepoDigests` representation                        | `rocky_preparation_contract.admit_fixture_identity` is the sole semantic owner | preparation delegates through the same contract CLI; pure assembly; preparation schema; trusted controller | `inspect-fixture-repo-digests`, `normalize-fixture-repo-digests`, `admit-fixture-arm64-child` |
| Reboot and hardware persistence           | boot ID, CPU, memory, and root filesystem observations                         | pure representation normalization and persistence admission                    | pure assembly; preparation schema; trusted controller                                                      | `read-boot-id`, `query-cpu-count`, `read-memory-info`, `query-root-filesystem`                |
| Cloud-identity absence                    | identity-transition marker and closed environment facts                        | pure cloud-boundary admission                                                  | pure assembly; preparation schema; trusted controller                                                      | `query-cloud-identity-marker`, `query-environment-authority`                                  |

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
- successful RPM verification of the preserved immutable installed header,
  including its RSA signature and SHA-256/SHA-1 header digests;
- the SHA-256 payload digest and algorithm stored in that signed header;
- the exact reviewed Rocky 10 signing-key packet and fingerprint; and
- exact current NEVRA membership in one of `baseos`, `appstream`, or `extras`,
  using repository metadata without transferring the RPM payload.

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
