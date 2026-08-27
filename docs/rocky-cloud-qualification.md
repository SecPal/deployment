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
Issue #67 elevated `one authoritative definition per semantic invariant` to an
explicit invariant, and #72 required replay of reviewed real-system evidence
because repository-authored fixtures cannot prove external representation
compatibility by themselves. PRs #63, #66, #73, and #74 are the implementation
and review history for those findings.

The current Rocky planning retained those lessons but sequenced them
incorrectly. #117 states that the #64/#68 layer and purity lessons are reusable,
while also sequencing their reapplication only after current semantic evidence.
Issues #120, #121, and #122 then scope the explicit layer/purity hardening to
issue #119 workload evidence. That left #118 host/preparation evidence able to
recreate the same structural failure mode before the later hardening work could
apply.

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
document does not redefine them. They apply before further #118 host evidence
and are not optional follow-up hardening reserved for #119.

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
