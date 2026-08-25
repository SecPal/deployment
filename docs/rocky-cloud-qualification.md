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
