<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Native Rocky qualification and retained cloud cleanup

The active GCP provisioning and qualification path is retired by the operator's
2026-11-08 decision. GCP and multi-provider portability (#123) are deferred, not
completed. The earlier #294 GCP evidence remains deferred, not successful.
No current workflow can discover/provision/prepare/resume a GCP test guest or
execute a GCP qualification target. No IAP, NAT, OS Login or KMS replacement is
introduced.

## Maintained native qualification

Rocky Linux 10.2+, AMD64/x86-64-v3 and ARM64, effective Enforcing SELinux,
rootless Podman/systemd/Quadlet, signed package provenance, PostgreSQL 18 with
TLS/SCRAM and distinct roles, and HAProxy/nftables/backend isolation remain
mandatory. The existing production host harness, native observers, reference-host
transport, closed admission and negative/failure/recovery/cleanup tests remain.

Accepted [#286](https://github.com/SecPal/deployment/pull/286) and
[#248](https://github.com/SecPal/deployment/issues/248) retain actual CX33/AMD64 and
CAX21/ARM64 evidence with their original source/host/artifact bindings. Reuse only
unchanged relevant evidence. Ubuntu CI and repository fixtures do not prove a
Rocky host result. No live host operation or requalification follows merely from
this source retirement. Existing dedicated hosts, identities, data and services
remain unchanged.

See [native PostgreSQL](architecture/native-postgresql.md),
[reference-host qualification](postgresql-qualification.md),
[product backends](product-backends.md) and
[production host](architecture/production-host.md). Their existing owners and
security boundaries are unchanged.

## Recovery remains available

External empty state has not been authenticated by this change. Therefore retain:

- The scheduled exact-owned DigitalOcean, legacy GCP and Rocky GCP janitors.
- The three pinned OpenTofu provider/lock roots under `infra/ci-cloud/`.
- Historical Rocky profile identities, continuation schemas and admission.
- The existing `rocky-cloud-qualification.yml` workflow, reduced to manual
  `destroy` of an exact retained continuation/state only.

Recovery accepts only protected-main control, a supported historical target,
profile and exact source run/attempt. It validates continuation/state ownership
before obtaining the existing cleanup OIDC identity. Native GitHub run/attempt,
original main workflow and verified source-commit ancestry are authenticated
independently of downloaded JSON. Fork, branch, source or signature substitution
fails before provider credentials. The independently admitted
run is reconciled, its saved OpenTofu state destroyed, and provider absence
checked independently; empty local state alone is insufficient. Expiry permits
cleanup, never renewed qualification. The current provider-only Rocky root has
no resources, modules, bootstrap or variable-driven provisioning.

No recovery operation was executed for retirement. Removing janitors/provider
roots or revoking actual provider roles requires independently authenticated
absence and discharged state/recovery obligations. Do not infer absence from
source deletion or TTL. The retained IAM-role document describes the existing
historical scope; retirement performs no IAM mutation or grant.

## Historical evidence

The former workflow, Terraform resources, metadata transport and bootstrap remain
in immutable [Git history at the pre-retirement head](https://github.com/SecPal/deployment/tree/bf6ec699f1ce28f13081f5d368bdd21996eb5b18).
Published schemas, original source/run identities and historical evidence are
preserved. Frozen native diagnostic/replay contracts remain valid for their
original observations; they do not authorize a new cloud lifecycle.

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
