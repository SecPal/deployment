<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Capacity and resource-quality capability contract

## Purpose and ownership

This document defines the public provider-neutral capability vocabulary used
to admit self-hosted hardware and to qualify current provider products. The
canonical machine-readable contract is
[`schemas/capacity-qualification.schema.json`](../../schemas/capacity-qualification.schema.json).
The capacity qualification contract consists of that versioned schema, the
strict admission validator, and the reviewed probe manifest at
[`config/capacity-probes-v1.json`](../../config/capacity-probes-v1.json). The
schema owns structural vocabulary, evidence shape, and directly expressible
floors. The validator owns cross-field, trust-binding, freshness, and admission
invariants. The probe manifest owns the exercised workload and storage demand.
Schema validation alone never establishes PASS. This document explains those
semantics without creating a second definition.

The model keeps five infrastructure truths independent:

```text
capacity_profile + compute_isolation + cpu_architecture
                 + storage_capability + topology
```

A capacity profile is a SecPal workload envelope. It is not a provider's vCPU
and RAM advertisement, a product name, a customer size, or a scaling rule.
Compute isolation describes scheduling and physical-host exclusivity, not size.
CPU architecture describes the executable platform, storage capability
describes persistent filesystem behavior, and topology retains the semantics
owned by ADR-022.

## Initial capacity profile

Schema version 1 defines only `M`. The identifier was selected from the small
ordered `S`/`M`/`L`/`XL` vocabulary because the repository has a defensible
first production planning envelope but does not yet have evidence for a lower
or larger envelope. `S`, `L`, and `XL` are not accepted placeholders. Adding
one requires measured workload evidence and a reviewed schema revision; a
provider product cannot introduce one implicitly.

For PASS, `M` requires the contract-owned floors below:

| Dimension                        |                                                                                          `M` requirement |
| -------------------------------- | -------------------------------------------------------------------------------------------------------: |
| Effective CPU scheduling ceiling |                                               4,000 millicores after affinity and effective quota limits |
| Online logical CPUs              |                                                                                                        4 |
| Guest/host-usable memory         |                                                                                                    8 GiB |
| Persistent storage capacity      |                                                                                                  100 GiB |
| Free persistent storage          |                                                                                  20 GiB and at least 20% |
| Total/free inodes                |                                                                1,000,000 / 200,000 and at least 20% free |
| Sustained workload observation   |          At least 600 seconds, one completed iteration, no failed iteration, deadline miss, or OOM event |
| Workload headroom                | At least 30% CPU is concurrently delivered and 30% memory is concurrently held while the workload passes |

The CPU value is the trusted effective scheduling ceiling after affinity and
cgroup quota limits, not a claim that a shared hypervisor continuously delivers
that nominal entitlement. Sustained delivery is proved separately by the
reviewed workload below. Usable memory is the effective host/guest/cgroup
limit after reservations. Advertised provider values alone cannot fill either
field. These are conservative admission floors derived from the current
four-CPU, 8-GiB, 100-GiB, and one-million-inode planning envelope. They are not
empirically proven universal workload minima, customer sizing, or an assertion
that every workload fits `M`.

## Reviewed workload and storage probes

The checked-in probe manifest is the authoritative v1 instrument. Each probe
revision is the SHA-256 of its probe object serialized as UTF-8 JSON with sorted
keys and compact separators. The workload and storage objects are hashed
independently, so an unrelated target or controller commit cannot silently
change either instrument.

One `secpal-capacity-workload-v1` iteration is a controller-timed continuous
600-second SecPal acceptance scenario with a 630-second outer deadline. During
it, the trusted controller, rather than target output:

- samples target-cgroup CPU usage and memory peak;
- reads target-cgroup OOM event counters;
- counts completed/failed iterations and deadline misses from process status
  and controller monotonic deadlines;
- runs a CPU-bound sibling cgroup requesting 30% of the effective CPU ceiling
  and proves that the requested CPU time was actually delivered throughout the
  iteration; and
- touches and holds a 30% memory reservation throughout the iteration.

The target executes reviewed operations and may return operation results, but
those results are explicitly non-authoritative. PASS requires the observed
target peak plus the concurrently delivered/held reservation to fit within the
effective CPU or memory value. A contended shared guest therefore fails when
the controller cannot deliver the reservation or the target misses its
deadline; low target CPU use cannot masquerade as headroom.

Each workload iteration includes five controller-timed
`secpal-capacity-storage-v1` cycles on the same qualified persistent
filesystem. A cycle has a 120-second deadline and comprises 256 PostgreSQL
synchronous-commit transactions with 4-KiB payloads plus a 64-MiB private-file
write, file `fsync`, atomic rename, directory `fsync`, read, and digest check.
The controller counts cycles and deadlines and verifies the returned data. Raw
IOPS, throughput, and p95 `fsync` observations remain unclassified facts, but
they must be arithmetically capable of the reviewed cycle. Thus v1 creates no
named performance tier while a 1-byte/second or one-day-`fsync` device cannot
qualify.

## Compute isolation

The closed vocabulary is:

- `shared`: CPU scheduling entitlement is shared with unrelated tenants;
- `dedicated-vcpu`: the virtual CPUs have a dedicated entitlement while the
  physical host may remain shared; and
- `dedicated-host`: the complete physical host is exclusive to the operator.

Each claim carries a matching evidence basis. A self-owned bare-metal machine
can therefore qualify as `dedicated-host` without naming a provider. Neither
`dedicated-vcpu` nor `dedicated-host` implies a larger capacity profile. Both
`M/shared` to `M/dedicated-vcpu` and `M/shared` to a future `L/shared` are
conceptually valid changes for different bottlenecks.

## CPU architecture

`amd64` and `arm64` are independent of capacity and isolation. An `amd64` PASS
requires the current host-contract baseline `x86-64-v3` or a compatible higher
level. An `arm64` PASS records native `arm64`. Effective vendor and model facts
remain evidence; they do not create architecture-specific capacity profiles.

Qualifying one current ARM or x86 provider product proves only that exact
subject and evidence window. It is not a recommendation for every deployment
of that architecture.

## Storage capability

Version 1 defines one functional capability, `persistent-posix`. PASS requires
persistent `ext4` or `xfs` storage, effective `fsync`, and either `local-block`
or `network-block` attachment. This admits self-hosted disks and provider block
storage through the same contract while keeping the backing semantics visible.
It does not treat equal disk capacity as equal storage quality.

Qualification records random read/write IOPS, sequential read/write
throughput, and p95 `fsync` latency from the independently revision-bound
storage probe. Version 1 deliberately defines no IOPS, throughput, latency
class, or provider tier: current evidence does not justify one. Admission only
checks those measurements against the concrete reviewed cycle above.
PostgreSQL and private-file storage consumers can retain the raw facts for
later reviewed profiles. Provider marketing tiers cannot stand in for them.

Backup, replication, and HA durability remain separately owned contracts.
`persistent-posix` does not claim that one device survives host loss or that a
backup exists.

## Topology and orthogonal infrastructure

The capability document uses exactly ADR-022's `single`, `replacement`, and
`ha` topology vocabulary. Topology is never encoded in `M`, and selecting `ha`
does not change what `M` means. A topology may need several independently
qualified nodes, but it cannot aggregate them into one larger per-node PASS.

Capacity is also independent of Edge Policy and Network Identity. DNS,
`secpal.cloud`, CloudFront, AWS WAF/AMR, `PROTECTED`/`DIRECT`, floating or
reserved addresses, endpoint switching, customer domains, and Managed rollout
policy are outside this contract. A deployment can therefore state:

```text
capacity_profile = M
compute_isolation = dedicated-vcpu
cpu_architecture = amd64
topology = single
edge_policy = PROTECTED
```

without Edge Policy changing the meaning of any capability field.

## Qualification evidence and provider mapping

The schema and validator consume the existing cloud-conformance evidence
architecture rather than creating a second orchestration system. The trusted
controller supplies one separately schema-validated source-evidence file. It
owns effective observations, target process status, monotonic deadlines,
cgroup measurements, provider catalog observation, and cleanup status. The
qualification artifact must reproduce its capability, subject, and
observations exactly and bind the SHA-256 of the supplied source bytes.

Admission also requires trusted expected target SHA, controller SHA, hashed
target identity, workload-probe revision, and storage-probe revision. Those
values must agree independently across trusted inputs, source evidence, the
qualification artifact, and the checked-in probe manifest. A tested target can
execute operations but cannot omit these trusted inputs, author authoritative
observations, refresh their observation time, or publish its own PASS.

These identities are deliberately independent:

```text
tested target SHA
!= trusted controller SHA
!= workload probe SHA-256
!= storage probe SHA-256
```

A provider-backed subject records a bounded provider name, the current catalog
product ID, catalog observation time, a digest of the catalog record, and a
hashed immutable target identity. The durable relationship is:

```text
provider-neutral capability
        -> reviewed qualification evidence
        -> current provider catalog product
        -> PASS / FAIL / UNAVAILABLE / UNKNOWN
```

The product ID can be a Hetzner server line, AWS instance type, DigitalOcean
Droplet type, GCP machine type, or a future equivalent. It appears only under
`subject.provider_product`; the capacity field accepts only `M`. Renaming or
retiring a product changes catalog mappings and qualification evidence, not the
SecPal architecture.

A self-host subject omits provider data entirely. It binds the same capability,
trusted source evidence, workload and storage probes, identities, freshness,
and cleanup applicability to a hashed hardware identity. No commercial SKU is
needed and no trust requirement is relaxed.

PASS requires complete observations, exact agreement between claimed and
observed isolation/architecture, a current evidence window of no more than 30
days, and complete cleanup when the qualification run was ephemeral. Missing
observations, unknown status, stale evidence, a future catalog observation, or
incomplete cleanup cannot be admitted as PASS. `FAIL`, `UNAVAILABLE`, and
`UNKNOWN` remain valid evidence outcomes but do not qualify a subject.

Run strict independent admission with trusted expected identities and an
explicit decision time:

```bash
python3 scripts/validate-capacity-qualification.py \
  --evidence path/to/non-secret-evidence.json \
  --source-evidence path/to/trusted-source-evidence.json \
  --expected-target-sha '<40 lowercase hex>' \
  --expected-control-sha '<40 lowercase hex>' \
  --expected-target-identity-sha256 '<64 lowercase hex>' \
  --expected-workload-probe-revision '<64 lowercase hex>' \
  --expected-storage-probe-revision '<64 lowercase hex>' \
  --evaluation-time 2026-08-29T00:00:00Z
```

The validator strictly parses bounded UTF-8 JSON, rejects duplicate keys,
validates the repository schema and probe contract, recomputes the source
digest, and applies cross-field admission. It does not read the system clock,
query a provider, inspect a host, dispatch qualification, or perform cleanup.

## Current provider qualification boundary

The active `gcp-rocky-10-2-arm64` selector and `c4a-standard-4` machine type
remain bounded #118/#123 provider-run inputs and architecture evidence. They
are not `capacity_profile` values and are not a universal ARM recommendation.
Existing evidence predates this schema and does not retroactively qualify `M`;
[provider replay #123](https://github.com/SecPal/deployment/issues/123) can
assemble this artifact from its reviewed real-system observations
when that leaf runs. No provider run is dispatched by this contract delivery.

[provider adapter contract #169](https://github.com/SecPal/deployment/issues/169)
may later request the public `capability` object and resolve it through a
currently qualified adapter/catalog mapping. Provider choice, customer or fleet
placement, scaling thresholds, procurement, cost, margin, reserve, automatic
downscale, regions, and SLAs remain private Managed Operations policy. No
customer inventory, provider credential, payment state, or mutable production
state belongs in qualification evidence.
