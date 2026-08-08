<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Production inventory contract

## Purpose

The production inventory records provider-neutral operator inputs for one
future SecPal reference host. Its canonical schema is
[`schemas/production-inventory.schema.json`](../../schemas/production-inventory.schema.json),
while supplied observations use the separate closed
[`schemas/production-host-facts.schema.json`](../../schemas/production-host-facts.schema.json)
contract. The repository contains only synthetic examples. Inventory is not a
deployment workflow, source of image trust, secret store, or host-discovery
mechanism.

## Versioning and migration

Inventory and host-fact schema version 1 are selected by the exact integer
`schema_version: 1`. Unknown schema versions fail closed. Consumers do not
coerce old values, ignore new fields, or silently accept a future version. Any
incompatible schema change requires a reviewed contract change, positive and
negative fixtures, and reviewed migration notes that state how an operator
moves an inventory between versions. D.1 provides no implicit inventory
migration.

Duplicate YAML mapping keys are malformed input and fail before schema
validation. A later duplicate cannot replace an unsupported schema version or
any other reviewed value. YAML merge keys may only add non-conflicting fields;
a merge collision is a duplicate. Shared aliases are scanned once per object,
and recursive alias graphs fail deterministically.

The schema uses `additionalProperties: false` at every object boundary. A
field that is not explicitly reviewed is invalid, even when its value would
otherwise look harmless.

## Non-secret rule

Inventory must not contain secrets, credential material, private keys, tokens,
passwords, or real customer data. Recursive policy validation rejects
secret-looking field names, private-key markers, GitHub-token shapes, and
credential-bearing URLs before schema validation. An error never echoes a
classified field name, its value, or the whole inventory; it reports only the
safe parent location and violated invariant.

`backup.credential_reference` is an opaque reference beginning with
`external-secret://`. It identifies material held by a later approved secret
system; it is not the material. Secret generation, storage, rotation, and
recovery belong to D.2 (#10).

Actual production inventories must remain outside this public repository. The
checked-in example uses `example.invalid` origins and RFC documentation
addresses only.

## Image-identity prohibition

Inventory must not select image identities, registries, repositories, tags,
digests, child manifests, discovery inputs, fallbacks, or attestation policy.
Fields such as `api_image`, `frontend_image`, `api_registry`,
`frontend_registry`, `api_repository`, `frontend_repository`, `api_digest`,
`frontend_digest`, `image_tag`, and `registry_fallback` are forbidden at every
nesting level.

Official SecPal artifact identities remain reviewed repository code. The
inventory cannot weaken anonymous digest pulls, fixed publisher identity,
attestation verification, or fail-closed ordering.

## Field groups

### `host`

`hostname`, `architecture`, `public_address`, and `private_addresses` are
asserted facts that later collection must match. Architecture is exactly
`amd64` or `arm64`. The host-fact document separately requires the normalized
`ubuntu-server` installation profile; Ubuntu release identifiers alone do not
establish the supported server provenance. Public addresses must be globally
routable, except for reserved documentation addresses in synthetic examples;
multicast and deprecated IPv6 site-local ranges are never host addresses.
Public and private address comparison uses parsed IP identities, so equivalent
IPv6 spellings match while semantic duplicates fail. IPv4-mapped IPv6 values
are rejected rather than treated as native IPv6 host addresses. DNS hostname
comparison is case-insensitive; IP literals and legacy numeric IPv4 spellings
are not hostnames. Private addresses are limited to RFC 1918 IPv4 or IPv6 ULA;
documentation, benchmarking, link-local, and other non-global ranges are not
treated as private-use addresses. Private-address order is not significant;
duplicate or mismatched facts fail closed. Address facts must use YAML strings;
numeric or binary representations are not coerced. Clock synchronization is
mandatory and cannot be disabled. The validator does not call cloud metadata
or inspect a machine.

### `service_account`

The name, primary group, numeric UID/GID, absolute home, non-login shell,
interactive-login state, and Docker-authority state are explicit. UID/GID
values are strict YAML integers, are bounded, and cannot reuse known SecPal
runtime IDs. Integral floating-point spellings are not coerced for UID/GID,
path ownership, decision-issue, or resource fields. The account never carries
a credential in inventory. `root` is forbidden as either account or group
name. Supplied host facts report the effective UID, primary GID, and
supplementary GIDs resolved for the configured identity, as well as its name,
primary group, home, shell, interactive-login state, effective sudo
authorization, and effective host-privilege authorization. Identity and home
facts must match inventory. Shell and login facts must prove the non-interactive
policy; sudo and broader host privilege authorization must be absent. The broad
denial covers privileged supplementary groups and equivalent ACL, device,
capability, service-manager, or policy grants. The account must not inherit the
Docker socket group; the socket fact also requires an effective
connection-denial result so an ACL grant cannot bypass the numeric group
comparison. A separate closed SSH fact must prove that direct root login is not
permitted.

### `origins`

`frontend` and `api` are exact HTTPS origins. The frontend and API origins must
differ. Each uses a DNS name, default HTTPS port, and no userinfo, path, query,
fragment, empty delimiter, control character, localhost name, loopback address,
or IP literal. The scheme and optional `:443` spelling must be canonical;
parser-normalized alternatives fail closed. Origin separation preserves the
credentialed CORS, Sanctum, cookie, and proxy trust boundary.

### `paths`

Each path object records an absolute path, owner role, numeric identity when
already known, baseline directory mode, persistence class, and any later issue
that must decide the runtime identity or lifecycle. Paths must be normalized,
unique, mutually non-overlapping, non-empty, non-root, and outside `/tmp`.
They must not contain or be contained by the service-account home. Fixed
metadata cannot be changed by an operator. Version 1 confines SecPal state to
strict children of `/srv/secpal`, runtime secrets to a strict child of
`/run/secpal`, and the service-account home to a strict child of `/var/lib`.
The Docker data root is exactly `/var/lib/docker`; it is recorded in inventory
but is not an operator override. These namespace rules prevent a later owner or
mode operation from targeting system directories such as `/etc`, `/usr`, or
unrelated `/var/lib` trees.

Paths use UTF-8 byte limits shared by the supported ext4/XFS host model: at
most 255 encoded bytes per component and 4095 encoded bytes for the complete
path. ASCII control characters and character-count-only values that the target
filesystem cannot safely represent fail admission.

Known API private and public storage uses `10001:10001`; Docker data uses
`0:0`. Runtime secret, PostgreSQL, edge, ACME, and CrowdSec identities remain
explicitly delegated to their owning Phase D issue rather than guessed.

### `resources`

The inventory declares admission requirements, never lower limits than the
schema contract. CPU, memory, total storage, and total inode values are
compared with supplied facts. `resources.storage` contains only byte and inode
headroom observations. The separate closed `filesystems` fact group contains
path, filesystem, locality, `d_type`, and XFS `ftype` observations for every
persistent inventory path plus backup staging. This separation ensures that
configuration and deployment state are checked even though they have no
separate capacity floor. Passing the floor is not a capacity guarantee; the
evidence method is defined in the host contract.

### `backup`

Schema version 1 permits only an `external-filesystem` target descriptor, with
a synthetic operator identifier and external credential reference. It contains
no host, bucket credential, password, key, or backup implementation. Object
storage remains represented by a disabled feature gate and requires a reviewed
schema migration after D.2 and D.7 define its endpoint, secret, backup,
encryption, retention, and restore contracts.

### `features`

Required image verification is always enabled. Mail, OpenTimestamp, Bitcoin
quorum, address-data imports, Android push, Web Push, and object storage are
explicit feature gates fixed to `false` in schema version 1. They describe the
known dependency surface without authorizing it. Enabling any one requires a
reviewed schema migration after its documented dependency and later
secret/runtime contract are available; an inventory cannot opt into it early.

## Validation

Run the pure validator with an inventory and a supplied fact document:

```bash
python3 scripts/validate-production-contract.py \
  --inventory config/production/inventory.example.yaml \
  --host-facts tests/fixtures/production-host/valid-amd64.yaml
```

The validator reads only those two files and the two repository schemas. It does
not query DNS, the network, Docker, `/proc`, `/sys`, cloud metadata, or a
remote machine and does not change the filesystem.

Validation consists of:

1. recursive secret and supply-chain field rejection;
2. closed JSON Schema Draft 2020-12 structure and type validation for both
   inventory and host facts;
3. cross-field rules for origins, paths, ownership, feature gates, addresses,
   and fixed resource floors; and
4. comparison with synthetic host facts for OS, architecture, effective
   service identity and privilege state, root SSH policy, kernel, cgroup,
   Docker package provenance, daemon socket authority, Compose, clock, tools,
   persistent-path filesystems, resources, and storage headroom.

Missing fields, unknown or duplicate fields, conflicting merges, unsupported
versions and topology, relative or traversing paths, duplicate or nested state
paths, invalid UID/GID or modes, secret material, image overrides, canonical or
non-canonical loopback values, collapsed origins, premature or contradictory
features, recursive aliases, excessive input depth, and mismatched facts all
fail closed.

## Examples and fixtures

[`config/production/inventory.example.yaml`](../../config/production/inventory.example.yaml)
is a non-production `amd64` example. Positive fixtures cover both supported
architectures under `tests/fixtures/production-inventory/`. Host prerequisites
are represented only by synthetic YAML under
`tests/fixtures/production-host/`; negative mutation descriptors exercise
architecture, disk, clock, kernel, cgroup, OS, Docker, Compose, and rootless
failures.

These examples do not authorize use of the synthetic usernames, IDs,
addresses, origins, paths, or backup target on a real system.
