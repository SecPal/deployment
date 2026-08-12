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
`amd64` or `arm64`. The closed host-fact document separately requires Debian
13/trixie identity, authenticated Debian archive provenance, the exact
codename-pinned release-suite set, the security-update and reboot policy, and
Debian Stable/Security kernel provenance. These observations must be collected
from effective OS, APT, package, kernel, and update-policy state; a self-selected
distribution label is insufficient. The kernel package architecture must equal
the admitted host architecture. Public addresses must be globally
routable. Reserved documentation addresses are permitted only by the explicit
`--synthetic` fixture mode; normal validation rejects them. Multicast,
IANA-reserved IPv6 space, deprecated IPv6 site-local ranges, and scoped IPv6
literals are never host addresses.
Public and private address comparison uses parsed IP identities, so equivalent
IPv6 spellings match while semantic duplicates fail. IPv4-mapped IPv6 values
are rejected rather than treated as native IPv6 host addresses. DNS hostname
comparison is case-insensitive; host identity permits a valid single label,
while public frontend and API origins require fully qualified multi-label DNS
names. IP literals and legacy numeric IPv4 spellings are not hostnames. Private
addresses are limited to RFC 1918 IPv4 or IPv6 ULA;
documentation, benchmarking, link-local, and other non-global ranges are not
treated as private-use addresses. Private-address order is not significant;
duplicate or mismatched facts fail closed. Address facts must use YAML strings;
numeric or binary representations are not coerced. Clock synchronization is
mandatory and cannot be disabled. The validator does not call cloud metadata
or inspect a machine.

### `service_account`

The name, primary group, numeric UID/GID, absolute home, non-login shell,
interactive-login state, rootless-Podman authority, and selected subordinate
UID/GID ranges are explicit. UID/GID
values are strict YAML integers, are bounded, and cannot reuse known SecPal
runtime IDs. Integral floating-point spellings are not coerced for UID/GID,
path ownership, decision-issue, or resource fields. The account never carries
a credential in inventory. `root` is forbidden as an account name; known
privileged or sensitive Debian and runtime primary-group names are also
forbidden. Host
facts must report no supplementary group membership.
Supplied host facts report the effective UID, primary GID, and supplementary
GIDs resolved for the configured identity, as well as its name,
primary group, home, shell, interactive-login state, effective sudo
authorization, and effective host-privilege authorization. Identity and home
facts must match inventory. Home facts additionally prove a local root-owned
`0750` directory with the service primary GID and no account-writable containers
configuration. Shell and login facts must prove the non-interactive policy;
sudo and broader host privilege authorization must be absent. The broad denial
covers privileged supplementary groups and equivalent ACL, device, capability,
system-unit, rootful-runtime, remote-runtime, or policy grants. A separate
closed SSH fact must prove that direct root login is not permitted.

Schema version 1 selects one contiguous 65536-identity range from `/etc/subuid`
and one from `/etc/subgid`. Starts and counts are strict integers; arithmetic
overflow, a range in the supported host-identity space, malformed facts, a
different account, multiple effective entries, overlap with another account,
or an effective mapping that differs from inventory fails closed. The size maps
all current known container identities without guessing the future PostgreSQL
or Valkey identity.

### Rootless runtime host facts

Runtime policy is reviewed schema, not an inventory escape hatch. Host facts
must prove Podman `>=5.4.2,<6.0.0`, rootless ownership by the selected account,
authenticated Debian installed-package provenance and an allowed installed
suite for every runtime package, effective mapping helpers, and `crun` as both
the installed and Podman-selected OCI runtime,
Netavark/Aardvark DNS, pasta, uidmap, a boot-capable systemd user manager with
linger, a local owner-only runtime directory and runroot, Quadlet, and local
overlay storage. The effective Quadlet search list contains only the reviewed
administrator path; its configuration is not account-writable and its complete
definition tree contains no symlinks. The definition directory and the
root-controlled service-account home use one shared path-access fact model;
their canonical path, owner, mode, effective account write access, and complete
ancestor write access are validated identically. Rootful Podman, Docker as the
selected production runtime, Compose orchestration, compatibility packages,
remote or socket APIs, host networking, auto-update, registry redirects,
user-writable Quadlet overrides, and non-root-owned Quadlet units fail closed.
Inventory cannot supply arbitrary Podman flags, Quadlet text, security options,
host-network toggles, runtime sockets, or update policy.

### `origins`

`frontend` and `api` are exact HTTPS origins. The frontend and API origins must
differ. Each uses a fully qualified multi-label DNS name, the default HTTPS
port, and no userinfo, path, query, fragment, empty delimiter, control
character, localhost name, loopback address, or IP literal. Reserved
documentation names such as `.invalid`, `.test`,
`.example`, and `example.com`/`.net`/`.org` are accepted only in explicit
`--synthetic` fixture mode. The scheme and optional `:443` spelling must be
canonical; parser-normalized alternatives fail closed. Origin separation
preserves the credentialed CORS, Sanctum, cookie, and proxy trust boundary.

### `paths`

Each path object records an absolute path, host owner role and numeric identity
when known, any known container UID/GID, baseline directory mode, persistence
class, and any later issue that must decide the mapped host identity or
lifecycle. Paths must be normalized,
unique, mutually non-overlapping, non-empty, non-root, and outside `/tmp`.
They must not contain or be contained by the service-account home. Fixed
metadata cannot be changed by an operator. Version 1 confines SecPal state to
strict children of `/srv/secpal`, runtime secrets to a strict child of
`/run/secpal`, and the service-account home to its dedicated
`/var/lib/secpal` subtree. Rootless Podman graphroot is a dedicated child of
`/srv/secpal`; Quadlet definitions are derived exactly as
`/etc/containers/systemd/users/<service UID>` and remain operator/root owned.
These namespace rules prevent a later owner or mode operation from targeting
unrelated system trees.

Paths use UTF-8 byte limits shared by the supported ext4/XFS host model: at
most 255 encoded bytes per component and 4095 encoded bytes for the complete
path. ASCII control characters and character-count-only values that the target
filesystem cannot safely represent fail admission.

Known API private and public storage requires container identity
`10001:10001`; the inventory deliberately records null host UID/GID for those
bind paths. Rootless namespace mapping means the container identity is not the
same host identity. A null owner delegates selection; it does not permit the
path to alias the service-account UID while claiming that the account cannot
write. Host facts must keep effective access consistent with UID/GID and mode.
D.2 owns safe host-side ownership materialization. Runtime
secret, PostgreSQL, edge, ACME, and CrowdSec identities remain explicitly
delegated rather than guessed. Podman graphroot is service-account-owned and
reconstructable; authoritative business data must remain outside it.

### `resources`

The inventory declares admission requirements. CPU, total storage, and total
inode values cannot be lower than the schema contract. Memory remains an
explicit positive operator-selected byte requirement until D.10 supplies a
measured universal floor; it is still compared exactly with supplied facts.
`resources.storage` contains only byte and inode
headroom observations plus the backing filesystem's byte and inode totals.
Each absolute/percentage pair must exactly match those per-filesystem totals,
allowing whole-number flooring, and each filesystem total must fit within the
corresponding aggregate host total.
The separate closed `filesystems` fact group contains a shared `access` fact
for canonical path, ownership, mode, locality, and effective account access,
plus filesystem type, effective read-only mount state, `d_type`, and XFS
`ftype` observations for every persistent inventory path plus backup staging.
The same access schema is used by `path_access` for the systemd runtime
directory, Podman runroot, root-owned service-account home, and Quadlet
definitions, without imposing a storage filesystem choice on `/run`, `/var`,
or `/etc`. Every represented mount must explicitly be writable. This
separation ensures that
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
  --host-facts tests/fixtures/production-host/valid-amd64.yaml \
  --synthetic
```

`--synthetic` exists only for checked-in fixtures that use reserved
documentation addresses. Omit it for external production inventories; without
it, documentation addresses fail closed. The validator reads only the two input
files and the two repository schemas. It does not query DNS, the network,
Podman, `/proc`, `/sys`, cloud metadata, or a remote machine and does not change
the filesystem.

Validation consists of:

1. recursive secret and supply-chain field rejection;
2. closed JSON Schema Draft 2020-12 structure and type validation for both
   inventory and host facts;
3. cross-field rules for origins, paths, ownership, addresses, and fixed
   resource floors; and
4. comparison with synthetic host facts for OS, architecture, effective
   service identity and privilege state, root SSH policy, Debian release,
   update and kernel package provenance, cgroup, Podman package provenance,
   subuid/subgid, systemd user/linger, Quadlet ownership, runtime/API and
   registry policy, clock, tools, filesystem ownership, modes, effective
   service-account access, trusted ancestry and writable mounts, AppArmor
   enforcing-profile evidence, resources, and storage headroom. Every supplied
   path-access value is the collector-resolved canonical path and must exactly
   equal its contract spelling, proving that no represented path component
   traverses a symlink. Runtime secrets receive that effective path evidence in
   D.2 when their materialization contract is defined.

Missing fields, unknown or duplicate fields, conflicting merges, unsupported
versions and topology, relative or traversing paths, duplicate or nested state
paths, invalid UID/GID or modes, secret material, image overrides, canonical or
non-canonical loopback values, IPv4 or IPv6 IANA special-purpose public
addresses under the reviewed 2025-10-09 registry snapshot,
special-use public DNS names, collapsed origins, premature or contradictory
features, recursive aliases, excessive input depth, and mismatched facts all
fail closed.

## Examples and fixtures

[`config/production/inventory.example.yaml`](../../config/production/inventory.example.yaml)
is a non-production `amd64` example. Positive fixtures cover both supported
architectures under `tests/fixtures/production-inventory/`. Host prerequisites
are represented only by synthetic YAML under
`tests/fixtures/production-host/`; negative mutation descriptors exercise
architecture, disk, clock, Debian release/suite/update lifecycle, kernel
provenance, cgroup, Podman provenance/version, rootful operation, subordinate
mapping, Quadlet/user-manager, API exposure, registry rewrite, graphroot, and
auto-update failures.

These examples do not authorize use of the synthetic usernames, IDs,
addresses, origins, paths, or backup target on a real system.
