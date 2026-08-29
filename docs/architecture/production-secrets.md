<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Production secret contract

## Boundary and delivery model

The canonical rows and delivery sets are in
[`config/production/state-contract.json`](../../config/production/state-contract.json).
Secret values are created by a security operator or external secret authority,
never by a product container, image build, Quadlet renderer, or ordinary state
initializer. D.2 contains no real value.

The external authority publishes a complete staged tree as
`/run/secpal/secrets` only after validating every file. Initial publication is
one atomic directory rename from a sibling on the same tmpfs filesystem.
Independent publication first proves the canonical `/run` ancestry and exact
`/run/secpal` owner, group, mode, and ACL contract; it cannot stage beneath an
arbitrary or product-writable parent.
Rotation stops affected roles, stages and fsyncs a complete replacement tree,
atomically exchanges it with the active tree, runs host and user-namespace
validation, restarts all affected roles, verifies recovery, and then destroys
the retired delivery copy. A partial tree never becomes active. Ordinary
initialization never removes, regenerates, chmods, chowns, or overwrites a valid
existing secret.

The root and consumer directories are root-owned, group-traversable only by the
service account, mode `0710`, and have no named or default ACL. Files are
read-only bind mounts with one link and no symlink. Each consumer gets individual
files, not the host secret root:

| Delivery                                    | Host file owner and mode | Consumers                             |
| ------------------------------------------- | ------------------------ | ------------------------------------- |
| `/run/secpal/secrets/api/app-key`           | `110000:210000`, `0400`  | Migrate, API, both workers, scheduler |
| `/run/secpal/secrets/api/app-previous-keys` | `110000:210000`, `0400`  | Same API roles                        |
| `/run/secpal/secrets/api/tenant-kek`        | `110000:210000`, `0600`  | Same API roles                        |
| `/run/secpal/secrets/api/postgres-password` | `110000:210000`, `0400`  | Same API roles                        |
| `/run/secpal/secrets/api/valkey-password`   | `110000:210000`, `0400`  | API roles only                        |
| `/run/secpal/secrets/valkey/password`       | `110001:210001`, `0400`  | Valkey only                           |

The Valkey copies must be byte-identical. Copies exist solely to avoid a shared
group or broad secret directory. Frontend and unrelated data/product roles
receive no secret mount.
Feature-gated external credentials have no delivery or consumer while their
inventory gates remain disabled.

## Application delivery without OS-environment secrets

The production PostgreSQL container and its initializer have been retired. The
current tree therefore has no PostgreSQL server credential-delivery directory
or executable database launcher. The API credential file remains an application
input; the future host-native PostgreSQL work owns its server-side delivery and
rotation seam. Valkey's fixed launcher validates the raw file's length and LF
count before command substitution, reads only its individual file, and writes a
mode-`0600` configuration in container tmpfs before exec. Its health probe tests
the expected unauthenticated `NOAUTH` response and never reads the password.

The API image currently names application settings through Laravel's PHP
configuration interface. Production mounts a root-owned `auto_prepend_file`
bootstrap. That bootstrap validates files, loads values only into PHP's
in-process `$_ENV`/`$_SERVER` configuration, and never changes the OS process
environment. Its production root is fixed at `/run/secpal/secrets/api`;
ordinary runtime environment cannot redirect it. Repository tests use an
explicit PHP constant that is not production configuration. Consequently
Quadlet source, generated systemd properties, Podman
container configuration, `/proc` environment inspection, and process arguments
contain paths and non-secret settings only. The bootstrap logs one bounded error
with no path content or value on failure.

Generic environment dumps remain prohibited. Diagnostic commands must use an
allowlist of non-secret names and must never print PHP superglobals, mounted
secret files, the transient Valkey configuration, or application configuration
objects that contain resolved values.

## APP_KEY lifecycle

Initial creation is external and uses 32 cryptographically random bytes encoded
in Laravel's exact `base64:<44-character-base64>` form. The delivered file has
one optional final newline and no other content. The external authority retains
the stable recovery copy; `/run` is only a boot delivery. Initialization refuses
to replace a valid key, and loss never triggers generation.

Rotation is an explicit reviewed maintenance operation:

1. Prove the current key and external recovery copy match without printing
   either value.
2. Generate the new key externally and stage it as the new active `app-key`.
3. Prepend the former active key to `app-previous-keys`; remove no key implicitly.
4. Stop all API roles, atomically exchange the complete delivery tree, validate,
   and restart migrate/API/workers/scheduler together.
5. Prove decryptability and normal operation before accepting the rotation.
6. Retire one previous key only through a separate recorded decision after all
   data requiring it has been re-encrypted or its retention obligation ended.

Failure before exchange leaves the old tree active. Failure after exchange
rolls back by exchanging the preserved old tree and restarting the same roles.
Destruction happens only after verified recovery and the retirement decision.

## APP_PREVIOUS_KEYS contract

The file is zero to three LF-separated Laravel keys, newest previous key first,
with at most one optional final LF. CR, CRLF, other line separators, and blank
records are invalid. An empty file means there is no previous key. Duplicate keys, the current
active key, blank interior lines, malformed base64, more than three entries, or
an unreviewed removal fail validation. PHP converts the validated list to the
comma-separated value expected by the API only in process memory. The list is
never appended automatically, so historical keys cannot grow without bound.

## Tenant KEK contract

The tenant KEK is exactly 32 raw bytes: no newline, prefix, hex decoding, base64
decoding, text normalization, or reinterpretation. Its container path has mode
`0600`, matching the API's byte-level file contract, and is read-only from the
container. The security operator's stable external copy is separate from
PostgreSQL, application storage, tenant ciphertext, and the backup that needs it.

It is never generated automatically and never writable by a product role.
Rotation uses the API's reviewed tenant-key rewrap operation: keep the prior KEK
externally, quiesce writers, rewrap every tenant key transactionally, verify all
tenants and recovery evidence, atomically exchange the delivery tree, restart
all API roles, and destroy the former key only after the rollback window closes.
`APP_PREVIOUS_KEYS` does not recover or rotate the tenant KEK.

## Database credential lifecycle

PostgreSQL and Valkey passwords are externally generated 24–128-character
values from the closed file grammar. They never appear in a URL, command line,
unit text, image, Git object, log, snapshot, or issue evidence.

The future host-native PostgreSQL work owns server-side credential delivery,
rotation, and rollback. The current tree does not retain the removed container
launcher or a dormant server credential copy.

Valkey rotation stages matching API and Valkey copies, stops queue producers and
workers, performs the reviewed Valkey credential change, exchanges the complete
tree, and restarts Valkey before API roles. Queue/AOF recovery is verified before
the old credential is destroyed. Neither path changes the credential merely
because a container was recreated.

## Infrastructure and operator secrets

Backup-encryption credentials, TLS private keys, operator/SSH credentials,
GitHub credentials, and registry credentials are not application secrets. They
remain under their external infrastructure or human authority and have no D.2
container consumer or mount. Backup decryption credentials are escrowed
separately and are never stored only inside the encrypted backup.

Official SecPal API and frontend images are public digest-pinned OCI identities.
Their production Quadlets use `Pull=never` after separate verified staging. No
GHCR login, GitHub token, registry auth file, credential helper, or registry
secret is required or introduced by D.2.

## Failure, recovery, and destruction

Validation distinguishes valid existing material, absent material, partial
sets, malformed values, wrong owners/groups/modes, ACL drift, symlinks, hard
links, wrong paths, and unexpected files. Only a complete valid set permits
startup. Diagnostics name the invariant class, never a secret, supplied path,
or value. A signal or failed staging operation cleans only its uniquely named
sibling staging directory and cannot touch the active tree.

Recovery re-delivers the externally retained stable versions, validates both
consumer-copy equality and application/data compatibility, and restarts exact
consumers. Destruction is explicit, attributable, and deferred until rollback
and retention requirements are satisfied. Deleting a container, rolling back a
Quadlet, or rebooting the host is never secret destruction authority.
