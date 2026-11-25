<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Public reference updates

This service is limited to the operator-enrolled synthetic data on the two
SecPal-owned public reference hosts. It performs an image-only switch with a
verified predecessor. It never migrates, restores, initializes, or moves any
persistent state. A customer installation, any target with real customer data,
or a change to PostgreSQL, private objects, or key generations requires its
own recovery authority, including the verified Recovery Set required by
[Deployment #109](https://github.com/SecPal/deployment/issues/109).

`secpal-reference-update.timer` runs the root-owned reference transaction
every ten minutes. The service takes its candidate pins and their
comparison evidence from the existing protected deployment source. It
acts on the frontend and API separately under the existing reference
deployment lock. A matching installed digest reports `already current`.

Install the adapter and its runtime modules below
`/usr/local/libexec/secpal/reference-update` in a root-owned directory
with no developer write access. Install the pinned GitHub CLI, canonical
governance checkout, its dependencies, and the official Node runtime
under the same directory. Root fetches protected GitHub metadata
directly. Only the exact OCI ZIP download uses the existing authenticated
account as an unprivileged process. Root verifies the independently
observed ZIP digest and existing signed publisher evidence before import.

The operator enrolls the previously accepted deployment revision and
the live exposure fingerprint in the root-owned
`/etc/secpal/reference-update.json`, with `data_class` explicitly set to
`secpal-owned-synthetic`. Confirm the target's data classification and the
applicable cross-host logical restore before enrollment. Use the existing
[logical restore procedure](fcos-application-poc.md#cross-host-logical-restore)
with the reference database, including any data or file dependencies relevant
to that target. A successful restore exercise is scoped to the data exercised. The root-only
`/etc/secpal/reference-update-witness` holds the enrolled synthetic account
credential for the existing public API tests. Before replacing pins, the service
rechecks the installed runtime, the actual public route and loopback
listeners, both protected source heads, and the exact comparison report.
The API also requires the enrolled PostgreSQL schema and migration
ledger and native forward and reverse evidence. The previous image must
remain admissible with the live schema. The browser-facing check uses the
reference's same origin, verifies host-only cookies, and exercises login,
organization access, and logout. Enroll the existing read-only frontend mount
from `/var/lib/secpal-reference/config/source-offer.json` to the image's
`/usr/share/nginx/html/source-offer.json` serving boundary. Enroll the existing
FPM configuration bind for API release metadata. Each lane writes and verifies
its source metadata from the qualified commit. The corresponding Contracts
archive is the OpenAPI revision adopted in [Frontend #1788][contracts-source].
The transaction stages
and checks the Quadlets before switching, then verifies the public
service and the unchanged database. A failed switch restores the
previous configuration when its authenticated rollback remains valid.
A failed rollback leaves the backups and reports a failed system
service for the existing Zabbix systemd alarm.

[contracts-source]: https://github.com/SecPal/frontend/pull/1788
