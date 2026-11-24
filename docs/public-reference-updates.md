<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Public reference updates

Activation remains a draft until the existing Deployment #93 requirement for
a current, verified Recovery Set under #109 can be checked for this target.

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
`/etc/secpal/reference-update.json`. The root-only
`/etc/secpal/reference-update-witness` holds the enrolled synthetic account
credential for the existing public API tests. Before replacing pins, the service
rechecks the installed runtime, the actual public route and loopback
listeners, both protected source heads, and the exact comparison report.
The API also requires the enrolled PostgreSQL schema and migration
ledger and native forward and reverse evidence. The transaction stages
and checks the Quadlets before switching, then verifies the public
service and the unchanged database. A failed switch restores the
previous configuration when its authenticated rollback remains valid.
A failed rollback leaves the backups and reports a failed system
service for the existing Zabbix systemd alarm.
