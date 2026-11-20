<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# PostgreSQL 18 qualification

## Current FCOS lab status

PostgreSQL containerization is **QUALIFIED** for the three-host SecPal FCOS lab
at deployment revision `8ca49d48c6ee2179bf1fe8eae7575379d425484d`.
PostgreSQL 18.6 uses the pinned Docker Official Images index and verified native
amd64 and arm64 manifests. Rootless Podman/Quadlet owns the service lifecycle.
PGDATA lives outside the container layer, with SELinux Enforcing. The fixture
uses the PHP-FPM/Nginx API pair and separate runtime and migration authorities.
The lab proved authenticated application reads and writes, persistence after
container recreation and guest reboot, and TLS/SCRAM with `verify-full`.
Wrong server identity, untrusted CA and unauthorized database operations fail
at the relevant runtime boundary.
[Source, reproduction and three-host configuration](fcos-application-poc.md)

Disposable process-crash runs on amd64 and arm64 killed the PostgreSQL
postmaster with SIGKILL. Systemd restarted the Quadlet and PostgreSQL replayed
WAL. Each acknowledged transaction and synthetic application record survived.
The uncommitted marker stayed absent despite flushed WAL. Identity, schema,
migration ledger, role ownership and grants persisted through clean recreation.
These observations cover process loss with the guest kernel and storage
available.
[Both evidence records in #426](https://github.com/SecPal/deployment/issues/426),
[reproduction procedure](fcos-application-poc.md#arm64-postgresql-process-crash-qualification)

## Remaining production qualification

[#426](https://github.com/SecPal/deployment/issues/426) remains open for the
portable container contract integrated with the accepted
[FCOS Host Foundation](https://github.com/SecPal/deployment/issues/425) and
[independent Secret Authority and Activation](https://github.com/SecPal/deployment/issues/100).
The production path still needs evidence of independently issued credentials,
rotation and retirement across the intended update and restart/reboot lifecycle,
and evidence for the intended storage and failure classes beyond process loss.
Routine release updates and migration/rollback remain under
[#93](https://github.com/SecPal/deployment/issues/93). Construction, Patroni/HA,
Barman/WAL and RecoverySet admission are owned by their existing contracts.
See the [Managed SINGLE roadmap](roadmap.md#managed-single-readiness).

Reuse the admitted lab evidence for its exact source, image, host and failure
model until a relevant input changes. Keep raw evidence and credentials private.

## Historical native Rocky evidence

Closed [#81](https://github.com/SecPal/deployment/issues/81) and
[PR #286](https://github.com/SecPal/deployment/pull/286) retain the original
native Rocky amd64 and arm64 qualification. Those runs used signed RPMs,
native systemd/SELinux and the then-admitted FrankenPHP application image
to exercise PHP/PDO TLS, restricted roles, and HTTP readiness and liveness
through a database outage. Keep the original run, artifact and source
bindings for those observations.
[Original authority, procedure and evidence boundaries at the retirement source revision](https://github.com/SecPal/deployment/blob/6c786b2dd02b41cc55dadaf2ac3f7c6733ea33d0/docs/postgresql-qualification.md)

The old launcher and reference-host transport were specific to a temporary
candidate and authorizations for #81. The retained native declaration,
configuration rendering, package and storage checks, and pure evidence
admission still support their native consumers and historical schemas.
The independent [retained cloud cleanup](rocky-cloud-qualification.md#recovery-remains-available)
remains available for its existing ownership and recovery scope.
