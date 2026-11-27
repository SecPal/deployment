<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Retained Rocky cloud recovery

The Managed reference is Fedora CoreOS. Active Rocky GCP provisioning and
qualification ended in [#395](https://github.com/SecPal/deployment/pull/395).
The [multi-provider qualification](https://github.com/SecPal/deployment/issues/123)
and [backend qualification](https://github.com/SecPal/deployment/issues/294)
were closed as not planned.

## Recovery remains available

The [manual cleanup workflow](../.github/workflows/rocky-cloud-qualification.yml)
admits only destroy of exact retained GCP continuation state. It authenticates
protected-main control and the original verified source, run, attempt, and
profile before using the cleanup identity. Provider absence must be checked
independently of local state. Expiry permits cleanup of the original subject.

The three pinned OpenTofu roots in `infra/ci-cloud/`, the exact-owned
DigitalOcean and GCP janitors, the historical Rocky profile inputs, and
continuation schemas remain required until their recovery obligations are
independently discharged. Technical retirement belongs to
[#538](https://github.com/SecPal/deployment/issues/538). This cleanup scope
excludes the retained FCOS lab hosts.
[Portable cloud evidence and ownership](https://github.com/SecPal/deployment/issues/117)

## Historical evidence

The accepted [test-host evidence](https://github.com/SecPal/deployment/issues/248)
and [native PostgreSQL qualification](https://github.com/SecPal/deployment/pull/286)
keep their original source, host, architecture, and artifact bindings.
[Native host evidence contract](architecture/production-host.md) ·
[PostgreSQL qualification](postgresql-qualification.md)

The original dispatch and source remain available at the
[pre-retirement revision](https://github.com/SecPal/deployment/tree/bf6ec699f1ce28f13081f5d368bdd21996eb5b18).
The accepted [provider and transport revision](https://github.com/SecPal/deployment/pull/371)
and [Phase-1 native host revision](https://github.com/SecPal/deployment/pull/365)
record their exact subjects and remaining evidence limits.
