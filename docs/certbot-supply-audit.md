<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# DIRECT Certbot supply audit

## Status

Historical audit retained for original #103 workspace continuity. The repository
authority boundary below was subsequently resolved by accepted #308 / PR #309,
merged as `bd373a8274038938853e3f3d7ceae1eed70b898e`. The sole current supply owner
is [the accepted package-provenance contract](architecture/certbot-package-provenance.md)
and its policy `config/production/certbot-package-policy.json`. Its independently
qualified native x86_64/aarch64 evidence supersedes this audit's pending claims.
The dated observations below are historical evidence, not a second maintained
package policy. Current TLS lifecycle scope is documented in
[DIRECT Viewer TLS](direct-viewer-tls.md).

This is the 2026-10-12 phase-one audit for deployment #103, against authenticated
`main` `4c528020be06c2f708acb6a2436152b64bf7ba6a`. It records available native RPM
supply and the unresolved repository-authority boundary. It does not admit an
EPEL installation, implement the TLS lifecycle, or claim installed runtime,
SELinux, ACME issuance, renewal, or delivery acceptance.

The authenticated native graph has #103 open under #90, with #220 as its sole
closed/completed blocker. PR #304 and PR #307 are merged; #219 and #220 remain
closed/completed. No new delivery PR or graph relationship was created by this
audit.

## Repository authority boundary

The accepted [production host contract](architecture/production-host.md#package-provenance-and-updates)
permits only Rocky `baseos`, `appstream`, and `extras` and rejects enabled
external repositories. The executable owner
`scripts/ci-cloud/rocky_preparation_contract.py` enforces that exact set and
Rocky's signing fingerprint. `schemas/production-host-facts.schema.json` also
requires exactly those repositories and `external_repositories_enabled=false`.

Both architecture queries against those three actual Rocky 10.2 repositories
returned no `certbot` or `python3-certbot` package. Fedora EPEL 10.2 provides
Certbot and eight necessary runtime dependencies. Enabling EPEL would therefore
fail existing host admission even with authentic packages. Package availability
and signature verification do not independently approve a new host repository
trust authority.

The boundary is **repository policy**, not absence of a compatible upstream RPM
or a reason to replace Certbot. Resolve whether #103 may explicitly amend the
existing host-provenance owner with a package-restricted, separately keyed EPEL
exception, or whether that independently reviewable authority change needs a
separate architecture decision. Preserve the current fail-closed owner until
that scope decision is made. Do not bypass it with manual RPM installation.

## Actual supply observations

Discovery used workspace-local DNF install roots, a separate repository file,
and no system RPM database. The optional EPEL repository existed only in that
discovery file. No repository or package was activated on the Polyscope host or
any reference server. Dependency solving used the DNF API with
`load_system_repo=False`, `install_weak_deps=False`, and no transaction execution.

The exact repository roots were:

- Rocky 10.2 BaseOS: `https://download.rockylinux.org/pub/rocky/10.2/BaseOS/<architecture>/os/`
- Rocky 10.2 AppStream: `https://download.rockylinux.org/pub/rocky/10.2/AppStream/<architecture>/os/`
- Rocky 10.2 Extras: `https://download.rockylinux.org/pub/rocky/10.2/extras/<architecture>/os/`
- [Fedora EPEL 10.2 x86_64](https://dl.fedoraproject.org/pub/epel/10.2/Everything/x86_64/)
- [Fedora EPEL 10.2 aarch64](https://dl.fedoraproject.org/pub/epel/10.2/Everything/aarch64/)

Do not substitute the moving EPEL `10` alias or assume the obsolete path without
`Everything/` exists. The Fedora package listing was discovery evidence only;
queries, actual RPM retrieval, and cryptographic verification followed.

The official [EPEL 10 key](https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-10)
fingerprint is `7D8D15CBFC4E62688591FB2633D98517E37ED158`. Its bytes matched the
[independent distribution-source copy](https://src.fedoraproject.org/rpms/epel-release/raw/epel10/f/RPM-GPG-KEY-EPEL-10),
SHA-256 `de390fc168eae5ab2852e9e93d34a0b9ddf05cf9ce90ee28d97de26a4b1f6b93`.
The accepted Rocky key fingerprint is
`FC226859C0860BF0DDB95B085B106C736FEDFC85`.

The solver resolved 106 packages from an empty root on each architecture,
including nine EPEL packages; all other packages came from Rocky BaseOS or
AppStream. No CRB, testing, COPR, snap, pip, sidecar, or installer was needed.
Every resolved RPM was downloaded from its explicit official repository and
verified using `rpmkeys --checksig --verbose` against a workspace-local keyring:
212 verification results passed, with the expected repository signing key,
header digests, and payload SHA-256 digest. This is supply evidence, not native
installation or execution evidence.

The nine EPEL RPMs have identical signed bytes in both architecture trees:

| Package                  | Epoch, version, release, architecture | RPM SHA-256                                                        |
| ------------------------ | ------------------------------------- | ------------------------------------------------------------------ |
| `certbot`                | `0:4.2.0-1.el10_2.noarch`             | `5d2554d6ffd1903ad9706e0e35139aaaaa0a49f7b8fa19b37da0e9663e76a1f7` |
| `python3-acme`           | `0:4.2.0-1.el10_2.noarch`             | `3229170401a9b19497e9ec36d84174a9cda0cc079b8f60b85f18e89c750ea690` |
| `python3-certbot`        | `0:4.2.0-1.el10_2.noarch`             | `a6ed64e8d76c67ba9c69706d4851065c23722b720dd64706eb437f017d3844a8` |
| `python3-configargparse` | `0:1.7.5-1.el10_2.noarch`             | `bb83f7d9553e0be4d388088b740a44d9129ed3c61f83a24020b0df01ca0e135c` |
| `python3-josepy`         | `0:2.0.0-2.el10_1.noarch`             | `7add9c93d58ab696e661845ab39403d86252662c25cdba057969be9487b8dee4` |
| `python3-parsedatetime`  | `0:2.6-1.el10_0.noarch`               | `6919faef97c7c001ace29f927ca19e952ba4dc3d816d76d0ce1fa2f38b9e0d0c` |
| `python3-pyOpenSSL`      | `0:25.0.0-1.el10_1.noarch`            | `eb5d2a6be0e47099c63fa042f83afac12021820bfc0d79fa0f9dcd57b71941dc` |
| `python3-pyrfc3339`      | `0:1.1-20.el10_0.noarch`              | `daf13290fe0b7f61d556133cd2dde5183225d7c6c72125e2df43e9b6917f6092` |
| `python3-pytz`           | `0:2025.1-1.el10_1.noarch`            | `72097a77fb1144dc2c20143040821e4ac74af04581a4fbdadaa7f097b3a5b8cb` |

`certbot`, `python3-certbot`, and `python3-acme` come from
`certbot-4.2.0-1.el10_2.src.rpm`. The actual Certbot runtime requires Python ABI
3.12. Both solver results select Rocky `python3`/`python3-libs`
`0:3.12.15-1.el10_2`, `python3-cryptography` `0:43.0.0-4.el10_2.5`,
`openssl-libs` `1:3.5.8-2.el10_2`, and systemd
`0:257-23.el10_2.2.rocky.0.1`, with architecture-specific native RPMs.
Dependency resolution does not prove those installed runtimes execute Certbot;
that qualification remains pending.

The extracted `/usr/bin/certbot` entrypoint SHA-256 is
`45c3cad0a369d043483953df2206d8153e2d493d71520fcea4f2114e33a77a6e`.
This is a Python entrypoint, not a self-contained executable; its identity alone
cannot authenticate imported modules or installed dependencies.

## Distribution scheduling and maintenance

The signed package contains `certbot-renew.service` and `certbot-renew.timer`.
The actual service is oneshot and runs `certbot renew --noninteractive
--no-random-sleep-on-renew`, consuming hook/argument variables from
`/etc/sysconfig/certbot`. The actual timer has `OnCalendar=*-*-* 00/12:00:00`,
`RandomizedDelaySec=12hours`, and `Persistent=true`. The packaged README describes
a different delay; the signed unit bytes are the observed scheduling semantics.
Neither timer nor hooks were enabled. An accepted SecPal lifecycle must bound
and serialize renewals and remove arbitrary hook/environment authority instead
of treating those package defaults as sufficient.

EPEL is a separate Fedora-maintained supply authority. Its major/minor branches
and community maintenance must be reviewed explicitly; it is not Rocky-signed
supply or an automatic extension of Rocky's security-maintenance promises.
Current maintenance-policy document retrieval was blocked by the Fedora Docs
access challenge; no maintenance SLA or complete update-policy qualification
is claimed here. A decision must select the maintenance owner, security-update
response, minor-version migration, package-retirement behavior, and whether
changes require exact dependency/package digest requalification. Preserve
operator-reviewed updates, no automatic service restart, and fail-closed
admission while this remains unresolved.

## Reference identities and limits

Read-only Hetzner API observations reauthenticated the three exact server IDs
and their running status. Resolver observations of each pair of reference DNS
names matched its server's IPv4 and the first address of its IPv6 subnet:

| Server            | Architecture | IPv4              | Observed IPv6 DNS destination |
| ----------------- | ------------ | ----------------- | ----------------------------- |
| CX23 `163965414`  | x86          | `78.47.193.193`   | `2a01:4f8:c013:ec3b::1`       |
| CX33 `163717938`  | x86          | `178.105.194.164` | `2a01:4f8:c013:be72::1`       |
| CAX21 `169716995` | arm          | `2.31.27.118`     | `2a01:4f8:c012:3ca5::1`       |

These are dated provider/resolver observations, not live TLS, DNSSEC, OS,
installed-package, firewall, reachability, or ACME acceptance. No host mutation,
public-port change, ACME request, or DNS mutation occurred. The six names are
not generic implementation defaults. `app.secpal.dev`, `api.secpal.dev`, and
the protected Polyscope server were not qualification targets.

## Retained local evidence and next boundary

Raw discovery configuration, DNF solver inputs/results, package bytes, signature
results, and extracted public package units remain workspace-local under
`.context/103-authority/supply/`. This temporary evidence is not a canonical
validation receipt, signed lifecycle publication, or final attestation. No
secret state or private certificate material was collected.

After resolving repository scope, independently qualify installed Certbot on
both architectures before selecting it for the production activation path.
Continue #103's failing-first lifecycle implementation using the accepted
`/etc/haproxy/secpal-viewer.pem`, shared reload owner, and DIRECT identity owner.
Optional public ACME testing needs a separately authorized bounded handoff; it
does not authorize changing the protected application domains or server.
