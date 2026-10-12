<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Scoped Fedora EPEL provenance for Certbot

## Decision and delivery boundary

[Deployment #308](https://github.com/SecPal/deployment/issues/308) owns this
atomic amendment to the [Rocky host contract](production-host.md).
The selected exception is Fedora EPEL **10.2**, solely for Certbot **4.2.0**
and its fully qualified required dependency closure. It introduces no general
EPEL repository or signer authority. This candidate requires independent native
installation/runtime qualification on both architectures before acceptance.

The historical [#80](https://github.com/SecPal/deployment/issues/80) delivery
remains the ordinary Rocky host baseline. Its repository and signer authority
continues to protect all ordinary host packages. This amendment belongs to the
existing platform family, independently of
[#103](https://github.com/SecPal/deployment/issues/103)'s certificate lifecycle.
Native GitHub relationships are authoritative; this document defines no graph
state. No new package-provenance owner is needed when #103 resumes.

This amendment does not implement issuance, HTTP-01, renewal, certificate
publication, TLS lifecycle, a production installer, public routing or DNS.
Loading the installed standalone plugin during qualification performs no ACME
operation, starts no listener and creates no certificate or account state.

## Contradiction being corrected

At protected deployment/main
`4c528020be06c2f708acb6a2436152b64bf7ba6a`, Certbot is absent from the actual
Rocky 10.2 BaseOS/AppStream/Extras metadata on both supported architectures.
The retained #103 audit discovered Fedora EPEL supply, but did not authorize it
or prove installed runtime compatibility. The following surfaces enforce the
Rocky-only boundary:

- `production-host.md` allows only Rocky repositories and Rocky signing authority.
- `production-host-facts.schema.json` requires exactly the three Rocky enabled
  repositories, Rocky's key, and disabled external repositories.
- `rocky_preparation_contract.admit_package` admits only Rocky provenance;
  native normalization authenticates the corresponding signed RPM header.
- `rocky-control.py` independently enforces the ordinary package owner;
  the synthetic production validator cannot establish native host evidence.
- Existing repository negatives reject enabled EPEL and uncontrolled repositories.
- #103 requires authenticated package qualification and a separate decision
  before changing supply authority. Authentic EPEL signatures alone cannot
  override any of these requirements.

The correction distinguishes **installed TLS-specific provenance** from
**enabled repository state**. It does not add EPEL to any ordinary Rocky
repository allowlist or modify the existing Rocky package admission function.

## Exact trust scope

The maintained [package policy](../../config/production/certbot-package-policy.json)
contains independently reauthenticated exact identities, RPM SHA-256,
signed-header SHA-256, payload digest, full signer fingerprint and original
official repository URL for every member of each architecture's closure.
The pure owner is
`rocky_preparation_contract.admit_certbot_exception`. Both the synthetic host
validator and the native control validator consume that owner. The native
observation schema references the existing host schema rather than redefining
the package-provenance shape.

Each architecture resolves 106 strong dependencies from an empty root with
weak dependencies disabled. Exactly nine packages have EPEL provenance:
`certbot`, `python3-certbot`, `python3-acme`, `python3-configargparse`,
`python3-josepy`, `python3-parsedatetime`, `python3-pyOpenSSL`,
`python3-pyrfc3339`, and `python3-pytz`. The remaining 97 packages retain Rocky
provenance. A required Rocky dependency does not receive EPEL trust simply
because it belongs to this closure. Optional plugins and unrelated EPEL
packages are outside the exception. No CRB or COPR package is required by the
independently resolved candidate closure.

The full Fedora EPEL 10 fingerprint is
`7D8D15CBFC4E62688591FB2633D98517E37ED158`. Independently fetched copies from
the [official EPEL key publication](https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-10)
and [Fedora epel-release source](https://src.fedoraproject.org/rpms/epel-release/raw/epel10/f/RPM-GPG-KEY-EPEL-10)
must match SHA-256
`de390fc168eae5ab2852e9e93d34a0b9ddf05cf9ce90ee28d97de26a4b1f6b93`.
The Rocky fingerprint remains
`FC226859C0860BF0DDB95B085B106C736FEDFC85` and remains a separate authority.
The scoped verifier uses a temporary RPM database, never the system keyring.

EPEL URLs use exactly
`https://dl.fedoraproject.org/pub/epel/10.2/Everything/<architecture>/`.
Rocky URLs use exactly the reviewed 10.2 BaseOS/AppStream/Extras roots.
The moving EPEL `10` alias, another minor, another repository, replacement RPM,
unknown signer, additional package, incomplete closure or changed digest is
not admitted. DNF's own solver independently rechecks the exact local signed
bundle without any enabled repository, network fallback or installed-root input.

## Acquisition, installation and maintenance policy

EPEL remains disabled outside exact reviewed transactions. Prefer acquisition
of the pinned RPMs into an operator-controlled bundle with
`scripts/qualify-certbot-packages.py --acquire DIRECTORY --architecture ARCH`.
The destination must be new. Only URLs in the authenticated target policy are
read; hashes, signatures, signed headers and the strong dependency closure are
verified before the bundle can be used. Acquisition performs no installation.

Any installation/maintenance executor must consume this same policy, restrict
the transaction to the authenticated exact bundle, use transaction-local signing
authority (for example RPM's in-memory `TransactionSet.setKeyring` primitive),
and retain signature/payload verification. It must not import the EPEL key into
the system RPMDB, disable signature checks, enable general EPEL, consult another
repository, substitute a package, update automatically, or skip required RPM
scriptlets. This leaf supplies the admission contract; #103 owns integration
with its reviewed installation and certificate-maintenance transaction.

After a transaction, admission requires:

- Ordinary enabled repositories exactly `baseos`, `appstream`, and `extras`;
  no external repository enabled and no EPEL key in the global RPMDB.
- Every installed closure member has the exact reviewed signed-header identity
  and verified executable/module/library payload. RPM's verifier checks these
  files; configuration authority remains with the consuming lifecycle.
- The complete installed EPEL-signed inventory matches the nine-package family;
  an unrelated EPEL RPM is rejected even if EPEL itself is disabled.
- Effective kernel and Python architecture agree independently for x86_64 and
  aarch64. The installed Python 3.12.15 imports the full client/dependency family
  and loads the Certbot 4.2.0 standalone plugin. A noarch RPM, solver result or
  emulation on the other architecture cannot satisfy this runtime boundary.
- The ordinary Rocky host qualification, including x86-64-v3 and SELinux,
  remains independently required. TLS package observations cannot replace it.

Deployment maintainers own review of Fedora EPEL security advisories, package
retirement and exact updates. There is no assumed Rocky maintenance guarantee
for Fedora packages. A security update requires a reviewed change to the exact
policy, fresh signing/provenance/closure authentication, both architecture
qualifications and renewed host admission. Until then there is no automatic
substitution or upgrade. If an urgent vulnerability or retired package makes
the accepted client unusable, fail closed and withhold its activation until a
reviewed replacement policy is available; do not widen supply as recovery.

Neither package acquisition nor admission activates `certbot-renew.timer`,
executes package renewal hooks, restarts a service or authorizes public traffic.
The deterministic renewal schedule and its hook authority remain #103 work.

## Qualification and evidence limits

`scripts/qualify-certbot-packages.py --installed DIRECTORY --architecture ARCH
--target-sha SHA --output FILE` requires a clean exact candidate checkout and
the independently authenticated RPM bundle. It observes the real installed
packages, effective repositories and native runtime before calling the pure
owner. Its closed output is target-bound. The control command
`validate-certbot-observation FILE --target-sha SHA` revalidates the shared
schema and owner. Both commands provide semantic validation; external native
transport must independently authenticate the producer and target. Arbitrary
caller-authored JSON is never native proof.

Repository tests prove synthetic positive and negative admission agreement,
including cross-architecture/runtime failures, unrelated EPEL RPMs and
uncontrolled external repositories. They do not prove installation.
The original snowy-hawk 212 verification results remain historical and
untouched. Fresh official metadata resolution, key authentication and all 212
RPM signature/digest checks reproduced those identities for this candidate.

Native installation evidence is still missing. The local x86_64 namespace
transaction encountered an incompatible filesystem/mount boundary while
installing `filesystem` (`/afs` creation failed with `Device or resource busy`).
No native aarch64 qualification environment was available. This is a missing
qualification capability, not evidence that Certbot needs CRB or broader EPEL.
No policy acceptance, successful installation or #103 resumption is claimed.
Resolve those qualifications in this same leaf and primary delivery, without
recursive prerequisite owners. After merge, independent protected-main
acceptance must precede completed closure and resumption of snowy-hawk.
