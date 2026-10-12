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
Redirects and repository fallback are prohibited. Qualification uses absolute
system tools, a fresh private HOME and a minimal environment; RPM command-line
configuration explicitly excludes caller rcfiles and macros. Native DNF loads
only when strong solving is requested, with caller environment and HOME macros
removed; an unavailable native binding rejects with `native-dnf-unavailable`.
Each input is read once as a bounded regular file and copied into a private
snapshot. Key import, signature/header verification, dependency solving and
installed-payload verification consume those same authenticated bytes.

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
  files against the authenticated RPM file, rather than trusting file checksums
  from the host RPMDB; configuration authority remains with the consuming
  lifecycle. The recorded RPM SHA-256 identifies the authenticated reference
  artifact. Its installation origin additionally requires the independent
  trusted transaction and transport evidence; extracted files cannot reconstruct
  an RPM container digest.
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

The original local x86_64 namespace transaction encountered an incompatible
filesystem/mount boundary while
installing `filesystem` (`/afs` creation failed with `Device or resource busy`).
No native aarch64 qualification environment was available for that original
attempt.

On 2026-10-12, the dedicated Hetzner CX23 (163965414, native x86_64) and
CAX21 (169716995, native aarch64) were independently authenticated through the
`secpal` provider context, provider console and pinned SSH host identities.
Both run Rocky 10.2 with Enforcing SELinux and only BaseOS, AppStream and Extras
enabled. Their original transaction preflight reported six dependency failures
per architecture: installed `glibc-gconv-extra` and `glibc-langpack-en` pinned
glibc `2.39-128.el10_2`, `python-unversioned-command` pinned Python
`3.12.14-1.el10_2`, and `xz` pinned `xz-libs` `1:5.6.2-4.el10_0`.
The original observations remain retained; no failed installation was retried.

The operator separately authorized exactly these four ordinary Rocky packages
for baseline alignment on those disposable hosts. Fresh official Rocky metadata,
RPM bytes, signed headers and payloads established the compatible identities:
`glibc-gconv-extra` and `glibc-langpack-en` `0:2.39-142.el10_2` in each native
architecture, `python-unversioned-command` `0:3.12.15-1.el10_2.noarch`, and `xz`
`1:5.6.2-4.el10_2.1` in each native architecture. These packages retain ordinary
Rocky authority and do not extend the Certbot exception or its 106-package policy.
The retained supplementary manifest is SHA-256
`0cf42f1d25ec78217945af8f4c8d9583bcf9ec3db6d69175def790fd96d5ea5b`.
It binds the full architecture-specific identities, official URLs, RPM digests,
header digests, payload digests and Rocky signer fingerprint.

An independent administrator controller authenticated all 110 input RPMs using
transaction-local in-memory signing authority. Each native DNF solver admitted
exactly 32 changes: 16 new packages and 16 version upgrades within the authorized
set. RPM independently checked dependencies before each single installation;
there were no package erasures, downgrades, additional packages, disabled
signature checks, skipped scriptlets, fallback repositories or global EPEL key
imports. All 110 installed signed-header identities match their authenticated
inputs, and privileged RPM payload verification succeeds on both hosts.

Rocky's systemd preset enabled the packaged renewal timer during its required
installation scriptlet, without starting it. The administrator disabled that
new timer immediately on both hosts. Independent systemd observations show the
timer disabled/inactive, the service inactive with no execution timestamp, and
no account, certificate or archive state. A consuming installation executor must
explicitly keep packaged renewal units disabled and inactive during qualification
and before the separate #103 activation authority. Default presets alone do not
establish that condition. This qualification introduced no public listener or
ACME operation and did not alter SELinux or the ordinary repository set.

Unprivileged native probes import the client and dependency modules, load the
standalone plugin, and execute Certbot 4.2.0 under Python 3.12.15 on both machines.
Rocky's explicit `rpm_prefix` Python installation scheme selects the verified
RPM module directories, while `-I -S` excludes user paths and automatic site hooks.
The original default-scheme probe failed because it selected `/usr/local`;
this same-delivery correction changes no package identity. Protected baseline
RPM files require an independent, temporary administrator read broker restricted
to payload verification of `libutempter`, `pam` and `util-linux`, with scriptlets
disabled. Its explicit `--payload-read-broker` capability admits only exact
package-name/RPM-digest pairs against the administrator's immutable copies and
returns a bounded receipt. No PATH shim or arbitrary privileged command is
admitted. Controller identity, helper bytes and transport remain independently
authenticated; a candidate-produced receipt cannot establish their authority.
Candidate Python has no general root or provider authority. Final
native observations must additionally bind a clean exact signed source head and
pass the existing observation schema and semantic owner before acceptance.

Both native hosts already contain the exact reviewed `filesystem` RPM, whose
signed-header and payload identities match the policy and whose RPM payload
verification succeeds, including the existing `/afs` directory. This supports
classifying the earlier failure as specific to the local installroot/namespace
environment rather than a supported-host `filesystem` package defect. The
precise local mount or filesystem collision remains unproven; the original
failure evidence is retained.

The original signing and strong dependency authentication remains valid supply
evidence, separate from native execution, authenticated transport and final
source admission. Historical namespace failures are not evidence that Certbot
needs CRB or broader EPEL. Final source qualification, finite review and hosted
checks belong to this same leaf and primary delivery. After merge, independent
protected-main acceptance must precede completed closure and resumption of
snowy-hawk. No certificate-lifecycle work is implemented by this amendment.
