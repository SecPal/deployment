<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# DIRECT single Viewer TLS lifecycle

Issue #103 consumes the [shared host-native HAProxy authority](haproxy-shared-base.md)
and [DIRECT identity boundary](haproxy-direct-viewer.md). HAProxy remains the only
public HTTP/TLS process. The fixed private product backends, exact application
proxy trust, forwarding sanitization, cookies, CORS and Sanctum are unchanged.
This contract applies only to DIRECT `single`; DIRECT HA, PROTECTED Viewer and
PROTECTED Origin certificates have separate authorities.

## Supply and execution authority

The only package owner is the accepted
[Certbot provenance contract](architecture/certbot-package-provenance.md) and
`config/production/certbot-package-policy.json`, policy
`certbot-epel-10.2-4.2.0-1`. Reuse its native CX23 x86_64 and CAX21 aarch64
qualification, signatures, dependency identities and Certbot 4.2.0 standalone
execution. This leaf changes no package identity or update authority. EPEL stays
disabled, its key remains transaction-scoped, and the packaged
`certbot-renew.timer` must remain disabled/inactive. No automatic upgrade,
repository expansion, pip, snap, sidecar or installer fallback exists.

`scripts/direct-viewer-tls.py` executes only from the fixed administrator-owned
`/usr/local/libexec/secpal/viewer-tls-source/scripts/direct-viewer-tls.py` using
`/usr/bin/python3 -I -S`. Install its `LIBRARIES` and the accepted package policy
at their original relative paths within that source directory, together with
`config/production/certbot-client.ini`. Install from one authenticated reviewed
source revision. All source ancestors are root-owned directories without
group/other writes or symlinks; files are root-owned regular single-link files,
scripts 0555 and data 0444. Repository authors and application accounts cannot
update this host copy. This is an administrator construction boundary, not #92's
full installer or #241 enrollment implementation.

The existing package observer checks installed payloads against the reviewed
public RPM bundle at `/var/lib/secpal/certbot-rpm-bundle` before client execution.
Retain the accepted bundle layout, authenticated keys and manifests; root owns
the bundle and its ancestry. This consumes #308's observer and admission owner;
it neither acquires nor installs packages. Dependency drift fails closed and
requires an operator-reviewed package-policy update. Runtime imports use the
accepted RPM interpreter scheme, excluding user sites, `/usr/local` imports and
site hooks. A private disposable import cache excludes adjacent bytecode.

## Private persistent state

| Path                                                                    | Authority and permissions                                   | SELinux type          |
| ----------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------- |
| `/srv/secpal/acme` and private subdirectories                           | root:root 0700; existing D.2 reserved infrastructure state  | `secpal_acme_state_t` |
| Certbot account files and archive private keys                          | root:root 0600, never product-mounted                       | `secpal_acme_state_t` |
| Archive certificate chains                                              | root:root 0600 or 0644, beneath private ancestry            | `secpal_acme_state_t` |
| `/etc/haproxy/secpal-viewer.pem`                                        | root:root 0600, one complete chain plus key                 | stock Rocky `etc_t`   |
| Publication journal, predecessor and receipt snapshot in `/etc/haproxy` | root:root 0600                                              | stock Rocky `etc_t`   |
| Activation/renewal receipts in `/srv/secpal/acme`                       | root:root 0600, bounded public facts within private storage | `secpal_acme_state_t` |
| `/run/secpal-viewer-tls` and lock files                                 | root:root 0700 and 0600                                     | stock runtime context |

The ACME config/work/log directories are beneath `/srv/secpal/acme`. Certbot's
logs are private state; never upload them to CI, evidence archives or issues.
Private keys/accounts never enter Git, images, Cloud-Init, application mounts,
conversation output or public evidence. Temporary candidate PEMs use restrictive
creation, file fsync and directory fsync; they share the serving file's filesystem.
The root HAProxy master reads the serving PEM before dropping worker privilege.
No worker or product account can write any certificate authority input.

Install the supplied tmpfiles fragment, systemd units and timers. The generated
listener drop-in adds `BindsTo/After=secpal-acme-policy.service` through the existing
configuration owner, without another HAProxy drop-in or reload controller.
`secpal-acme-policy.service` constructs policy only while HAProxy and renewal are
inactive. The supplied units explicitly select root `unconfined_service_t`;
manual root administration also admits `unconfined_t`. Its CIL maps private state
and TCP 18084, permits `haproxy_t` connect, root service bind and the explicit
`init_t` to root service transition under NoNewPrivileges, and changes no broad
SELinux boolean. Native
effective access, port labels and the exact nft table are checked on each use.
Existing-table drift is rejected; an unchanged table may be re-admitted at boot.
The source never disables SELinux Enforcing.

The nft seam rejects non-loopback access to TCP 18084, permits host loopback
access only from root and the admitted HAProxy UID, and rejects IPv6 responder
access. Certbot binds IPv4 loopback only; HAProxy's admitted IPv4/IPv6 public
sockets both reach that same responder. Product container identities cannot
impersonate those host UIDs. Root controls policy construction and account state.

Activating this state makes an encrypted infrastructure backup necessary under
D.2. The operator owns storage, retention and restore credentials independently
of product backups. Restore only to the same intended host identity, with modes,
labels, exact names and serving proof re-admitted. Never clone private keys or
account state across reference machines. On state loss, keep a still-valid serving
PEM active where possible, disable renewal, and authorize a fresh account/key and
reissuance after checking CA limits. Never infer success or reconstruct an
activation receipt from a certificate found on disk. Rebuilding trust or changing
names is a construction/reissuance decision, not automatic renewal recovery.

## HTTP-01 admission

The closed DIRECT document selects `"tls_lifecycle": "http01"`. Historical #220
documents retain their identity-only behavior; the TLS controller refuses them.
Configure both the frontend and API DNS names in that document, never from a CSR,
Host header or certificate. No reference-host name is a generic default.

After #220's method, target, Host and size checks, HAProxy admits only GET with
the exact raw target `/.well-known/acme-challenge/` followed by a 43-character
base64url token. Certbot's standalone responder serves only its currently active
token and key authorization; an unknown token is not accepted. Queries, suffixes,
traversal, encodings, malformed tokens and alternate methods never reach it.
The backend has fixed loopback authority, bounded timeouts and sanitized headers.
An inactive responder yields failure rather than application fallback.

Every other admitted HTTP request redirects with 308 to the selected fixed HTTPS
origin, preserving encoded path/query (OPTIONS `*` redirects to that origin's
root); unknown Hosts are rejected. HTTPS challenge
requests return 404. HTTP/2's native URI representation is projected to its exact
encoded path/query before existing origin-form checks. HTTP/1 absolute targets
remain rejected. The existing internal generation witness is limited to admitted
local probe sources and its exact fingerprint; it is not a public HTTP exception.
The challenge seam is the sole future #106 WAF/CrowdSec bypass, and implements no
WAF or CrowdSec policy itself.

## Initial construction and renewal

The administrator selects `/etc/haproxy/secpal-acme.json`, a closed object with
`email` and `directory` (`staging` or `production`). Only the fixed Let's Encrypt
directory URLs are permitted. Selecting a URL is not external execution authority.
Actual public issuance requires independently authorized external HTTP-01
reachability; an old source-limited test firewall cannot supply that reachability.

First construct the HTTP-only `http01` listener through #219's existing inactive
host construction/start mechanism, with the ACME isolation barrier active. An
authorized `--obtain` runs Certbot standalone without stopping HAProxy and stores
the new lineage without publishing it. Add the intended HTTPS sockets to the
desired closed document, then run `--prepare-initial`. It validates and atomically
prepares the PEM with a durable pending marker, explicitly returning **PENDING**.
HTTPS socket addition is a separate #219 host construction decision. Its boot
guard permits this bounded first preparation, but not HSTS or renewal replay.
After the existing runtime has started, `--accept-initial` independently verifies
every served TLS socket before issuing the activation receipt and clearing the
marker. Failure is never initial activation acceptance.

Renewal changes no sockets or desired configuration. The SecPal timer runs twice
daily, randomized by at most 30 minutes, persistent across reboot, with a
15-minute service deadline and a 10-minute client deadline. Root-only nonblocking
flocks exclude duplicate renewals and publications; Certbot retains its own state
locks. The packaged timer, default sysconfig and directory hooks are excluded.
The CLI fixes standalone, address, port, endpoint, paths, key type and hooks;
persisted renewal state admits only this one bounded native lineage. Pre/post
hooks are `/usr/bin/true`; the deploy hook is the fixed root helper. No force
renewal, stop/start, arbitrary command or DNS credential is production input.

The deployment hook admits matching archive generations and root-controlled
lineage links, parses complete chain/key material, requires exactly the two
intended DNS SANs, server purpose, non-CA status, approved RSA/EC strength and
SHA-2 signature, valid dates and at least 14 days remaining. Native OpenSSL
independently verifies signatures, chain, purpose and both hostnames against
the fixed Rocky system trust bundle. A certificate cannot supply its own trust.

The existing #219 publication primitive stages private material and validates
the exact regenerated configuration with `haproxy -c` against the candidate.
It writes a durable predecessor/journal, atomically replaces the fixed serving
PEM and calls only `systemctl reload haproxy.service`. The accepted master/worker
and configuration-generation proof remains in force. Independent TLS probes
use real CA/hostname verification, both SAN names as SNI, each HTTPS socket,
TLS 1.2/1.3 and ALPN h2/http/1.1. Only a leaf fingerprint match admits activation.
Filesystem equality alone is insufficient, including no-op renewal.

Any validation failure preserves the predecessor; reload/serving failure restores
it and attempts one compensating shared-runtime reload/probe. Uncertain recovery
keeps its pending marker and reports failure. On interruption, ordinary startup
refuses a pending renewal. `--recover` under the root publication lock restores
the digest-bound predecessor and its old receipt, then uses the same reload/probe
if HAProxy is active. It never replays or accepts the candidate. An interrupted
first preparation has no accepted predecessor and is removed only with HAProxy
inactive, preserving a possibly serving initial construction until the operator
has selected its recovery. A held root lock
allows only the immediate promotion/compensation reload of the unchanged serving
configuration, never a boot replay. Health observations do not acquire this lock.

## Health and HSTS

`--health` emits one closed JSON Security capability fact for #129, and exits
nonzero unless HEALTHY. An expired observed certificate is FAILED; a contradictory
serving fingerprint is FAILED; renewal failure or expiry within 30 days is
DEGRADED. Missing, stale or unavailable observations are UNKNOWN. Renewal writes
UNKNOWN before execution, SUCCESS only after serving proof (including no-op),
and FAILURE on execution/activation failure. The hourly health timer exposes
bounded facts in the system journal; Certbot output and private state are never
diagnostic payloads. A missing producer remains unknown to the future aggregator.
This does not implement #129's global deployment-health decision.

HSTS is absent in `http01`. The separate `hsts` selection requires an accepted
initial certificate, a subsequent different served certificate, and a recent
successful renewal receipt at ordinary activation/startup. It emits only
`max-age=86400` over HTTPS. No preload or includeSubDomains is inferred safe.
Certificate-only reloads preserve the already accepted HSTS prerequisite;
a pending first renewal cannot activate HSTS.

## Qualification scope

Run `python3 tests/direct-viewer-tls-contract.py` for registered source contracts
and `bash tests/direct-viewer-tls-runtime.sh` for the real private ACME/TLS fixture.
The latter requires the qualified local native Certbot/crypto/HAProxy tools and
a fresh rootless user/network namespace; it fails closed without isolation.
It generates an ephemeral CA, keys and account state in private temporary storage,
exercises real Certbot HTTP-01 through HAProxy, renewal/no-op, TLS and rollback,
native nft projection agreement and subordinate-UID responder/key denial,
then removes all private fixture material. Forced renewal and disabled ACME-peer
trust are fixture-only options; neither is exposed by the production controller.
Source tests admit DAC/SELinux facts and reject bad facts. They do not prove a
native installed SELinux/systemd deployment or public CA issuance.

The accepted #219/#220/#308 native evidence retains its original scope and source
binding. New live host installation, SELinux policy or firewall changes require
separate applicable authority. Optional public qualification must name exact
server IDs, DNS A/AAAA records, ports, CA directory, public challenge-source
reachability, duration, rate limits, private-state retention and rollback. This
source delivery changes no reference host, DNS or provider firewall, and never
targets the protected `app.secpal.dev` / `api.secpal.dev` Polyscope server.
