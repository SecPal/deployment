<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Host CrowdSec decisioning

Owner: [#105](https://github.com/SecPal/deployment/issues/105).
The native Security Engine detects behavior and owns its local decision database.
[The host firewall](host-firewall.md) exclusively owns effective nftables policy.
Application availability and Security health remain independent.

## Supply and installation boundary

The reviewed inputs are in config/production/crowdsec/supply.json:

- CrowdSec 1.8.1-1.el9 RPMs, separately pinned for x86_64 and aarch64;
- exact RPM SHA-256, native executable/pattern bytes, and signing-key fingerprint
  9082D8CACBBEB0DAB218BAB04C3D386C3CDF0DB4;
- the fixed CrowdSec Hub commit used for the syslog parser and SSH scenario; and
- exact runtime configuration/parser/scenario hashes.

These are vendor rpm_any EL9 artifacts, not a claimed Rocky/EL10 distribution
build. Package signature and byte admission do not establish native architecture,
systemd or SELinux compatibility. Each supported architecture needs that evidence.

Installation belongs to #92's trusted administrator boundary, consuming accepted
protected-main source. Verify the public key's pinned digest/fingerprint and RPM
signature/digests using a dedicated read-only RPM filesystem keyring. Do not
import the CrowdSec key into the global Rocky keyring or enable a moving vendor
repository. The ordinary Rocky and TLS-only Certbot authorities remain unchanged.

The vendor RPM's scriptlets register Central access, update/upgrade Hub content,
start services and enable an updater timer. They are not the SecPal installation
contract. A controlled RPM transaction must preserve signature/dependency checks
while suppressing those scriptlets and package triggers. No signature, digest or
dependency bypass is permitted. Qualification must prove this installation/update
behavior before activation; this source does not install anything.

Native administration explicitly selects
cscli -c /usr/share/secpal/crowdsec/secpal.yaml. Initial machine generation uses
the native --auto and --file output interfaces; the bouncer key is captured
directly into its protected credential file. Existing identities/credentials are
preserved on restart/update, not silently replaced with --force.

Construction must:

1. Create the dedicated system identity using the supplied sysusers fragment.
2. Prepare /srv/secpal/crowdsec for that identity and protected root-owned source,
   operator policy and credential directories.
3. Install the reviewed configuration at /usr/share/secpal/crowdsec, with patterns
   linked to the exact verified /etc/crowdsec/patterns directory. Create the empty
   notifications/plugins directories; the empty pinned Hub index stays read-only.
4. Deliver agent credentials and a distinct read-only bouncer key through the
   declared systemd LoadCredential interfaces. Use native credential generation
   and protected file/captured output; no key/password command arguments.
5. Mask **and stop** crowdsec-hubupdate.service and crowdsec-hubupdate.timer.
6. Apply the reviewed engine drop-in, remediation service/timer and native audit
   rules. Verify actual service, socket, SELinux, audit and privilege boundaries.

The engine startup checks exact required payload/configuration bytes rather than
running a whole-package filesystem observer against systemd-masked home paths.
Missing, altered or additional parser/configuration/pattern inputs are rejected.
This check does not pretend to be an authenticated installed-RPM observation.

## Process and local API authority

The existing crowdsec.service runs as secpal-crowdsec with no capabilities.
Its only permitted socket family is AF_UNIX. LAPI uses
/run/secpal-crowdsec/lapi.sock, with no TCP listener, forwarded-header trust,
remote registration, automatic registration, metrics listener or Central client.
The dedicated group permits only the bounded administrator consumer to reach
the private runtime directory/socket.

The engine receives only its local agent credential. The administrator projector
receives only the read-only bouncer key. Secret-source directories, product
secrets/data and other services' credentials are hidden from their namespaces.
Neither application containers nor a normal LAPI client receives CAP_NET_ADMIN.

The single remediation oneshot has only CAP_NET_ADMIN and writes only #104's
existing accepted state directory. It authenticates the socket server UID before
sending its key. It accepts no request URL, executable, table, PID, source path
or credentials on its command line. There is no generic root broker.

## Acquired identity and privacy

The pinned journalctl acquisition admits root sshd.service records or HAProxy
stdout from haproxy.service. Native trusted journal fields establish provenance;
a caller-selected SYSLOG_IDENTIFIER is insufficient.

The SSH parser accepts explicit failed-authentication forms and derives the peer
from the anchored terminal transport suffix, not an embedded username or header.
The native Grok patterns are composed so the pinned C++ RE2 implementation emits
actual IP captures. The username is discarded.

The paired peer/client HAProxy parser consumes #220's canonical single-host
format. The actual network peer remains distinct from the canonical client.
The equivalent PROTECTED producer belongs to #209/#217; replay compatibility
does not establish live Origin authentication. A deployment must qualify the
owning producer before admitting its events. HA transport/preface logs are not
silently reinterpreted as the paired single-host format.

HTTP forwarding headers are not IP authority. No Laravel log parser is selected.
Raw event text and unnecessary target-user data are removed before local alert
storage. No cookie, Authorization header, body, query string or employee activity
profile is acquired. Local security cache retention is bounded to 24 hours/5000
items; it is not authoritative application or recovery state.

## Bounded projection and recovery

The projector reads fresh authenticated native LAPI query snapshots, not a
persistent second decision database. Only reviewed local IP-ban scenarios qualify.
It consumes #104's canonical limits, protected-peer exclusion and read-back.

SSH peer decisions may reach L3 in either mode. HTTP canonical-client decisions
reach L3 only in DIRECT single, where the client is the network peer. Behind an
LB or CloudFront, HTTP decisions remain available to #106's separate L7 consumer;
banning a CDN/LB peer or claiming client-IP L3 enforcement would be incorrect.

Local allowlists live in root-owned /etc/secpal/crowdsec/allowlist.json, initially
from the supplied example. Changing them requires administrator authority.
The native audit rule records policy-directory replacement/permission changes
and local cscli administration without copying file contents or secret values.

Reconciliation removes revoked/allowlisted decisions, prioritizes missing
entries, and does not reset an already shorter ban. The fresh observation
deadline includes local processing time. Every mutation passes through #104's
checked exact-IP interface; ambiguous acknowledgements are reconciled there.
A partial failure is reported, never blindly replayed from a cached response.
The next run reads both authorities again. Existing decisions expire in the
kernel; restart does not flush baseline policy or create indefinite bans.

Security health checks the native engine, expected live journal reader, masked
updaters, current authenticated decisions and their effective #104 projection.
A missing or stale effective ban reports degradation even when baseline policy
and the engine remain healthy. Failure
reports SECURITY_DEGRADED; no product readiness or stop/start authority is coupled
to it. A live reader is scoped process evidence, not proof that historical logs
were complete. Journal retention/outage coverage needs independent host evidence.

## Evidence scope

The focused contract tests cover selection, expiry, protected peers, allowlists,
interruption, input integrity and source privilege constraints. Authored fixtures
are not package, real-journal, SELinux or provider qualification.

The native test runs the actual pinned engine, SQLite state and UDS protocol in
one verified disposable network namespace on the real host architecture. It
exercises positive/negative acquisition replay, real read-only API authorization,
peer UID/DAC/capability isolation, #104 kernel projection, mode-specific behavior,
allowlist recovery and restart. It uses no production credential or host service.

A process test and native READY notification are not execution by PID 1.
Actual systemd sandbox, SELinux/audit admission, installed-package transaction and
both CPU architectures remain independently qualified installation requirements.
No existing host installation or provider mutation is implied.
