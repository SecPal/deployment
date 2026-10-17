<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Host firewall enforcement

Owner: [#104](https://github.com/SecPal/deployment/issues/104).
The single rule definition is `scripts/host_firewall_contract.py`; the bounded
administrator entrypoint is `scripts/host-firewall.py`. There is no firewall
daemon, runtime socket, provider adapter or replacement CrowdSec authority.

## Composition

The baseline owns only `table inet secpal_host`. Its input and forward hooks
have permanent default-drop policies. Existing #81 PostgreSQL output, #101
backend UID/SELinux, #220 DIRECT decoder and #103 ACME rules retain their own
tables and service lifecycles. A baseline accept never overrides a specialized
reject. No output hook is added: existing local-service and metadata-credential
egress barriers remain authoritative, while ordinary host-initiated DNS/HTTPS
traffic can receive conntrack reply-direction responses.

The current single-host reference does not route traffic for other hosts.
Rootless Podman/pasta networks do not need host forwarding authority. Future
HA/private seams require explicit reviewed admission rather than wildcard
private-network exceptions.

| Mode      | External application ingress                                                      |
| --------- | --------------------------------------------------------------------------------- |
| DIRECT    | Reviewed #220 HAProxy TCP 80/443; #103 still owns the narrow HTTP-01 routing path |
| PROTECTED | TCP 443 only from the accepted CloudFront Origin-facing IPv4/IPv6 prefix snapshot |

TCP 22 is allowed only from explicit authorized management networks, independently
of the Edge mode. Management never receives private DB/backend access. All other
unsolicited TCP/UDP ingress is denied, including PostgreSQL 5432, LAPI 8080,
product 18080/18081, decoders 18082/18083 and ACME responder 18084. Loopback
acceptance does not bypass the existing specialized output rules. External
loopback-source spoofing is rejected. Essential ICMP errors/PMTU and on-link
IPv6 neighbor discovery remain permitted.

An established inbound connection must still satisfy the current mode. The
conntrack exception admits only replies to host-initiated traffic, so switching
DIRECT to PROTECTED cannot preserve unauthorized pre-existing Viewer sessions.
No HTTP header or caller-supplied viewer identity affects kernel peer admission.

## Administrator inputs and prefix authority

Install the helper as `/usr/local/libexec/secpal/host-firewall`, alongside
`host_firewall_contract.py` and the existing
`cloudfront-origin-prefix-lkg.py`. Source and all ancestors must be root-owned,
non-writable by other identities, regular and unsymlinked. The CLI rejects execution
from a checkout and imports through a private administrator bytecode-cache path.

The fixed root-owned `/etc/secpal/host-firewall.json` has exactly:

```json
{
  "edge_mode": "DIRECT",
  "management_ipv4": ["192.0.2.10/32"],
  "management_ipv6": ["2001:db8::10/128"]
}
```

These are documentation-only addresses. #92 construction supplies independently
authenticated deployment mode and management paths, verifies initial management
reachability, and keeps HAProxy/Edge composition consistent. CIDRs must be
canonical, sorted, unique, family-correct and non-default; at least one family
must provide management. Later reloads cannot remove an already authorized
management network. Changing that authority is separate maintenance, not an
automatic firewall update.

PROTECTED reads only the existing administrator-owned accepted prefix LKG at
`/var/lib/secpal/cloudfront-origin-prefixes`. There is no caller-provided prefix
file or self-authorizing JSON argument. Existing prefix-source validation owns
HTTPS provenance, exact service, both non-empty families, canonical CIDRs,
publication metadata and digest. Its shared `admit_successor` also rejects
publication rollback or contradictory content at the same publication identity.
The prefix owner's existing no-maximum-age policy is preserved; no arbitrary
new freshness cutoff is introduced. DIRECT rejects a supplied CloudFront snapshot.

## Checked publication and restart

The CLI provides `--apply`, `--restore` and `--check`; it accepts no command,
table, binary or state-directory override. It uses fixed native nft JSON with
bounded timeouts/output and closed operation diagnostics. State is non-secret
accepted configuration, not a deployment journal.

`--apply` admits inputs and the prior effective policy, runs native
`nft --check`, and publishes one atomic batch. Updates flush only the two owned
chains **inside that batch**; their default-drop policies and remediation sets
remain intact. No global/table-wide flush or temporary default-open chain exists.
Authoritative kernel read-back must exactly match the generated policy before
atomic persistence of `/var/lib/secpal/host-firewall/accepted.json`.

Rejected candidates retain the previous policy. A lost acknowledgement causes
independent read-back, never blind mutation retry. If the kernel committed but
accepted-file publication was interrupted, a subsequent normal `--apply` can
persist the exact independently verified desired policy without replaying nft.
An unexplained different table fails closed. Post-rename directory-sync failure
reports `COMMITTED_DURABILITY_UNCONFIRMED`, not definite rollback.

The checked drop-in
`config/production/host-systemd/nftables.service.d/secpal-host.conf`
uses the **existing** native `nftables.service`. It restores/checks only this
accepted table, removes the distribution's global stop flush, and retains #81's
disabled global reload. Stopping or restarting that service does not withdraw
baseline ingress. Existing specialized units retain their After/PartOf ordering
and listener quiescence; #104 never tears down their tables.

Use the checked `--apply` interface for a configuration reload. Existing live
tables are verified on restart; after boot the accepted table is recreated
before dependent product/HAProxy policy units start. Initial installation must
first prepare a valid accepted policy and the private state directory. The
reference service uses only CAP_NET_ADMIN, protected filesystem/source paths,
private temporary state and AF_NETLINK/AF_UNIX. No product identity receives
firewall authority or administrator-helper execution rights.

Construction owns installation and reconciliation of any pre-existing vendor or
operator nft configuration. This explicit reference drop-in replaces the
distribution's arbitrary `nftables.conf` launcher; it must not be installed
blindly over independently owned operator policy. No installer is added here.

## Narrow #105 remediation interface

`--add <canonical-IP> --ttl <seconds>` and `--remove <canonical-IP>` operate only
on the two owned timeout sets. Each has at most 4096 entries; each decision lasts
1–3600 seconds. Native nft JSON time values are seconds, as exercised by real
expiration tests. No CIDR ban, arbitrary rule or executable input is accepted.
Management and current CloudFront Origin peer addresses cannot be banned.

Baseline updates/restarts preserve existing decisions. Removal/addition is one
checked atomic element batch with read-back. #105 owns authenticated decision
selection and its reviewed host-security dispatch; this interface does not grant
CrowdSec CAP_NET_ADMIN, create sudo rules, implement a bouncer, or authorize
blocking a CDN peer based on a client-controlled identity.

## Evidence scope

`python3 tests/host-firewall-contract.py` exercises closed configuration,
prefix-source reuse, malformed inputs and remediation bounds.
`python3 tests/host-firewall-native.py` creates anonymous user/network namespaces,
a veth peer, actual dual-stack TCP listeners and genuine nft kernel rules.
It checks positive controls, private ingress denial, mode changes on an existing
connection, spoofed XFF non-authority, preservation of a foreign specialized
table, rejected atomic batches, interrupted persistence, lost acknowledgements,
management preservation, remediation expiry/removal and CAP_NET_ADMIN denial.
All links/listeners/firewall tables exist only inside those disposable namespaces.
The default launcher verifies network-namespace separation before mutation.

These are real kernel/socket results, not a handwritten packet-policy evaluator.
The source document supplying test CloudFront ranges is explicitly synthetic;
the test does not claim a live AWS observation or cloud firewall qualification.
The ordinary existing architecture CI jobs run the focused admission tests
through preflight. Native firewall qualification runs in the available authorized
Rocky environment; it is not substituted with fixture success on an incapable
runner. Hosted Ubuntu 26.04 denies the second peer network namespace even with
CAP_NET_ADMIN/CAP_SYS_ADMIN in the first namespace. That environment is UNAVAILABLE
for this native test. No runner security restriction is relaxed, no native test
is changed into a successful skip, and no hosted ARM64 firewall PASS is claimed.

No deployment/provider mutation or existing-host installation is implied.
Production installation remains #92's responsibility, with #80 platform and
existing specialized-policy qualification consumed in their scope.
