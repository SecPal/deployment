<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# DIRECT Viewer identity composition

Deployment #220 consumes #219's host-native HAProxy runtime and routing and
Issue #101's backend policy. The candidate implements `single` and the private
`ha` PROXY v2 seam. This is a listener seam, not an HA fleet qualification.
Public Viewer acceptance additionally requires approved real public-ingress
qualification. The immutable #219 reference record remains historical provenance.

## Closed single input

`render-haproxy-direct.py` accepts a bounded JSON document with exactly
`topology`, `frontend_host`, `api_host`, and `listeners`. `topology` is `single`.
Each listener has exactly `address`, `port`, and `transport`; transport is
`http` or `https`. Socket coordinates reuse #219's `Listener`. External HTTP
listeners use port 80; external HTTPS listeners use port 443. High loopback
ports permit isolated qualification. Overlapping wildcard/address sockets are
rejected; IPv6 sockets explicitly use `v6only`.

HTTPS binds use only `/etc/haproxy/secpal-viewer.pem`, TLS 1.2 or later, and
HTTP/2 or HTTP/1.1. #103 owns material validation, issuance, renewal,
publication, HTTP challenge/redirect behavior, and certificate health. This
consumer introduces no ACME client, certificate issuance, or certificate-input
pathname. Local tests use an ephemeral self-signed fixture outside Git.

Both transport listeners accept ordinary TCP with no PROXY receiver. Real
HAProxy parsing rejects public PROXY v1/v2 without selecting either backend.
The original TCP source is the canonical client address. The shared
`forwarding_sanitization()` removes caller `Forwarded`, `X-Forwarded-*`,
`X-Real-IP`, `X-SecPal-*`, and request-ID fields before this consumer emits:

| Header              | Reviewed source                                         |
| ------------------- | ------------------------------------------------------- |
| `X-Forwarded-For`   | Actual TCP source, exactly one address                  |
| `X-Forwarded-Host`  | Accepted frontend/API Host, normalized without its port |
| `X-Forwarded-Proto` | Actual local HTTP/TLS transport                         |
| `X-Forwarded-Port`  | Corresponding public origin port, 80 or 443             |

The origin matching, hygiene, readiness, fixed `127.0.0.1:18080` and
`127.0.0.1:18081` targets, and log field bounds remain #219's reviewed rules.
DIRECT logs add canonical client IP to the original network peer. They retain
the generated request ID and exclude request paths, queries, authorization,
cookies, bodies, and arbitrary caller/internal header values.

## Application trust and lifecycle

The API's `config/trustedproxy.php` consumes `TRUSTED_PROXIES`.
`render-haproxy-direct.py INPUT --application-peer OBSERVED_TCP_PEER` emits an
exact numeric proxy peer for API environment composition. It rejects wildcard,
CIDR, `REMOTE_ADDR`, comma-separated argument values, and unspecified input.
The flag may repeat for at most two independently observed exact peers on
the API’s existing private interfaces; it produces one bounded environment
value. Rootless forwarding may select either interface after recreation. Observe the actual
rootless forwarding address first; it is not necessarily host loopback inside
the product container. A configured address alone is insufficient host proof:
the #101 firewall, UID, SELinux and private-network boundary must independently
prevent a different authority from impersonating that application peer.
Rootless localhost publication can remap the source to a container interface
address. Reserve the selected private addresses through the existing product
network contract before enabling trust, and verify it after recreation. An
address change must fail closed; never compensate with a wildcard or CIDR.

No request Origin, Referer, cookie, CORS, Sanctum, or application route is
rewritten. Product session/CORS tests require the actual API/frontend runtime;
synthetic passthrough tests and the API-locked Symfony identity primitive do
not establish that acceptance. The qualification-only
`tests/haproxy-direct-api.php` front controller mounts on the immutable API
image and uses its complete HTTP kernel and API middleware, including Sanctum
statefulness. Its synthetic session counter is absent for foreign, stateless
origins. It adds no product route or runtime extension.

The existing administrator helper uses a fixed compile-time composition
module. No module path, plugin, runtime socket/API, backend discovery, raw
fragment or external command is configuration input. Neutral #219 inputs may
activate only loopback sockets; external serving requires the DIRECT input
shape. Exact regeneration of embedded closed inputs authenticates serving
bytes independently of rejected desired inputs. Systemd listener constraints
remain derived from the socket type; existing supply, account, SELinux,
Issue #101 policy, publication, reload and LKG gates remain in force. Install the new
composition libraries alongside the existing root-owned helper libraries
before selecting a DIRECT input. No installer or live activation is performed
by the preview command.

The serving-generation witness dials each exact socket. HTTPS probes retain
frontend SNI, certificate and hostname verification without DNS lookup. A
failed probe cannot establish successful activation/reload. Socket changes
remain construction decisions and are rejected by graceful reload.

## Qualification and remaining boundary

`tests/haproxy-direct-contract.py` covers closed input, public-port pairing,
neutral-listener bypass rejection, sanitization, exact byte regeneration,
exact application proxy peer admission, pre-import installed-source authority,
and unchanged shared-renderer bytes.

`tests/haproxy-direct-runtime.py` executes real HAProxy with synthetic fixed
loopback peers. It tests genuine IPv4/IPv6 HTTP and TLS connections, spoofed
headers, public PROXY v1/v2 rejection, separate origins, readiness recreation,
HTTP hygiene, privacy-safe logs, serving generation, and graceful reload/LKG.
It fails if fixed backend ports are already in use; use an isolated network
namespace without stopping another service:

```bash
unshare --user --map-auto --map-root-user --net bash -c \
  'set -euo pipefail; ip link set lo up; exec python3 tests/haproxy-direct-runtime.py'
```

`tests/haproxy-direct-application.py PINNED_HTTP_FOUNDATION_ROOT` additionally
exercises the actual Symfony Request primitive from the API's authenticated
lockfile with real HAProxy-delivered identity. It proves IPv4/IPv6 identity,
scheme/host/port reconstruction, and rejection of metadata from an untrusted
application peer. It uses native `/usr/bin/php`, with no container runtime.

## Strict private HA seam

`ha` listeners additionally require `trusted_peers`, a nonempty bounded list of
unique exact private IPv4/IPv6 addresses. Wildcards, CIDRs, public addresses,
unspecified addresses and multicast addresses are rejected. Listener addresses
are loopback, RFC1918 or ULA; public/wildcard listeners cannot select this mode.
The topology cannot mix public direct and private PROXY listeners.

The outer HAProxy TCP frontend authenticates the physical TCP source before
examining any claimed address. It admits exactly the binary v2 signature,
PROXY command, TCP/IPv4 with a 12-byte address block or TCP/IPv6 with a 36-byte
address block. The complete 28- or 52-byte frame must arrive within one second.
LOCAL, UNSPEC, datagram, UNIX, mapped IPv6, other versions, extra TLVs, inconsistent lengths,
v1 and incomplete prefaces fail closed. Decoded unspecified/multicast client
addresses and missing/zero source ports are rejected before any HTTP response,
including the read-only serving witness. This intentionally closed profile does
not admit arbitrary v2 extensions. The native inner parser owns decoding;
`accept-proxy` alone is not the version boundary.

Only admitted bytes pass to the same daemon's isolated HTTP/TLS decoder at
`127.0.0.1:18082`/`127.0.0.1:18083`. `haproxy-direct-policy` binds a distinct
SELinux port type to these two sockets, permits HAProxy bind/connect, and installs
a separate nftables table denying external ingress and unrelated-UID loopback
access. Effective kernel decisions and port labels are checked with the
accepted #101 libselinux observer and the installed SETools package. Stock
container domains already have generic port operations; their decisions remain
equal to the existing unreserved-port decisions. nftables supplies the
complementary host UID isolation. This adds no product/backend permission to #101. Root remains the accepted
administrator authority. Fixed loopback administrative generation probes must
also pass UID admission. The listener's own address is an administrative
TCP peer only on the local path protected by that UID gate; external input
still admits only the configured L4 peers. Probes let the kernel select the
physical local source, preserving systemd's prohibition on arbitrary binds. All local preface callers are UID-bound; an unrelated
process cannot bind an allowlisted loopback source and use that address to
bypass the L4 allowlist. The installed config helper refuses HA activation without
the root-owned policy, source binding and matching effective nftables table.
The policy service performs native kernel observation through its fixed reload
action; the config helper then checks the matching source-bound marker. This
keeps netlink and NET_ADMIN outside the HAProxy runtime sandbox. Installed
project modules compile in an empty, administrator-private per-process cache
namespace after ownership admission, excluding substituted adjacent bytecode.
The HA listener unit requires the policy service before HAProxy starts.

The admission log records the physical peer and complete internal TCP socket tuple.
The HTTP log records that tuple, worker PID, canonical client and generated
request ID. Journal time and the complete connection tuple correlate requests
to their admitted physical connection, including multiple requests per connection
and connections crossing a graceful worker reload. The stages may have different
worker PIDs during that handoff.
No raw PROXY frame, caller TLV, request path, header, cookie or body is logged.
Generation probes traverse the complete preface and decoding chain, including
verified TLS where configured. Neither decoder has a runtime API or admin socket.

Install `haproxy_direct_policy.py`, the fixed `haproxy-direct-policy` helper and
`secpal-direct-policy.service` along with the composition libraries for HA.
Construction uses `haproxy-direct-policy --activate --desired` on a stopped
HAProxy service, followed by `haproxy-config --activate` before starting the
services. Boot and running-policy checks reconstruct the accepted serving bytes,
so a rejected desired document cannot invalidate the last-known-good generation.
The policy does not open a public port or configure a load-balancer fleet.

Reference-host qualification must use freshly authenticated inventory, SSH
host identity and an accepted operator SSH profile. Public Viewer qualification
additionally requires an exact authenticated target and bounded operator-approved
public-ingress scope. No retained #219 test grants public activation authority.
Until these gates and full application/private-host tests pass, the candidate
cannot proceed to PRE_READY, Ready, merge, or completed closure of #220.
