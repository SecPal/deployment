<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# DIRECT Viewer Edge decision

**Status:** Accepted
**Decision authority:** SecPal maintainers, under accepted
[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)
**Delivery owner:** [deployment #89](https://github.com/SecPal/deployment/issues/89)

## Scope and authority

This record makes the accepted DIRECT decision durable for Rocky Linux 10.2+
with SELinux enforcing. ADR-019 owns the two Edge modes and their trust
boundaries; [ADR-022](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-deployment-topology-high-availability-adr022.md)
owns the orthogonal `single`, `replacement`, and `ha` topologies. This record
applies those authorities to DIRECT without replacing either ADR.

PROTECTED remains a separately accepted mode: CloudFront Multi-Tenant owns the
public Viewer Edge, while host-native HAProxy remains the authenticated
Origin/backend boundary. PROTECTED is neither superseded nor implemented here;
its implementation belongs to [#209](https://github.com/SecPal/deployment/issues/209)
descendants.

This decision supersedes closed [#11](https://github.com/SecPal/deployment/issues/11)
and the historical [Debian/NGINX/Certbot/no-WAF decision](production-edge.md)
where they conflict with the current DIRECT architecture. Historical package
pins, no-upstream-proxy rules, and no-L7-integration rules are not current
implementation authority. Descendants implement this decision; changing the
Edge technology, runtime authority, client-identity model, or certificate
authority requires a new architecture-level decision.

## Selected Edge and endpoint contract

The DIRECT reference Viewer Edge is **host-native HAProxy**, managed by systemd
under SELinux, outside rootless product-container authority. HAProxy owns Viewer
TLS termination, public HTTP(S) ingress, routing, health-based backend selection,
canonical client identity, and HTTP hygiene.

In DIRECT, only HAProxy owns public application ingress. Frontend and API
backends, workers, scheduler, PostgreSQL, and control endpoints remain private.
Product containers have no public-port, public-TLS, ACME, public-listener
certificate, or Edge runtime authority. HAProxy consumes fixed private loopback
backends without container-IP discovery or Podman/Docker socket/API access.

Frontend and API remain **separate HTTPS origins**: the frontend origin routes
only to frontend backends; the API origin routes all its application paths only
to API backends. Unknown hosts and unmatched SNI cannot reach either backend.
There is no same-origin shortcut or frontend-owned API proxy.

HAProxy's backend-pool, health, and routing abstraction supports `single`,
temporary `replacement`, and permanent `ha` without replacing the Edge
architecture or changing application endpoint contracts. Topology changes do
not collapse the two origins or grant product containers public authority.

## DIRECT client identity

### Single

Public Viewer TCP reaches HAProxy directly. The canonical client IP is the
public TCP source. The normal public listener does **not** accept PROXY protocol;
public PROXY input is rejected. HTTP headers never override the TCP source.

### HA

The preferred upstream is a trusted L4/TCP load balancer using PROXY protocol,
with v2 preferred where cleanly supported. ADR-019's reference trusted HA seam
uses PROXY v2. PROXY input is accepted only on a **separate trusted/private
listener** from explicitly allowlisted LB peers. Public or unauthorized PROXY
input is rejected, and direct bypass of that trusted boundary is blocked.
Neither application backends nor an alternate backend-edge listener may provide
a direct route around the trusted LB path.

The canonical client IP comes from validated PROXY metadata admitted through
that seam. The actual network peer remains the LB and is preserved separately;
it must not be lost when deriving canonical client identity. Adding an upstream
that changes identity outside this model requires an architecture decision.

### Canonical forwarding and application trust

HAProxy discards/overwrites caller-controlled `Forwarded`, `X-Forwarded-For`,
`X-Forwarded-Proto`, and `X-Real-IP`, including duplicate values and other
`X-Forwarded-*` metadata that could become authoritative. It then emits exactly
one reviewed canonical downstream forwarding set. It never appends trusted
identity to a caller-supplied forwarding chain.

Canonical downstream client IP derives only from the topology's trusted source
above; external host derives from the admitted frontend/API origin, and scheme
from HAProxy's Viewer TLS boundary. Caller forwarding headers are never
authority. SecPal trusts forwarded metadata **only from HAProxy** through the
reviewed private backend path and exact trusted-peer admission; wildcard proxy
trust is forbidden. Rootless transport does not grant arbitrary local peers
authority to impersonate HAProxy.

HAProxy, CrowdSec, WAF/AppSec, logs, and application downstream processing consume
the same canonical client identity semantics. The network peer and canonical
client remain distinct fields even when they are equal in `single`.

## TLS and protocol commitment

HAProxy terminates DIRECT Viewer TLS. **External Certbot** is the current ACME
reference; HAProxy's experimental built-in ACME is not selected. Product API
and frontend containers own neither public TLS nor ACME state or certificates.
Certbot package/supply qualification and certificate lifecycle implementation
belong to [#103](https://github.com/SecPal/deployment/issues/103).

The reference supports HTTP/1.1 and HTTP/2, with TLS 1.2/1.3 implemented by the
TLS owner. There is **no HTTP/3 commitment**. ADR-019's exact HTTP-01 handling,
other-HTTP redirect, validated atomic certificate publication, graceful reload,
and last-known-good requirements remain binding; their implementation stays
with #103. PROTECTED Viewer and Origin certificates are separate lifecycles.

## Security, failure, and access logs

The DIRECT WAF/security integration target is **CrowdSec HAProxy SPOA + CrowdSec
AppSec (Coraza engine) + pinned OWASP CRS**, within ADR-019's layered security
architecture. A separate Coraza service is not selected unless a later concrete
requirement proves the need. Security services remain outside product-container
authority.

CrowdSec/AppSec outage is Security **DEGRADED** and does not by itself make
SecPal unavailable or fail application readiness/authentication. HAProxy Edge
failure remains availability-critical. Degraded security never authorizes
direct product publication or weakening the client-identity boundary.

The privacy-safe access-log contract preserves at least:

- network-peer IP and canonical-client IP;
- request ID, method, admitted host, and path without query secrets;
- status, byte counts, duration, and selected backend; and
- relevant security outcome, including degraded security.

Credentials, Authorization/proxy-authorization headers, cookies/session secrets,
tokens, and request/response bodies are excluded from access logs; request bodies
are not logged by default. Query strings and arbitrary header dumps cannot
introduce secrets into access or error logs. Logs preserve canonical identity
without granting log producers runtime or firewall authority.

## Rationale and implementation ownership

HAProxy preserves one backend-pool/health/routing abstraction across single,
replacement, and HA. For the accepted security stack, it avoids a custom
Caddy/xCaddy module supply chain and the weaker NGINX/Coraza connector path.
This is an architecture selection, not a claim that package provenance or real
Rocky runtime behavior has already been qualified.

Implementation remains with existing leaves; these links are ownership
navigation, not a duplicate dependency graph:

- [#101](https://github.com/SecPal/deployment/issues/101): fixed loopback backend
  publishing and private transport enforcement.
- [#219](https://github.com/SecPal/deployment/issues/219): shared HAProxy package,
  systemd/SELinux runtime, routing, health, HTTP hygiene, and logging base.
- [#220](https://github.com/SecPal/deployment/issues/220): DIRECT public/private
  listeners, canonical identity, forwarding reconstruction, application trust,
  spoofing/bypass rejection, and end-to-end evidence.
- [#103](https://github.com/SecPal/deployment/issues/103): DIRECT Certbot supply,
  ACME, certificate publication/renewal, and TLS lifecycle.
- [#105](https://github.com/SecPal/deployment/issues/105): host CrowdSec decisioning
  and bounded remediation; [#106](https://github.com/SecPal/deployment/issues/106):
  HAProxy SPOA/AppSec/Coraza/CRS integration.

This decision installs no package, publishes no backend or public port, obtains
no certificate, and mutates no DNS, provider resource, or live system. Native
GitHub relationships remain authoritative for prerequisites and delivery state.
