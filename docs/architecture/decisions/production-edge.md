<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Production edge decision

## Status

Accepted for the single-host production reference. This ADR is a decision and
contract only: it installs nothing, publishes no port, changes no firewall or
DNS, and obtains no certificate.

## Context and requirements

D.1 fixes Debian 13/trixie, amd64 and arm64, rootless Podman 5.x with crun,
Netavark/Aardvark and pasta, and systemd-user/native Quadlet for product and
data workloads. D.2 fixes the state and secret boundaries, including the
reserved `/srv/secpal/edge`, `/srv/secpal/acme`, and `/srv/secpal/crowdsec`
namespaces. The production edge must preserve those decisions while making
only one ingress authority public.

The mandatory outcome is two exact, inventory-supplied HTTPS origins:

- `https://<frontend-host>` sends every path only to the frontend backend.
- `https://<api-host>` sends every path, including API and Sanctum paths, only
  to the API backend.

Unknown hosts and unmatched SNI do not reach either backend. There is no
same-origin mode and the frontend image never proxies the API. TLS and ACME
state remain outside both product images.

## Candidates and evidence

The bounded candidate set is Debian's standard NGINX and Caddy packages. Both
are credible reverse proxies, support TLS 1.2/1.3, exact virtual hosts,
dual-stack listeners, configuration validation, graceful reload, and
structured logs. A third proxy would add no material decision distinction.

| Criterion               | NGINX                                                                                                   | Caddy                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Debian 13 provenance    | `nginx` 1.26.3-3+deb13u7 from trixie/security                                                           | Caddy 2.6.2 stable line; 2.6.2-12+b3 is indexed and 2.6.2-12+deb13u1 was accepted into stable-security                         |
| amd64 and arm64         | Both published                                                                                          | Both published; the newer 2.11 backport is amd64-only                                                                          |
| Update model            | Debian stable/security package revision, reviewed activation                                            | Debian stable/security package revision, reviewed activation                                                                   |
| Least privilege         | Dedicated non-login user; only `CAP_NET_BIND_SERVICE`; root-owned configuration                         | Same host-service shape is feasible, but native ACME adds certificate-state write authority to the public process              |
| Rootless/read-only      | Host process, not a rootless container; system paths read-only with bounded runtime/log writes          | Host process is feasible; containerizing reintroduces the D.1 public-port and source-address uncertainty                       |
| systemd/Quadlet         | system service in front of rootless user Quadlets; no runtime socket                                    | system service in front of rootless user Quadlets; no runtime socket                                                           |
| Validation/reload       | `nginx -t`; HUP starts new workers and retains old configuration on apply failure                       | `caddy validate`; API-driven graceful reload retains the working configuration on failure                                      |
| ACME                    | Separate Debian Certbot authority and deploy hook                                                       | Native automatic HTTPS in the public process                                                                                   |
| Logs/privacy            | Native JSON escaping and a closed format using `$uri` without query arguments                           | Structured logs and filters; richer current log facilities are newer than trixie's 2.6 line                                    |
| Client identity         | Direct listeners use the kernel socket peer in `$remote_addr`; no real-IP rewriting                     | Direct listeners also expose the socket peer                                                                                   |
| CrowdSec                | Privacy-safe access log plus independent nftables firewall bouncer; optional Lua L7 bouncer is rejected | Privacy-safe access log plus independent nftables firewall bouncer; no edge plugin required                                    |
| Supply chain/complexity | One proxy package plus the separately scoped ACME package; no modules or plugins                        | One proxy package, but the supported trixie line is old and newer distribution choices lose the closed two-architecture policy |
| Testability             | Native syntax test, socket evidence, log parsing, and graceful reload are locally testable              | Equivalent tests are possible, subject to the selected older feature set                                                       |

Primary capability and provenance sources checked on 2026-08-22:

- [Debian nginx package](https://packages.debian.org/trixie/nginx) and
  [Debian Caddy package](https://packages.debian.org/trixie/caddy) establish
  current versions and architectures.
- [NGINX configuration control](https://nginx.org/en/docs/control.html),
  [proxy headers](https://nginx.org/en/docs/http/ngx_http_proxy_module.html),
  and [JSON-capable access logs](https://nginx.org/en/docs/http/ngx_http_log_module.html)
  establish validation, rollback, forwarding, and logging behavior.
- [Caddy service operation](https://caddyserver.com/docs/running),
  [automatic HTTPS](https://caddyserver.com/docs/automatic-https), and
  [access logging](https://caddyserver.com/docs/caddyfile/directives/log)
  establish the compared Caddy capabilities.
- [Podman rootless networking](https://github.com/containers/podman/blob/v5.4.2/docs/tutorials/basic_networking.md)
  documents the public-port/source-address distinction that D.4 must test
  rather than assume.
- [CrowdSec firewall remediation](https://docs.crowdsec.net/u/bouncers/firewall/)
  establishes asynchronous nftables decisions for IPv4 and IPv6.

No material capability used to select NGINX is unknown. Real host networking
behavior is deliberately evidence owned by D.4, not a claim made from
documentation.

## Decision

The reference edge is Debian NGINX as a hardened **host system service**.
Operator root owns installation, the systemd definition, immutable
configuration, and activation. The master and workers run as a dedicated
non-login `secpal-edge` system identity, not root and not the rootless product
service account. Its capability bounding and ambient sets contain only
`CAP_NET_BIND_SERVICE`. `NoNewPrivileges` is enabled; the system filesystem is
read-only; writable paths are limited to a bounded runtime directory and the
service emits logs to stdout for the operator-owned log authority. The selected
`/srv/secpal/edge` namespace is root-owned, grouped to the edge identity, mode
`0750`, and runtime-read-only; reviewed configuration inside it is root-write,
edge-read. The service receives no Podman/Docker socket, host network namespace
from a container, firewall authority, product secret, or ACME write authority.

The initial selected package inputs are:

- `nginx=1.26.3-3+deb13u7` on amd64 and arm64; and
- for the later D.5 ACME implementation,
  `certbot=4.0.0-2+deb13u1` (`all`).

Both must come from authenticated Debian 13 `trixie` or `trixie-security`
metadata. Installation records the exact package versions. Debian package
revision changes, including security fixes on the same upstream line, require
a reviewed maintenance change, local validation, and controlled restart or
reload under D.9. No backports, external package repository, unattended edge
upgrade, upstream binary, container tag, `latest`, or runtime version discovery
is supported. A different upstream line or Debian major version requires this
ADR to be reviewed and amended or superseded.

### Public and backend boundaries

NGINX alone owns direct TCP listeners on IPv4 `0.0.0.0:80/443` and IPv6
`[::]:80/443`; the IPv6 sockets are explicitly IPv6-only so their evidence
cannot be satisfied through IPv4-mapped acceptance. Port 80 exists only for
the D.5 ACME/redirect contract. The listener is not a rootless port forward,
NAT gateway, load balancer, CDN, or provider proxy. An upstream component that
changes the socket peer is unsupported until a superseding ADR defines and
proves that trust boundary.

Frontend and API remain rootless containers generated by root-owned native
Quadlets under the systemd user manager. Each exposes its HTTP listener only
on a distinct, fixed, high host loopback port. D.4 must apply host nftables
output policy so only the dedicated edge UID (plus an explicitly justified
local validation authority) can connect to those exact ports. PostgreSQL,
Valkey, migration, workers, and scheduler publish no port and have no edge
network membership. No product role receives host networking, a runtime
socket, TLS keys, `NET_ADMIN`, or firewall authority.

The edge system service and the rootless user target are deliberately separate
systemd managers. Neither controls the other through the Podman API. Backend
unavailability yields a bounded gateway error; it does not grant the edge
runtime authority. D.4 owns ordering, readiness, restart policy, the exact
loopback ports, and proof of the UID-filtered path.

### Client address and proxy trust

The selected path is:

```text
external IPv4 or IPv6 client
  -> host public interface and kernel TCP listener
  -> NGINX ($remote_addr is the direct socket peer)
  -> UID-filtered host loopback port
  -> rootless Podman port forwarder
  -> API HTTP listener
```

There is no trusted proxy before NGINX. NGINX does not enable the real-IP
module and never derives `$remote_addr` from a header. It discards incoming
`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`,
`X-Forwarded-Host`, and `X-Forwarded-Port`. For each backend request it writes
one new `X-Forwarded-For` and `X-Real-IP` value from `$remote_addr`, plus
`X-Forwarded-Proto: https`, the statically selected canonical origin host, and
`X-Forwarded-Port: 443`. It does not use `$proxy_add_x_forwarded_for` and does
not send `Forwarded`, avoiding an invented IPv6 serialization layer.

The API may trust forwarded metadata only when the TCP peer is one of the
exact immediate rootless-forwarder addresses independently observed by D.4
for the closed IPv4 and IPv6 backend paths. It must not trust loopback CIDRs,
RFC 1918, ULA, container-network ranges, `private_ranges`, every proxy, or a
caller-controlled token. The UID-filtered loopback rule and the API peer
allowlist are both required: a header alone is never client-identity evidence.

D.4 must use external IPv4 and IPv6 clients and socket/network capture to prove
independently that the public socket peer equals the client address, NGINX logs
that address, NGINX overwrites spoofed forwarding headers, and the API accepts
only the edge-authored value from each exact immediate peer. If either address
family is NATed, collapsed, unavailable, or differs from this model, D.4 must
stop and supersede this ADR before implementation proceeds.

### TLS and ACME authority

TLS 1.2 and 1.3 terminate only in NGINX. Backend HTTP remains on the protected
local path. Product images never receive a certificate, private key, ACME
account, challenge response authority, or TLS configuration.

D.5 will run the pinned Debian Certbot package as a separate root-owned TLS
operator. Its account, renewal, certificate, and private-key state is the D.2
directory `/srv/secpal/acme`, mode `0700`; NGINX cannot write or traverse that
authority. After successful issuance or renewal, D.5 must validate a complete
matching certificate/key pair and atomically publish only the current runtime
pair through a restricted read-only `/run/secpal` delivery visible to the edge
identity. It then runs `nginx -t` and requests a graceful reload. Partial or
invalid state never replaces the last valid runtime pair. D.5 owns hostname
and DNS preconditions, ACME execution, challenge routing, renewal tests,
HTTP-to-HTTPS behavior, and HSTS activation; this ADR performs none of them.

### CrowdSec seam

D.6 may read the closed edge access-log schema below using a least-authority
local acquisition. The selected remediation seam is the separately pinned
host CrowdSec firewall bouncer in asynchronous nftables mode for both IPv4 and
IPv6. It receives no product-runtime or Podman authority. NGINX does not query
CrowdSec synchronously and no NGINX Lua module, dynamic bouncer, WAF plugin, or
runtime plugin download is selected. CrowdSec unavailability marks security
`DEGRADED`; it does not make frontend/API readiness fail. D.6 owns exact
packages, locally reviewed scenarios and parsers, cached-decision behavior,
remediation tests, and the no-moving-Hub-content rule.

### Logging and privacy

NGINX emits one JSON access record using JSON escaping and a closed field set:

- trusted socket `client_ip`, timestamp, method, and the static canonical host;
- normalized `$uri` path, never `$request_uri` or query arguments;
- response status, response bytes, and request duration; and
- fixed upstream identity and upstream status.

NGINX writes these records to stdout. The systemd/journal boundary and the
later D.6 least-authority collector, not the public process, own persistence
under the D.2 `/srv/secpal/logs` contract.

Authorization and proxy-authorization headers, cookies, query strings, raw
tokens, request/response bodies, referrers, and arbitrary headers are never
logged. User-agent is omitted because D.6 has no demonstrated need that
outweighs its personal-data cost. Error logs must not add request bodies,
secrets, or unbounded header dumps. D.6 owns bounded retention, permissions,
rotation, parser admission, and any future privacy review; there is no analytics
platform in this decision.

### Supply chain and failure semantics

The complete NGINX configuration, systemd policy, ACME policy, future CrowdSec
policy, parsers, and remediation inputs are reviewed local files. Includes may
resolve only inside their root-owned local configuration trees. Production
admits no dynamic modules, plugins, remote includes, recommended configuration,
automatic network fetch, moving blocklist, moving CrowdSec Hub content, or
registry contact. Any later module becomes a new immutable, reviewed dependency
and requires this ADR to be amended first.

Before activation, D.4 runs `nginx -t` with the installed pinned binary. An
invalid configuration is rejected. A reload sends HUP only after validation;
NGINX starts replacement workers before gracefully retiring old workers, and
an apply failure retains the old configuration. A failed sole edge makes both
origins publicly unavailable and must be observable; this single-host reference
does not claim high availability. D.4 owns systemd restart/backoff and edge
health evidence.

ACME issuance or renewal failure leaves the last valid certificate active and
is surfaced for D.5 retry/operator action; partial files are fail-closed.
CrowdSec loss is the asynchronous degraded-security state described above and
is owned by D.6. None of these failures permit direct product publication.

## Normative decision contract

The following closed summary is the authoritative input to the focused static
and negative-mutation tests. Prose above explains the values; downstream work
must implement rather than redefine them.

<!-- production-edge-contract:start -->

```json
{
  "schema_version": 1,
  "status": "accepted",
  "reference_edge": {
    "technology": "nginx",
    "phase_b_gateway": false
  },
  "distribution": {
    "package": "nginx=1.26.3-3+deb13u7",
    "architectures": ["amd64", "arm64"],
    "suites": ["trixie", "trixie-security"]
  },
  "runtime_authority": {
    "model": "host-system-service",
    "user": "dedicated-secpal-edge",
    "capabilities": ["CAP_NET_BIND_SERVICE"],
    "read_only_system": true,
    "edge_state": "/srv/secpal/edge-root-owned-edge-read-only"
  },
  "orchestration": {
    "edge": "systemd-system",
    "backends": "systemd-user-native-quadlet",
    "podman_api_socket": "forbidden",
    "docker_socket": "forbidden"
  },
  "public_boundary": {
    "public_roles": ["edge"],
    "private_roles": [
      "frontend",
      "api",
      "migrate",
      "worker-general",
      "worker-hash-chain",
      "scheduler",
      "postgresql",
      "valkey"
    ],
    "listeners": ["0.0.0.0:80", "[::]:80", "0.0.0.0:443", "[::]:443"],
    "product_public_ports": false
  },
  "origins": {
    "frontend": "https://<frontend-host> -> frontend-only",
    "api": "https://<api-host> -> api-only-all-paths",
    "same_origin": false,
    "frontend_api_proxy": false
  },
  "backend_boundary": {
    "transport": "owner-filtered-loopback-high-ports",
    "product_host_network": false,
    "data_edge_membership": false
  },
  "proxy_trust": {
    "allowlist": "exact-d4-proven-immediate-peer-addresses",
    "wildcards": false,
    "caller_headers_are_identity": false
  },
  "forwarded_metadata": {
    "discard": [
      "Forwarded",
      "X-Forwarded-For",
      "X-Forwarded-Host",
      "X-Forwarded-Port",
      "X-Forwarded-Proto",
      "X-Real-IP"
    ],
    "set": [
      "X-Forwarded-For",
      "X-Real-IP",
      "X-Forwarded-Proto",
      "X-Forwarded-Host",
      "X-Forwarded-Port"
    ]
  },
  "client_identity_evidence": {
    "ipv4": "direct-socket-peer-to-edge-then-edge-authored-header",
    "ipv6": "direct-socket-peer-to-edge-then-edge-authored-header",
    "upstream_proxy": "unsupported-without-superseding-adr"
  },
  "tls": {
    "termination": "edge-only",
    "product_tls": false
  },
  "acme": {
    "client": "certbot=4.0.0-2+deb13u1",
    "authority": "root-tls-operator",
    "state": "/srv/secpal/acme",
    "edge_access": "runtime-read-only-last-valid-publication"
  },
  "logging": {
    "format": "json",
    "sink": "stdout-to-operator-log-authority",
    "path_field": "$uri-without-query",
    "fields": [
      "client_ip",
      "timestamp",
      "method",
      "canonical_host",
      "canonical_path",
      "status",
      "response_bytes",
      "request_duration",
      "upstream_id",
      "upstream_status"
    ],
    "forbidden": [
      "authorization",
      "cookies",
      "query",
      "request_body",
      "tokens",
      "user_agent"
    ]
  },
  "crowdsec": {
    "remediation": "asynchronous-host-nftables-firewall-bouncer",
    "ipv4": true,
    "ipv6": true,
    "application_readiness_dependency": false,
    "l7_plugin": false
  },
  "supply_chain": {
    "runtime_downloads": [],
    "plugins": [],
    "remote_configuration": false,
    "moving_blocklists": false,
    "reviewed_updates_only": true
  },
  "failure_semantics": {
    "invalid_config": "reject-before-activation",
    "reload_failure": "retain-working-config",
    "edge_failure": "publicly-unavailable",
    "acme_failure": "retain-last-valid-certificate",
    "crowdsec_failure": "security-degraded-application-independent"
  },
  "phase_b": {
    "caddy_image": "test-only-not-promoted",
    "internal_ca": "disposable-not-promoted",
    "playwright_gateway": "behavioral-evidence-not-production"
  },
  "downstream": {
    "d4_issue": 12,
    "d5_issue": 13,
    "d6_issue": 14
  }
}
```

<!-- production-edge-contract:end -->

## Rejected promotion and downstream obligations

The Phase B/D.1a gateway remains disposable test evidence. Its locally built
Caddy image is not the pinned Debian NGINX distribution; it runs as a test
container, publishes only a loopback fixture port, uses an internal disposable
CA, trusts stack-local test metadata, and exists to drive Playwright. None of
its image, CA, credentials, routing configuration, dynamic port behavior, or
trust rule is promoted.

D.4 (#12) implements and proves the selected public/loopback topology, exact
backend peer allowlist, dual-stack source paths, spoofed-header overwrite,
firewall owner rule, configuration validation, reload, health, and process
failure behavior. D.5 (#13) implements DNS preconditions, Certbot state and
runtime publication, challenges, renewal, redirects, and HSTS. D.6 (#14)
implements the pinned CrowdSec engine/bouncer inputs, local log acquisition,
privacy and retention controls, IPv4/IPv6 remediation, degraded mode, and
security-profile evidence.

This decision-only change can be reverted without external cleanup. If real
D.4-D.6 evidence disproves a premise, implementation stops and a dedicated ADR
change amends or supersedes this decision before another edge technology or
trust path is activated.
