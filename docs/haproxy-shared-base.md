<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Shared host-native HAProxy base

Deployment #219 owns the shared runtime, HTTP routing, health, hygiene, logging
and configuration lifecycle. It consumes #101's fixed backend and host-policy
owner, `product_backend_contract.py` and `product-backend-policy`. It does not
replace that owner or add SELinux/nftables exceptions. #80 owns Rocky admission.
Issue #220 owns DIRECT public listeners and canonical Viewer identity; #103 owns
DIRECT certificates. #217 owns PROTECTED authentication and reconstruction;
Issue #213 owns PROTECTED Origin TLS. This base contains none of those semantics.

## Supply and maintenance

The reviewed package is Rocky Linux 10.2 AppStream `haproxy`, epoch 0,
version **3.0.5**, release **6.el10_2.2**, with source RPM
`haproxy-3.0.5-6.el10_2.2.src.rpm`. There is no module stream or third-party
repository. `haproxy_supply_contract.py` owns exact RPM and executable SHA-256
identities for x86_64 and aarch64. Inventory names remain amd64 and arm64.

Both official architecture RPMs were retrieved and independently verified with
`rpm -Kv`: Rocky key `6fedfc85` signature, header and payload digests passed.
Their extracted executables both declare `+SYSTEMD`, `+THREAD`, `+OPENSSL` and
`+PCRE2`. The common build options include `USE_SYSTEMD=1` and
`USE_OPENSSL=1`. The amd64 installed package's `haproxy -vv` additionally proves
native execution, HTTP/1 and HTTP/2 multiplexers, systemd support and the same
feature list. Shared configuration uses HTTP checks, HTX parsing, ACLs, prefix
header deletion, UUID request IDs, bounded transaction variables and
master-worker reload. Compiled Lua/SPOE support is **not configured**; there is
no plugin, script, resolver, map mutation or administrative runtime socket.

Supply references:

- [Rocky x86_64 RPM](https://download.rockylinux.org/pub/rocky/10.2/AppStream/x86_64/os/Packages/h/haproxy-3.0.5-6.el10_2.2.x86_64.rpm)
- [Rocky aarch64 RPM](https://download.rockylinux.org/pub/rocky/10.2/AppStream/aarch64/os/Packages/h/haproxy-3.0.5-6.el10_2.2.aarch64.rpm)
- [HAProxy 3.0 configuration manual](https://docs.haproxy.org/3.0/configuration.html)
- [HAProxy 3.0 management guide](https://docs.haproxy.org/3.0/management.html)

Apply #80's enabled-repository, Rocky signature, minor-version and x86-64-v3
admission before construction. Only reviewed Rocky BaseOS/AppStream/Extras may
be enabled; this package comes from AppStream. No automatic package updates,
service restart, repository fallback or new Rocky minor is admitted. A reviewed
maintenance change updates both architecture identities, rechecks signatures,
compiled features and real binary behavior, and requalifies the affected host.
Until that change is accepted, the installed helper rejects another package
build or executable digest. Upstream version text alone is insufficient: Rocky
backports fixes in the release. Never replace the Rocky package with an ad hoc
source build to bypass supply admission.

Arm64 **package/supply is proven** from genuine signed Rocky RPM bytes. Its
compiled feature declaration is proven by those bytes. **Runtime behavior has
not been executed on arm64**. Shared HTTP source semantics are independent of
architecture, but that does not qualify arm64 systemd/SELinux behavior.

## Routing and typed composition seams

`Routing` accepts two distinct normalized DNS hostnames; `Listener` contains only
numeric IP socket coordinates. The closed JSON input has exactly
`frontend_host`, `api_host`, and `listeners`; each listener has exactly `address`
and `port`. Backend addresses, commands, modes, identity rules, TLS options,
PROXY options, secrets and configuration snippets are not input fields.

`render-haproxy-base.py ROUTING.json` previews deterministic configuration.
`--listener-unit` previews the exact TCP port constraints for systemd. There is
no checked-in live routing input or default public bind. A separately reviewed
listener owner must admit placement before deployment. The neutral HTTP socket
seam neither selects DIRECT/PROTECTED nor grants public-ingress acceptance.

Reviewed listener/identity consumers reuse `Routing`, `Listener`,
`routing_sections()` and `forwarding_sanitization()` at compile time. The
sanitization stage removes all `Forwarded`, `X-Forwarded-*`, `X-Real-IP`,
`X-SecPal-*` and caller request-ID fields. A later identity owner authenticates
its transport before sanitization and emits its own canonical metadata
thereafter. The base emits no canonical client IP, scheme or trusted proxy
configuration. Extending composition requires reviewed source and closed input
admission; no runtime-selected Python module or raw fragment is supported.

Routing uses exactly `127.0.0.1:18080` for frontend and `127.0.0.1:18081` for
API. Host matching is exact and case-insensitive, allowing explicit standard
HTTP/HTTPS ports. Unknown origins return 421; missing/duplicate Host and
non-origin-form request targets return 400. Origins never share a fallback
backend. Application paths, CORS, Sanctum, cookie and data policy remain product
contracts; the proxy does not rewrite routes, origin headers or cookies.

API eligibility checks the product's `/health/ready` for HTTP 200, rather than
Issue #101's transport-only `/health/live`. The static frontend's existing
`/health/live` is its available HTTP surface; its immutable server starts after
entrypoint initialization. It has no separate data-readiness route. The product
references examined were API `7da77556e7a4896940b6c50ccf6ba2c3fb9a8653`
(`HealthController`, health routes) and frontend
`eb2a3496112e035b70e950da072736cac8f9b427` (`docker/default.conf`). This base
introduces no product health endpoint or independent readiness definition.

Checks run every second, with one failure excluding a backend and two successes
restoring it; check timeout is three seconds. Health is sampled, not a promise
that a dependency cannot fail between samples. Recreation preserves the fixed
loopback contract. The proxy neither discovers container addresses nor accesses
a Podman/Docker socket, API, network namespace or product storage.

## HTTP hygiene and privacy

Connection timeout is 3s; client/server inactivity is 30s; complete request
headers are due in 5s; HTTP keepalive is 5s; queue is 3s; check is 3s; tunnel is
30s. There is no automatic retry of a potentially state-changing request.
The buffer is 16,384 bytes with 1,024 bytes reserved for rewriting; header count
is 64; request target length is at most 8,192 bytes. These are HTTP header/target
limits, not an upload/body-size policy. Product upload limits remain separate.
Allowed methods are GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; others
return 405 when syntactically valid. HAProxy's strict HTTP parser rejects
malformed framing/names. Its native RFC9112 behavior removes extraneous
Content-Length in TE+CL requests and closes the client connection; no relaxed
parsing or insecure framing option is enabled.

The access log records network peer, generated UUID, allowlisted method,
finite origin role, fixed backend/server, status, bytes, duration, termination
and finite security outcome. The peer is the socket peer, never a reconstructed
Viewer identity. Raw URI/path/query/Host, arbitrary method tokens, supplied
request IDs, captured headers, credentials, cookies and bodies are omitted.
This retains routing/rejection diagnosis without logging customer identifiers
that can occur inside a URL. Identity consumers own any additional canonical
client field. HAProxy health failures use a fixed readiness description;
reload diagnostics come from master-worker operation. Validation failures emit
bounded operation identities and discard subprocess output. No log retention
or customer-production guarantee is introduced.

## Host service and configuration lifecycle

Install the reviewed drop-in as
`/etc/systemd/system/haproxy.service.d/secpal.conf`, retaining the Rocky package
service. It clears optional environment files, arguments and `conf.d` loading.
The sole executable is `/usr/sbin/haproxy -Ws`; root master and dedicated
non-login `haproxy` workers remain outside product authority. Notify semantics
and mixed stop behavior are retained. Systemd hardening constrains filesystem,
devices, capabilities, address families and socket binds. The separately
rendered `secpal-listeners.conf` admits exactly the reviewed listener ports;
backend ports cannot be listeners. Runtime sockets/storage paths are hidden.
The unit binds to and starts after #101's policy service: withdrawing that
service also stops HAProxy.

Host construction remains #92's responsibility. The administrator installs the
helper at `/usr/local/libexec/secpal/haproxy-config` and its four imported library
files in that directory, from reviewed source. Complete ancestor paths and
files must be root-owned, regular where applicable, without group/other write
access, symlinks or hard-linked authority files. Scripts can be 0555 and inputs 0444. Install the desired closed input at `/etc/haproxy/secpal-routing.json` and
the two systemd drop-ins before activation; reload the system manager after
unit installation. Product accounts cannot modify any of these inputs.

`haproxy-config --activate` admits package bytes/features, #101's effective
policy/barrier and the listener unit, and requires `haproxy.service` inactive.
It generates a restrictive same-directory candidate, restores the stock Rocky
`haproxy_conf_t` label, validates with the actual `haproxy -c -q`, and atomically
publishes `/etc/haproxy/secpal.cfg` as 0444. A fixed root-only lock serializes
publication. File/directory synchronization prevents partial active writes.
The `/run/haproxy` directory is root-owned 0755, with root-only lifecycle lock
and runtime PID file; workers gain no mutable configuration authority.

Startup `--check` independently regenerates the accepted serving bytes from
closed embedded reviewed input comments, validates syntax and rechecks #101.
It does not use a pending desired input: a rejected desired specification must
not prevent last-known-good startup. The comments contain configuration inputs,
not observed or mutable live state. There is no persisted server-state file.

`ExecReload` generates and validates before replacement or signal. Listener
coordinates must remain unchanged. It verifies the systemd master process,
signals SIGUSR2 and waits boundedly for a new worker generation with the dedicated
UID and effective `haproxy_t` domain. A read-only generation diagnostic must be
served on every configured listener from that exact new worker PID, with the
expected reviewed configuration fingerprint. It uses the existing origin and
method/header bounds and returns only 204 plus PID/fingerprint; it neither
checks product readiness nor grants backend access, identity or mutation.
A transient correctly labeled worker without this serving proof is rejected. Old workers drain up to 35s (above the 30s
request inactivity limit). Invalid candidates never replace accepted bytes or
signal HAProxy. On a reload failure, accepted disk bytes are restored before
one bounded compensating reload; no automatic retry loop exists. An unavailable
or contradictory reload observation is a failure, not a successful activation.
Changing listening sockets is a separately reviewed host-construction operation.

SELinux must be Enforcing and `haproxy_connect_any`/`pasta_bind_all_ports` off.
Reuse #101's dedicated `secpal_backend_port_t`, exact labels, effective
allow/deny decisions, dedicated-UID nftables rules and mandatory barrier.
This base adds no SELinux module, boolean, connect-any privilege, local UID
exception, container runtime authority or namespace escape. Stock binary,
configuration and runtime labels must be observed on the actual host, not
inferred from repository text.

## Evidence and remaining qualification

Focused source validation:

```bash
python3 tests/haproxy-base-contract.py
python3 tests/haproxy-base-runtime.py
python3 tests/product-backend-contract.py
./scripts/preflight.sh
```

The runtime suite requires real HAProxy and unused fixed backend ports. It runs
an isolated non-root master-worker process and synthetic HTTP peers, removing
only privilege-dropping directives from the generated test configuration. It
proves binary syntax, origin separation, readiness exclusion/recovery,
fixed-socket HTTP peer recreation, request hygiene, actual log exclusion,
invalid candidate preservation and an in-flight request across graceful reload.
These peers are not real rootless product workloads or a privileged host-policy
qualification. Configuration callbacks cannot substitute for installed-service
reload evidence. Contract tests separately reject wrong ports, container
addresses, sockets/APIs, arbitrary extensions and identity/TLS/secret inputs.

The current workspace's real Rocky amd64 binary supplies local execution
proof. Its active host is not qualified: a non-Rocky repository is enabled and
`pasta_bind_all_ports` is on. No service/firewall/SELinux mutation was performed.
A conforming administrator-controlled Rocky host is still required to exercise
the installed drop-in/helper, effective labels/UIDs, startup barrier,
intended/unrelated-UID and external-interface policy, actual rootless workload
recreation, journal privacy and reload/LKG. Arm64 installed execution is also
unproven. Do not turn these gaps into PASS or infer them from signed RPM supply.

Actual reference-host evidence, when available, must be bounded and bound to
the exact reviewed source tree, with independently revalidated observations.
It may establish only the tested host/architecture/outcomes. GCP #294 is
explicitly deferred and is not a gate here; no alternate cloud requirement is
introduced. No GCP, multi-provider, Managed Production, HA or customer-production
acceptance is granted. #248 may consume this base only within its genuinely
proven scope. #220 and certificate/auth consumers remain separate deliveries.
