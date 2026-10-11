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
`USE_OPENSSL=1`. Actual amd64 and arm64 installed packages' `haproxy -vv` additionally prove
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

Both architectures have independently verified signed package supply and
compiled features. Installed systemd/SELinux and HAProxy behavior were also
executed separately on genuine x86_64 and aarch64 Rocky reference hosts; see
the bounded evidence below. These executions qualify only the tested systems
and outcomes, rather than every host on either architecture.

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
The root master retains `CAP_KILL` to signal its dedicated-UID workers during
reload and shutdown; workers drop all effective capabilities. A fixed
`ExecStartPost` witness refuses startup unless the master and a serving worker
have the expected UID, `haproxy_t` domain, cgroup and configuration generation.
The unit binds to and starts after #101's policy service: withdrawing that
service also stops HAProxy.

Host construction remains #92's responsibility. The administrator installs the
helper at `/usr/local/libexec/secpal/haproxy-config` and its four imported library
files in that directory, from reviewed source. Install the independently Rocky-signature-verified
architecture-specific reviewed RPM there as `haproxy-reviewed.rpm` (root-owned
0444). The helper checks its exact digest and uses native `rpm -V -p` to verify
all installed package files against that authenticated payload. Complete ancestor paths and
files must be root-owned, regular where applicable, without group/other write
access, symlinks or hard-linked authority files. Scripts can be 0555 and inputs 0444. Install the desired closed input at `/etc/haproxy/secpal-routing.json` and
the two systemd drop-ins before activation; reload the system manager after
unit installation. Activation and startup reject `NeedDaemonReload=yes`,
an unexpected package fragment or any additional loaded drop-in. The manager
must have loaded exactly the reviewed base and listener files. Product accounts
cannot modify any of these inputs.
Install `config/production/host-selinux/secpal_haproxy_runtime.cil` beside the
helper. Its only permission is the `init_t` to `haproxy_t` process transition
under `NoNewPrivileges`; its only file-context mapping gives the private
`/run/haproxy` directory the existing stock `haproxy_var_run_t` type. It grants
no backend, container, unrelated-UID or connect-any permission. The stock
Rocky configuration context is `etc_t`; `haproxy_conf_t` is not a type in the
observed Rocky 10.2 policy. The #101 unit uses `RuntimeDirectoryMode=0755` for
its public read-only startup barrier, while retaining `UMask=0077`.

`haproxy-config --activate` admits package bytes/features, #101's effective
policy/barrier and the listener unit, and requires `haproxy.service` inactive.
While inactive, activation installs the fixed reviewed runtime policy and
restores its runtime labels. It generates a restrictive same-directory
candidate, restores the stock Rocky configuration label, validates with the actual `haproxy -c -q`, and atomically
publishes `/etc/haproxy/secpal.cfg` as 0444. A fixed root-only lock serializes
publication. File/directory synchronization prevents partial active writes. A directory-sync
failure after replacement restores the accepted bytes before bounded live
recovery. Reload requests reapply and witness the live generation even when
the desired bytes equal the serving file; disk equality never proves recovery.
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
The small runtime module above preserves confinement with `NoNewPrivileges`;
it adds no boolean, backend privilege, connect-any privilege, local UID
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

The workspace binary supplies local execution evidence only. Its host is not
qualified: its non-Rocky repository and broad rootless-network boolean were
not changed. The seven local binary cases were run in an isolated unprivileged
network namespace because unrelated workloads occupied the fixed backend ports.
That local test is distinct from the installed reference-host qualification.

On 2026-10-11, the operator-authorized disposable Hetzner CX23, CAX21 and CX33
servers were independently rebuilt in place, authenticated with fresh SSH host
keys through the provider console, and qualified on Rocky Linux 10.2. The
[historical observation record](evidence/haproxy-rocky-reference.json) retains
exact resource/image/action identities, installed signed package provenance,
runtime source hashes, real process domains/UIDs, negative security outcomes,
recreation, reload and last-known-good observations. Raw observations and exact
public controller inputs remain retained in the original qualification workspace.
The record is evidence, not a desired configuration or live-state input.

| Host  | Resource ID | Architecture | Image ID  | Rebuild action  |
| ----- | ----------- | ------------ | --------- | --------------- |
| CX23  | 163965414   | x86_64       | 245249370 | 660832265333033 |
| CAX21 | 169716995   | aarch64      | 245249744 | 660849445245896 |
| CX33  | 163717938   | x86_64       | 245249370 | 660849445254580 |

Each host independently demonstrated Enforcing SELinux after reboot, rootless
Quadlet execution with correlated cross-MCS denial, disabled runtime sockets,
Issue #101's exact effective SELinux/nftables policy, unrelated-UID and non-loopback
ingress denial, confined root-master/dedicated-worker operation and startup
refusal when the required transition was disabled. The same fixed public
bootstrap input was exercised on both x86_64 servers; architecture-correct
package and image inputs were separately exercised on ARM64. This proves
provider **REBUILD**, not fresh provider-resource **CREATE** or repeated rebuild
of every individual server. Server/IP identities and unrelated cloud resources
were preserved; no cloud Volumes, snapshots, backups or networks were deleted.

The product fixture used accepted pinned API/frontend images and an actual
rootless disposable PostgreSQL 18.6 dependency, real migrations, one synthetic
tenant and the scheduler heartbeat. API `/health/live` remained distinct from
`/health/ready`; missing readiness dependencies were not bypassed. The fixture's
ephemeral tenant key file used the pinned API's required 0600 mode with read-only
consumer delivery. This is bounded test preparation, not native PostgreSQL #81,
production construction #92, Host Enrollment #241 or Deployment Activation #100.
No production secret or customer data was used.

Actual installed HAProxy processing proved distinct private test origins,
health exclusion and recovery across real rootless frontend/API recreation,
malformed requests, methods, header/target bounds and the request-header timeout.
Synthetic requests observed on the real backend socket proved forwarding-header
removal; actual journal output excluded synthetic credential, cookie, URI/query,
body and caller-ID markers while retaining bounded routing/rejection diagnostics.
Invalid candidates preserved the serving generation. Valid reload preserved the
master, admitted the exact new worker/fingerprint and completed an in-flight
request. A deliberately blocked administrator serving witness caused a failed
reload and bounded restoration; uninterrupted allowed frontend samples and the
restored accepted fingerprint were observed. Withdrawing #101's policy stopped
the products and proxy; restoring it recovered genuine API readiness and routing.
Temporary packet-capture, ingress and restrictive firewall probes were cleaned.

The pilot uncovered real installed-host defects that source fixtures missed:
the public backend barrier inherited root-only directory access, `NoNewPrivileges`
suppressed the stock HAProxy domain transition, the private runtime directory
needed its stock label, and the root master needed permission to signal its
workers. The small corrections above retain confinement and narrow backend
permissions. A startup serving/domain witness now rejects an unconfined process.

The private test listener was `127.0.0.1:8080` with synthetic `.example.invalid`
origins. No DNS/TLS or public Viewer identity for `app.secpal.dev` or
`api.secpal.dev` was configured. GCP #294 remains explicitly deferred; no GCP,
multi-provider, Managed Production, HA or customer-production acceptance is
granted. #248 may consume the tested shared base and host observations within
this scope. #220 and certificate/auth consumers remain separate deliveries.

## Qualification composition and administrator witness

The existing #101 package-unit qualification is an isolated clean-host
experiment **before** installation of any shared-base/listener drop-in. It now
rejects installed or cached shared drop-ins before fixture mutation. Its
temporary `/etc/haproxy/haproxy.cfg` and statistics socket never substitute for
qualification of the installed #219 service. The reference evidence exercises
that installed service and consumes #101's effective policy directly.

The root master retains only its existing four runtime capabilities; dedicated
workers retain none. Exact worker executable inspection requires Linux's
`CAP_SYS_PTRACE` for `/proc/<worker>/exe` after the worker changes UID. The fixed
administrator-only startup/reload witness runs separately through native
`setpriv`, immediately bounded to read-only process inspection (and `CAP_KILL`
for the fixed reload signal). This does not add capabilities to HAProxy or
workers, change backend nftables UID permission, authorize an unrelated UID's
backend access, or expose a ptrace API. The witness first requires its PID to
match systemd's actual MainPID, then inspects only that authenticated master and
its direct children. No configurable program, command, alternate PID, mutable
extension or runtime socket is admitted. The short-lived administrator helper
is outside the application/HAProxy runtime authority.

The generation response contains only a non-secret configuration fingerprint
and the worker PID used for bounded serving proof. It conveys no client identity,
credential, application data or authority. Later listener/identity owners must
review their complete composition, including its exact configuration admission;
this base does not claim their future extended bytes already pass its renderer.

`validate-haproxy-reference.py` consumes the canonical evidence-architecture
owner. It admits the historical record through a bounded closed JSON Schema and
checks the recorded runtime payloads against its exact reviewed target SHA.
It cannot obtain host/provider authority or manufacture new host observations.
The record remains historical evidence; later corrected source requires its own
installed execution proof before acceptance.
