<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Fixed rootless product backends

Deployment #101 owns backend exposure. The reviewed configuration owner is
`scripts/product_backend_contract.py`; the retained production Quadlet renderer
consumes it. Changing an endpoint requires a reviewed configuration change.

| Product  | Host endpoint     | Container listener | HTTP transport check |
| -------- | ----------------- | ------------------ | -------------------- |
| Frontend | `127.0.0.1:18080` | TCP 8080           | `/health/live`       |
| API      | `127.0.0.1:18081` | TCP 8080           | `/health/live`       |

Both publications explicitly include `/tcp`. IPv4 loopback is the entire
internal contract. Workers, migration and scheduler publish no backend port.
No product uses host networking, public/wildcard publication, automatic host
port allocation, runtime sockets/APIs, or container-IP discovery. HAProxy's
backend-only fragment uses the fixed addresses and checks for HTTP 200.
API data readiness remains `/health/ready` in the product; its database and
application-state outcome is outside this transport contract.

Frontend retains its existing internal edge network and tmpfs only. Publishing
it adds no application network membership, environment secrets, PostgreSQL
credentials, private storage mount or migration authority. This change adds
only HTTP publication to API; PostgreSQL connectivity remains #81's authority.
The public edge, client identity, TLS, ACME, CrowdSec and production host
construction remain owned by their separate contracts.

## Host policy authority

`scripts/product-backend-policy.py` is an administrator-owned activation helper
and a read-only startup check. Install it as
`/usr/local/libexec/secpal/product-backend-policy`, together with its immutable
`product_backend_contract.py`. Their complete parent path must be root-owned
and inaccessible to non-root write authority. Install the host unit from
`config/production/host-systemd/secpal-product-backend-policy.service` in the
system manager, separately from the product user-manager units.

The helper resolves the distribution `haproxy` non-login system account. Its
system UID is disjoint from the runtime identity range owned by the production
inventory's `serviceAccountId`; startup also rejects the actual HAProxy UID as
a product runtime caller. It accepts no activation UID or host port from a caller. Numeric UID
substitution in `render-product-backend-policy.py` is preview rendering only;
it does not establish account admission or activation authority.

Activation requires SELinux Enforcing, `haproxy_connect_any=off` and
`pasta_bind_all_ports=off`. It installs a dedicated `secpal_backend_port_t`
label for exactly the two TCP ports, permits `haproxy_t` to connect and
`container_runtime_t` to bind. The selected named bridge-network publication
uses `rootlessport`; the real local transport fixture observed that forwarder
in `container_runtime_t`. Pasta's presence as a networking prerequisite does
not by itself identify the process binding a published bridge port.
Activation explicitly enables its module and queries the effective kernel
policy through libselinux. Both activation and startup require intended
connect/bind decisions, deny HAProxy access to `unreserved_port_t`, and reject
permissive domain decisions. This guard supplements actual port-label and
service-path qualification; authored CIL alone is not effective-policy proof.

The nftables table rejects traffic to these ports arriving on a non-loopback
interface. Its output rule admits only HAProxy's UID at the exact IPv4 address;
other UIDs and IPv6 loopback are rejected. No broad local validation exemption
is granted. Other host policy can further restrict this path. A process with
the HAProxy identity has that identity's authority; the account must remain
non-login and dedicated. Root can alter the policies and is outside the
local-process isolation claim.

Only successful policy activation publishes the root-owned configuration-bound
startup barrier under `/run/secpal-product-backends`. Both product units check
it before Podman starts. Missing, writable, symlinked or stale authority, changed
identity, non-enforcing SELinux and broad booleans refuse startup. Stopping the host policy service first removes the barrier and synchronously
stops only `secpal-frontend.service` and `secpal-api.service` in the existing
inventory-owned runtime user manager. The helper reads the administrator-owned
`/srv/secpal/config/state-contract.json` for its runtime UID; it accepts no caller
account, path or unit. Reverse `After=nftables.service` ordering completes this
withdrawal before nftables stops. A failed activation removes the barrier.
Restarting nftables also
restarts the policy service through `PartOf`. Root-controlled policy changes
outside that service require explicit maintenance and requalification; the
marker is a privileged activation attestation, not a firewall discovery API.

Host construction must activate this policy before starting product units.
The administrator helper has only this fixed backend withdrawal operation.
Issue #219 consumes the fixed endpoint/policy owner and implements its own
application-readiness routing checks; the transport fragment remains outside
public listener, TLS and identity decisions.

## Validation and qualification

Focused repository evidence:

```bash
python3 tests/product-backend-contract.py
python3 tests/production-state-contract.py
python3 tests/product-backend-network.py
python3 tests/product-backend-quadlet-lifecycle.py
```

The namespace test applies the actual nftables policy in a disposable user and
network namespace. It exercises intended and unrelated UIDs, exact loopback
sockets, external-address and IPv6 denial, and recreation. It never changes
the host firewall.

The explicit native product fixture requires the immutable product images
already staged, native Quadlet and a rootless user manager. It derives the
same publications and role/network model from the production renderer. Its
isolated HTTP-only profile supplies synthetic API initialization and frontend
public runtime configuration; it supplies no database or private storage.
It samples host HTTP readiness directly, independently of application-state
health supervision, over three start/stop recreations. It rejects runtime
environment overrides, forces local Podman observation and cleanup, and clears
runtime overrides from generated services. An inactive stale socket pathname
is not a runtime API dependency. It creates only its own named units/networks
and removes them after the test.

These tests prove the source contract. The historical GCP proof extraction
[#294](https://github.com/SecPal/deployment/issues/294) retained a privileged
accepted-main qualification path; candidate PR #293 could not authorize its
own cloud/root execution. The explicit Greenfield replan under #248 defers
that GCP-specific evidence and removes it as an intrinsic #219 gate. Deferral
is not successful proof: actual Enforcing Rocky host evidence must still
establish the applicable installed backend/runtime/security behavior. Issue
Issue #219 can consume genuine bounded provider-neutral reference-host evidence,
without adding another cloud requirement. A post-merge source defect requires
a corrective leaf rather than reopening #101.

The existing Rocky workflow has the closed `product-backend-policy` selector.
Its fixed entrypoint is
`scripts/ci-cloud/run-product-backend-qualification.sh`; it executes
`qualify-product-backends.py` from accepted control installed under
`/opt/secpal-control`, using only two bounded numeric run arguments. The selector
rejects caller target SHAs and retains the authenticated frozen #80 host pair.
It adds no PR resolver, executable-path input, provider, workflow family or
arbitrary privileged command facility.

Preparation publishes a closed source manifest binding accepted control SHA,
profile, preparation run/attempt and the exact fixed executable/import/policy
closure. Qualification retrieves it from that exact preparation and reconfirms
it before provider authority. A plain host or PostgreSQL preparation cannot
supply this capability. Aggregate-hashed bootstrap transport installs the closure
and manifest as root-owned immutable files. The product profile carries its own
optional payload in place of the PostgreSQL optional payload; both reuse the
existing host preparation, identity-free handoff, continuation and cleanup.
OpenTofu metadata admission and exact reconstruction tests cover both profiles.

The qualifier installs the actual administrator helper/contract and service,
requires Enforcing, disables only the qualification host's pasta bind-all
boolean, and requires HAProxy connect-any already off. It activates the actual
policy, queries loaded kernel SELinux port mappings and access decisions, reads
live nftables rules, and uses the packaged host-native `haproxy.service` with its
real non-login UID and `haproxy_t` worker context. Backend-only HTTP health checks
run across three native rootless product recreations. A local Unix stats socket
reports HTTP 200 health; no public HAProxy routing is constructed here.

The same run exercises unrelated local UID, IPv6-loopback and external-veth
access denial, an actual unrelated-port HAProxy SELinux denial, and mandatory
startup refusal when the policy barrier is missing or has a stale digest.
Stopping the actual policy service and withdrawing its dedicated nftables table
must leave both previously running product units inactive, their listeners absent
and the barrier withdrawn. The host control-plane metadata firewall is preserved;
unit ordering binds the same synchronous withdrawal to nftables service stop.
External denial includes a healthy private-address listener as its positive control. Frontend has only the edge
network and no private credentials or bind mounts. Product images remain digest
pinned, rootless and separate; local Podman uses no runtime API/socket or IP
lookup. Synthetic HTTP fixture initialization is never production secret material.

Observations and diagnostic identities are closed and bounded. Pure admission
reuses the existing Rocky signed-RPM owner and the backend policy owner.
Accepted-main control independently authenticates source hashes, preparation and
resource identities, the frozen host evidence digest and all required effective
facts from raw access decisions, installed rules, service/cgroup/process identity,
HTTP statistics and network results. Guest output has no self-authorizing PASS
field. The closed backend preparation profile installs `haproxy` and
`setools-console` through the existing reviewed DNF preparation transaction.
These packages, their dependencies and package-created accounts belong to the
prepared VM baseline; the observer performs no package transaction. It compares
before/after RPM catalog and public account-file digests, which control admits
independently. Provider destruction removes the entire prepared baseline.
Host cleanup stops only
qualification services, removes owned policy/module/rules/units/networks/test
state and restores the original HAProxy configuration and pasta boolean. Exact
container, image, network, listener, service, file and policy absence is read back
and independently admitted; nftables is restored active. The
existing unconditional provider cleanup destroys the exact continuation state.
The proof leaf also requires authoritative provider empty-state read-back.

The retained GCP qualification path covers `gcp-rocky-10-2-x86-64` and
`gcp-rocky-10-2-arm64`; it grants no dispatch authority and is not a replacement
for the current provider-neutral Greenfield direction. Issue #80 supports both
architectures. One actual host proves only its exercised architecture and
outcomes; fixture/source evidence does not qualify the privileged installed
boundary. See [the shared base](haproxy-shared-base.md) for the separately
classified package/supply, binary and installed-host evidence.
