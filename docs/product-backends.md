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
identity, non-enforcing SELinux and broad booleans refuse startup. Stopping or
failing the host policy service removes the barrier. Restarting nftables also
restarts the policy service through `PartOf`. Root-controlled policy changes
outside that service require explicit maintenance and requalification; the
marker is a privileged activation attestation, not a firewall discovery API.

Host construction must activate this policy before starting product units.
The system and user managers do not acquire control over each other. #219 can
consume the emitted backend fragment once this capability has been qualified;
the fragment contains no public listener, TLS material or routing decision.

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

These tests do not substitute for privileged host qualification. Before Ready
or issue closure, a reviewed Rocky host must prove the actual installed custom
port labels/rules with Enforcing effective process labels, host-native HAProxy
HTTP access across product recreation, external-interface and unrelated UID
denial, a representative denied HAProxy connection to an unrelated port,
and startup refusal with missing/stale policy authority. Keep the smallest
non-redundant real-system record, including exact commands, package versions,
architecture, candidate identity and results. Preserve #80's amd64/arm64 host
and rootless authority contracts. Authored policy text or a fixture PASS does
not qualify the installed HAProxy/SELinux path.
