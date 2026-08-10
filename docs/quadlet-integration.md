<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Rootless Podman and Quadlet integration

This is the active disposable integration runtime. It transfers the completed
Phase B/C behavior to native rootless Podman 5, Quadlet-generated systemd user
services, `crun`, Netavark/Aardvark, and `pasta`. It is not a production
deployment and does not implement persistence, production secrets, public
edge, TLS lifecycle, CrowdSec, backup, update, or rollback operations.

The old [`compose.yaml`](../compose.yaml) and
[`local-integration.sh`](../scripts/local-integration.sh) remain immutable
historical evidence of how Phase B/C was originally completed. They are no
longer the active required runtime.

## Closed runtime contract

[`render-integration-quadlets.py`](../scripts/render-integration-quadlets.py)
accepts only an integration instance identifier, one loopback port, a private
fixture root, and an output directory for a normal run. Its optional
integration-only failure selector is a closed enum: `migration`, `dependency`,
or `health`; each value changes exactly one reviewed unit with fixed text.
Product images, exact OCI index digests, service commands, users, mounts,
security flags, network membership, and systemd relationships are otherwise
constants. No input accepts a registry, image, Podman argument, Quadlet
fragment, host network, socket, auto-update policy, or security override.

Each run generates ten container definitions, two internal networks, three
disposable volumes, and one native systemd user target. Resource names and
`org.secpal.integration.instance` labels include the validated run identifier,
so parallel runs do not collide.

| Role                  | Identity                             | Networks          | Writable state                              | Required predecessor             |
| --------------------- | ------------------------------------ | ----------------- | ------------------------------------------- | -------------------------------- |
| secret initialization | `0:0` in the rootless user namespace | none              | secret, PostgreSQL, private-storage volumes | none                             |
| PostgreSQL            | `999:999`                            | application       | PostgreSQL volume and bounded tmpfs         | successful secret initialization |
| Valkey                | `10002:10002`                        | application       | bounded tmpfs only                          | successful secret initialization |
| migration             | `10001:10001`                        | application       | private-storage volume and bounded tmpfs    | healthy PostgreSQL and Valkey    |
| API                   | `10001:10001`                        | application, edge | private-storage volume and bounded tmpfs    | successful one-shot migration    |
| general worker        | `10001:10001`                        | application       | private-storage volume and bounded tmpfs    | successful one-shot migration    |
| hash-chain worker     | `10001:10001`                        | application       | private-storage volume and bounded tmpfs    | successful one-shot migration    |
| scheduler             | `10001:10001`                        | application       | private-storage volume and bounded tmpfs    | successful one-shot migration    |
| frontend              | `101:101`                            | edge              | bounded `/tmp` tmpfs                        | none                             |
| integration gateway   | `10003:10003`                        | edge              | bounded tmpfs                               | healthy API and frontend         |

There is exactly one `activity-hash-chain` worker, one scheduler, and one
explicit migration container. Migration remains a `Type=oneshot` service and
its reviewed `Exec=` is the only place that selects `php artisan migrate`.
The shared API runtime-preparation wrapper loads file-backed fixture secrets
and prepares writable directories, but never decides to run a migration.
Health checks, workers, and the scheduler never invoke migration.
PostgreSQL, Valkey, API, frontend, and gateway use Podman health notifications
as systemd readiness. Failed health or migration therefore prevents the
dependent target from becoming active.

All containers have read-only root filesystems, explicit writable paths, all
capabilities dropped, `no-new-privileges`, no host networking, no privileged
mode, and no runtime socket. Secret initialization alone receives `CHOWN` and
`FOWNER` inside the rootless user namespace. Runtime inspection rechecks these
properties, exact identities, `crun`, both networks' effective internal state,
network membership, the gateway's exact `127.0.0.1:<port>:8443` publication,
and the effective AppArmor profile when AppArmor is available.

## Supply-chain order

The active runner is fail closed in this order:

1. validate repository inputs and the local rootless runtime;
2. retrieve each exact SecPal OCI index and its public attestation bundle;
3. verify the exact index digest, response digest, descriptor chain, publisher
   workflow, source ref, source commit, and GitHub-hosted publisher policy;
4. stage the verified digest anonymously in local rootless Podman storage;
5. repeat the complete gate for both API and frontend;
6. stage the digest-pinned official PostgreSQL, Valkey, and Caddy inputs;
7. build only the integration gateway with its already-staged base and
   `--pull=never`;
8. render, validate, root-own, install, and translate the Quadlets; and
9. start the native systemd user target.

The product units specify canonical digest references and `Pull=never`.
Verification and pulls use an empty authentication file plus isolated temporary
home, XDG configuration, Docker configuration, and certificate directories.
The admitted rootless storage location is preserved, but caller credential
files and external registry credential helpers cannot be consulted. The runner
never logs in, depends on GHCR credentials, or falls back to a tag or alternate
registry.

## Lifecycle evidence and cleanup

The same API health, separate browser origins, exact credentialed CORS,
Sanctum/secure-cookie, CSP, service-worker, Valkey cache and queue, worker
ownership, and private-storage probes used by the completed integration are
run against the Quadlet services. An API restart must preserve the disposable
private-storage fixture without creating a new migration container. The shared
file must retain the historical `10001:10001:640` owner, group, and mode when
observed from the hash-chain worker.
Every HTTP transfer has a ten-second maximum, and the readiness probes reduce
that maximum to the remaining lifecycle deadline. Negative HTTP evidence
accepts curl's HTTP-error exit only; DNS, connection, and TLS failures remain
transport failures rather than valid application rejection evidence.

Three closed real-runtime profiles also prove that a failed migration never
starts its dependent application roles, a failed PostgreSQL dependency never
starts migration or its dependents, and a gateway health failure cannot leave
the integration target active. The profiles are evidence fixtures only; they
cannot accept arbitrary commands or Quadlet text. Migration and dependency
evidence requires the exact `/bin/false` exit result. Health evidence requires
Podman's effective `CMD-SHELL /bin/false` configuration, the retained
`health_status=unhealthy` event bound to that exact container identity, and the
resulting systemd exit after Podman applies the reviewed
`HealthOnFailure=kill` policy; an
unrelated gateway failure is not accepted as health-failure evidence.

An automatically selected loopback port is chosen only after image verification
and staging. A current-invocation gateway bind collision triggers at most two
new selections, including during the health-failure profile. The retry
preserves PostgreSQL, Valkey, both completed
one-shots, and the migration invocation; it replaces only the long-running
application roles whose origin configuration contains the port. An explicitly
provided port is never silently replaced.

Success, any failed phase, and handled `SIGHUP`, `SIGINT`, or `SIGTERM` all run
the same exact cleanup. Cleanup stops the run target and its generated
run-scoped services, removes only its ten named containers, two named networks,
three named volumes, generated unit files, native target, and locally built
gateway image, then verifies the resources and generated service states are
absent. It never prunes images, volumes, networks, or unrelated containers.
Pre-existing unrelated resource names outside the reserved integration
namespace are snapshotted and must still exist afterward. The published SecPal
images are not cleanup artifacts. A failed resource-state query is reported as
an incomplete cleanup, but cannot skip the independent fixture-root removal.

Hosted runtime evidence gives the complete pre-gateway lifecycle a bounded
600-second readiness deadline, waits until the gateway service is active,
sends an external `SIGTERM` to the integration harness, requires exit status
`143`, and requires the fixture root to be absent after the harness's exact
cleanup.

The runner emits bounded non-secret container statistics, systemd memory
current/peak and CPU observations, unpacked image sizes, disposable volume
sizes collected inside the rootless user namespace, and fixture disk use as
evidence. An unavailable volume observation is reported explicitly rather than
as a false zero. Those observations do not change the D.1 production resource
floors.

## Running the integration

The runtime requires a non-root user, Podman `>=5.4.2,<6`, `crun`, `catatonit`,
Netavark, Aardvark, `pasta`, subordinate-ID helpers, an active systemd user
manager, Debian's native Quadlet user generator at
`/usr/lib/systemd/user-generators/podman-user-generator`, and the D.1
root-owned Quadlet search-path policy. GitHub CLI 2.97.0, Node.js, npm,
Playwright Chromium, Python 3, `curl`, and GNU `du` are also required.
Podman prereleases sort below their corresponding stable release. The runtime
and generator compatibility check compares the normalized release and
prerelease while ignoring non-precedence distro build metadata.
Admission also requires unified cgroup v2, effective Aardvark DNS, and trusted
root-owned executable paths for `crun`, Netavark, Aardvark, and `pasta` before
any image is staged. Generated containers disable Podman's default host-proxy
environment inheritance, and runtime inspection rejects any effective proxy
variable.

The administrator-owned policy must expose only the current user's root-owned
Quadlet directory:

```text
QUADLET_UNIT_DIRS=/etc/containers/systemd/users/<uid>
```

The harness requests one standard sudo credential refresh over stdin
(`sudo -S -v`) before doing any runtime or registry work. The password is not a
command-line value. Unit installation and cleanup then use only non-interactive
`sudo -n`, so a failure or signal cannot block on a password prompt. Hosted
runners may satisfy the same gate through their existing passwordless operator
policy; no SecPal-specific broad sudoers rule is needed.

After the policy is imported into the user manager, run:

```bash
python3 scripts/quadlet-integration.py
```

The closed negative evidence runs are:

```bash
for failure_case in migration dependency health; do
  python3 scripts/quadlet-integration.py --failure-case "$failure_case"
done
```

For parallel scheduling, give every run a distinct identifier, port, and new
private fixture path. Because the fixture path is embedded in Quadlet mount
definitions, it must be an absolute canonical ASCII path containing only
letters, digits, `/`, `.`, `_`, `@`, `+`, and `-`:

```bash
python3 scripts/quadlet-integration.py \
  --instance parallel01 \
  --port 18443 \
  --fixture-root /absolute/new/private/path
```

The identifier also scopes Playwright output and last-run state beneath
`test-results/secpal-int-<instance>`, so concurrent browser proofs never share
worker artifacts or trace paths. The retained historical Compose harness uses
the fixed `secpal-int-phasebcompose` output directory when no Quadlet instance
identifier is present.

## Hosted evidence and production admission

As inspected on 2026-08-09, `ubuntu-latest`/Ubuntu 24.04 provides Podman 4.9.3
and cannot satisfy the D.1 version floor. The active workflow therefore names
the Ubuntu 26.04 public-preview x64 and arm64 images, whose published
inventories report Podman 5.7.0, and then admits every required effective
runtime property before integration. It intentionally fails if either preview
image lacks `crun`, Netavark/Aardvark, `pasta`, subordinate-ID helpers, or a
usable systemd user manager. Both supported product architectures run the same
real lifecycle, browser, failure, parallel-isolation, and cleanup evidence.

Ubuntu-hosted execution proves integration behavior only. It does not prove
the separate D.1 Debian 13 production-host admission contract, which remains
covered by the production inventory and synthetic host-fact validators.

The required check changes from `Local Integration / Compose Contract` to the
`Local Integration / Quadlet Contract (amd64)` and `Local Integration / Quadlet
Contract (arm64)` matrix checks. Branch protection must make that an explicit
atomic governance cutover when this change is merged; the repository does not
silently mutate branch protection.
