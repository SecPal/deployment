<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# FCOS lab container rollouts

This coordinator sequences compatible, migration-free changes to the
[FCOS application fixture](fcos-application-poc.md). The production update
and RecoverySet requirements remain under
[deployment #93](https://github.com/SecPal/deployment/issues/93). This source
delivery provides protected-main release detection, a user timer and rollout
state handling. Live rollout also requires a separately qualified lab adapter.

## Release source and discovery

The runner fetches the fixed SecPal/deployment `refs/heads/main` over HTTPS.
The desired release is the commit and a fingerprint of the versioned
application renderer, its inputs, and the edge and security configuration.
Changes outside those inputs cannot trigger activation. The runner reads
Git objects as data and executes its installed copy of the coordinator.
Live credentials, host access and observed running state remain private.

The product publishing workflows are the starting point for discovering
SecPal releases. PostgreSQL candidates must stay on major 18 and preserve its
supported image layout. HAProxy, CrowdSec, SPOA and OWASP CRS candidates use
their respective upstream publishers. A discovery result is a candidate for
a reviewed deployment change. Product signatures and attestations, official
image provenance, the exact index and native manifests, and ruleset
authenticity remain part of admission. Automated proposal creation and
admission for every upstream are separate from detecting changes on main.

## Scoped activation requirement

Install an independently controlled lab adapter using the existing
WireGuard and strict SSH host-key trust. The three guest service
configurations are administrator-owned. Give the timer a dedicated
restricted credential for the lab rollout operations. The current manual
bootstrap identity grants administrative access and is unsuitable as a
standing timer credential. No operator workstation connection is needed
during steady-state operation. Keep the timer disabled until the adapter
passes live acceptance.

The coordinator calls an installed executable using literal arguments.
Keep its executable and host policy outside the fetched release:

```text
ADAPTER OPERATION HOST PLATFORM CANDIDATE_COMMIT CANDIDATE_FINGERPRINT PREVIOUS_COMMIT PREVIOUS_FINGERPRINT
```

Limit host aliases to `cx23`, `cx33` and `cax21` in that order. Resolve the
destination through fixed local inventory. The adapter must re-admit the Git
commit and fingerprint, and use trusted host identities, from outside the
supplied request. An exit code of zero and empty standard output indicate
success, except that `observe` returns exactly one 64-character lowercase
hexadecimal fingerprint and a newline. Exit code 10 for `accept` is an
explicit candidate rejection. Other errors are ambiguous failures. Standard
output and error must contain no secrets. The coordinator does not emit
adapter diagnostics.

| Operation  | Required adapter behavior                                                                                                                                                                                                                               |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `observe`  | Read the release from actual units, configuration and running container identities. Reject mixed or unrecognized state.                                                                                                                                 |
| `prepare`  | Stage exact verified children and signed CRS as required. Render and validate the candidate and rollback configuration. Verify both architectures before any host is switched. Refuse schema migrations, PostgreSQL major upgrades and unsafe rollback. |
| `activate` | Switch only the changed units and real dependencies. Retain private inputs, named storage and the prior configuration. Validate HAProxy before graceful reload.                                                                                         |
| `accept`   | Check live TLS, auth, organization read/write, PostgreSQL data and settings, both queues, one scheduler, rootless/SELinux, HAProxy and AppSec. A security-degraded response fails acceptance. Use an idempotent synthetic data witness.                 |
| `rollback` | Restore only an independently admitted compatible candidate and verify its health. Refuse schema rollback.                                                                                                                                              |

The scoped endpoint must bind the request to the host and admissible
release, retain the last accepted configuration and record native digests
per host. It may not expose a shell, arbitrary unit installation, a
container socket or general sudo. Protect the migration credential from the
timer. The application contract provides a separate explicit migration
authority. This lab path permits zero automatic migrations.

## Start, inspect and suspend

After the scoped endpoint and adapter have passed independent acceptance,
install the reviewed Python file under
`~/.local/lib/secpal-fcos-lab-rollout/` and the two units under
`~/.config/systemd/user/`. Set the following values in the private
`~/.config/secpal-fcos-lab-rollout/rollout.conf`:

```ini
SECPAL_FCOS_BASELINE=<reviewed full commit already running on all three hosts>
SECPAL_FCOS_ADAPTER=<absolute path to qualified lab adapter>
```

Run the service once to admit the running baseline, then enable the timer
with `systemctl --user enable --now secpal-fcos-lab-rollout.timer`. The
management user requires an active persistent user manager. Verify
`loginctl show-user "$USER" -p Linger` and use
`systemctl --user list-timers secpal-fcos-lab-rollout.timer`. Check desired
source separately with `fcos_lab_rollout.py --state-directory DIRECTORY
--inspect`; use a private directory. This operation does not contact any
guest. Use `journalctl --user -u secpal-fcos-lab-rollout.service` and the
private state under `~/.local/state/secpal-fcos-lab-rollout/` to inspect
rollout progress. The adapter owns the read-back of running native digests.

Pause future runs with `systemctl --user disable --now
secpal-fcos-lab-rollout.timer`. Let an active service finish as appropriate
before maintenance. Re-enabling the timer resumes ordinary pending work.
The local lock serializes invocations. After interruption, a confirmed
candidate is tested without another activation. A mixed or ambiguous
switch stops for reconciliation. A definite failed candidate attempts
compatible rollback on the failed host only and halts the entire fleet.
Keep the timer paused and reconcile the hosts to one verified release
before running the coordinator with `--recover`, the reconciled full Git SHA
as `--baseline`, and the existing state directory and adapter. Recovery first
requires matching live read-back from all three hosts, then archives the
blocked journal and records the reconciled baseline. Resume the timer after
reviewing the protected-main candidate.

## Separate Fedora CoreOS maintenance

The lab uses Zincati with automatic updates disabled. Keep the container
rollout paused during an OS update. A separate maintenance job should use
the same three-host order and stop on failed acceptance.

1. Admit the Fedora-signed Stable artifact and its exact native digest for
   both architectures. Verify the guest booted from the expected deployment
   and that a known-good previous boot and independent recovery are available.
2. Stage one host with
   `rpm-ostree rebase --disallow-downgrade ostree-image-signed:docker://quay.io/fedora/fedora-coreos@sha256:<native-digest>`.
   Check `rpm-ostree status --json` for the staged version and
   `container-image-reference-digest`. Stop if a driver blocks staging.
3. Reboot that host. Check the booted digest, WireGuard, SELinux, the rootless
   user services and the complete application and security acceptance. Keep
   the previous deployment available until these checks succeed.
4. Continue only after acceptance. On failure, keep the other hosts at their
   current revisions and use the previous deployment or independent recovery
   on the failing host.

A local [Zincati maintenance window](https://coreos.github.io/zincati/usage/updates-strategy/)
schedules node-local reboots. The separate maintenance job owns fleet
serialization and uses a distinct authority and journal.
