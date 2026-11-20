<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# FCOS lab container rollouts

This coordinator sequences compatible, migration-free changes to the
[FCOS application fixture](fcos-application-poc.md). The production update
and RecoverySet requirements remain under
[deployment #93](https://github.com/SecPal/deployment/issues/93). The user timer and coordinator provide protected-main release detection, staged
rollout and interruption recovery. The first guest adapter admits changes to the
SecPal frontend image only. Standing access and the first automated release
require live acceptance before this path is qualified.

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

## First release scope

The adapter accepts a change to the frontend index digest and its publisher
commit in `scripts/integration_runtime_contract.py`. All other release inputs
must match the enrolled fixture. The first lane rejects API changes, migrations,
PostgreSQL upgrades, HAProxy and AppSec updates, and changes to the deployment
layout. Health checks still exercise PostgreSQL, the application and inspection
services on every host. This keeps those services running during frontend
activation and makes the previous frontend a compatible rollback target.
Qualification of other components can extend these same five operations.

The coordinator invokes the installed adapter with an operation, host,
platform, and the candidate and previous Git revisions and fingerprints.
Preparation must succeed on CX23, CX33 and CAX21 before any activation.
The controller verifies the OCI index with the existing GitHub attestation
toolchain, including the exact publisher workflow and source commit on main.
It binds each signed native child to its host. The guest independently
checks the requested revision and fingerprint against protected main, independently
verifies the supplied publisher bundle and immutable index with the same pinned
verifier, checks the native child, pulls it as the rootless runtime user,
and validates the frontend Quadlet and a single image drop-in in isolation.

| Operation  | Guest and controller behavior                                                                                                                                                                                               |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `observe`  | Read the installed Quadlet and running container identities. Return exactly the observed 64-character fingerprint and newline for an admitted state. Reject drift and mixed state.                                          |
| `prepare`  | Match the accepted predecessor, enforce frontend-only scope, stage the pinned native child and validate the candidate. Persist both release identities before any switch.                                                   |
| `activate` | Install the single image drop-in and restart the frontend only. Verify running native manifest, image configuration and unchanged roles and layout.                                                                         |
| `accept`   | Check real TLS, private app/API routing, authentication and the synthetic organisation, plus PostgreSQL cluster identity, both queues, one scheduler, rootless/SELinux and AppSec inspection. Persist the accepted release. |
| `rollback` | Restore the admitted previous frontend and verify its health. Keep the PostgreSQL container, volumes and private inputs intact.                                                                                             |

An explicit rejection returns exit code 10 from `accept`. Other errors halt
on an ambiguous result. Successful operations other than `observe` have no
standard output. Neither application credentials nor guest administrator
credentials are passed as command-line arguments.

## One-time guest administrator handoff

An independent administrator does this once on each existing lab guest.
Use the existing authenticated management path. The controller's standing
credential must never be its broadly authorized bootstrap key. Confirm the
guest's machine ID, WireGuard source, SSH host identity and installed fixture
before installing the exact reviewed source revision.

1. Create one dedicated synthetic organisational unit named
   `FCOS lab rollout witness` using the existing private fixture. Record its
   UUID and use a synthetic account permitted to read and edit that unit.
   The acceptance check only changes that record's description and verifies
   the resulting value. Prepare the root-only input `/secure/guest.json` with
   the following shape:

   ```json
   {
     "foundation": "<reviewed full commit of the running fixture>",
     "host": "<cx23, cx33 or cax21>",
     "machine_id": "<authenticated guest machine ID>",
     "witness": "<synthetic organisational unit UUID>"
   }
   ```

2. From the reviewed source directory on that guest, install the fixed
   helper and enroll the existing fixture. Replace `/secure` with the
   administrator's protected transfer directory. Stage the checksum-verified native
   GitHub CLI described below on the controller for each architecture and
   transfer the appropriate executable as `/secure/gh`. The helper checks the native
   executable digest before each attestation. The guest does not need
   Python or GitHub credentials.

   ```sh
   guest_lib=/usr/local/libexec/secpal-fcos-lab-rollout
   install -d -o root -g root -m 0755 "$guest_lib"
   install -m 0755 -o root -g root scripts/fcos-lab-rollout-guest.sh "$guest_lib/guest"
   install -m 0644 -o root -g root scripts/fcos-lab-release-paths.txt "$guest_lib/release-paths.txt"
   install -m 0644 -o root -g root scripts/fcos-lab-gh-binary-sha256.txt "$guest_lib/gh-binary-sha256.txt"
   install -m 0755 -o root -g root /secure/gh "$guest_lib/gh"
   install -d -o root -g root -m 0700 /etc/secpal-fcos-lab-rollout /var/lib/secpal-fcos-lab-rollout
   install -d -o root -g root -m 0755 /etc/containers/systemd/users/20000/secpal-int-haproxy01-frontend.container.d
   install -m 0600 -o root -g root /secure/guest.json /etc/secpal-fcos-lab-rollout/guest.json
   "$guest_lib/guest" --enroll
   ```

   Enrollment captures the exact installed image and fixed configuration,
   checks rootless runtime health and verifies the PostgreSQL cluster and
   synthetic witness. It records adapter state and exercises both queues
   with temporary synthetic jobs and cache markers. Stop if the installed
   fixture does not match. Keep administrator recovery access.

3. Install the following exact sudoers entry at
   `/etc/sudoers.d/secpal-fcos-lab-rollout` under administrator ownership and
   mode `0440`. Use `visudo -cf` on the staging file before installation and
   `visudo -c` after installation. The empty argument list limits the entry
   to the fixed guest protocol. The `--enroll` operation remains root-only.

   ```sudoers
   secpal-lab-rollout ALL=(root) NOPASSWD: /usr/local/libexec/secpal-fcos-lab-rollout/guest ""
   ```

4. Create the dedicated account if absent. Install the controller's dedicated
   public key in the administrator-owned file using the line below. Check
   any existing account, group or file before adopting it. Do not add this
   account to an administrative group.

   ```sh
   guest_home=/var/home/secpal-lab-rollout
   useradd --no-create-home --home-dir "$guest_home" --shell /bin/bash secpal-lab-rollout
   install -d -o root -g root -m 0755 "$guest_home" "$guest_home/.ssh"
   install -m 0644 -o root -g root /secure/rollout.authorized_keys "$guest_home/.ssh/authorized_keys"
   restorecon -RF "$guest_home" /usr/local/libexec/secpal-fcos-lab-rollout /etc/sudoers.d/secpal-fcos-lab-rollout
   ```

   ```text
   restrict,from="<verified controller WireGuard source IPv4>/32",command="/usr/local/libexec/secpal-fcos-lab-rollout/guest --ssh-entry" ssh-ed25519 <dedicated-controller-public-key>
   ```

   Verify `sshd -T` admits public keys from the configured authorized-keys
   file. Through the dedicated key, verify an exact read-back of the
   enrolled baseline and rejection of an explicit SSH command, TCP
   forwarding, an unknown operation, wrong host identity and a candidate
   outside the enrolled scope. As administrator, use `sudo -l -U
secpal-lab-rollout` to verify the exact no-argument rule and no other
   privilege. Verify the dedicated account cannot modify the key, policy,
   journal, helper or Quadlets. The existing recovery key remains independent.

## Controller setup and qualification

From the exact reviewed source tree as the normal controller user, install
the private client and units. Do not arm the timer yet.

```sh
umask 077
rollout_lib="$HOME/.local/lib/secpal-fcos-lab-rollout"
rollout_config="$HOME/.config/secpal-fcos-lab-rollout"
rollout_state="$HOME/.local/state/secpal-fcos-lab-rollout"
install -d -m 0700 "$rollout_lib" "$rollout_config" "$rollout_state"
install -d "$HOME/.config/systemd/user"
install -m 0700 scripts/fcos_lab_rollout_adapter.py "$rollout_lib/"
install -m 0600 scripts/fcos_lab_rollout.py scripts/fcos-lab-release-paths.txt \
  scripts/fetch-oci-attestation.py scripts/integration_runtime_contract.py \
  scripts/image_attestation_runtime.py scripts/fcos-lab-gh-binary-sha256.txt "$rollout_lib/"
install -m 0644 config/quadlet/fcos-lab-rollout/secpal-fcos-lab-rollout.{service,timer} \
  "$HOME/.config/systemd/user/"
ssh-keygen -q -t ed25519 -N "" -f "$rollout_config/rollout_ed25519"
systemctl --user daemon-reload
```

Use the official GitHub CLI executable selected by
`scripts/image_attestation_runtime.py` and its pinned archive checksum.
The following runs the maintained downloader and digest check for the
controller's native architecture, then installs the executable as `gh`.
For guest staging, pass a private output directory and `x86_64` or `aarch64`
as the second argument. For example, change the invocation to
`python3 -I - "$rollout_lib" aarch64` only when that directory is dedicated to
staging an ARM64 guest tool.

```sh
python3 -I - "$rollout_lib" <<'PYTHON'
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path.cwd() / "scripts"))
from image_attestation_runtime import CLOUD_GH_RELEASES, stage_gh_cli
with tempfile.TemporaryDirectory() as scratch:
    def run(argv, environment):
        subprocess.run(argv, env=environment, check=True)
    architecture = sys.argv[2] if len(sys.argv) == 3 else platform.machine()
    tool = stage_gh_cli(Path(scratch), CLOUD_GH_RELEASES[architecture], run,
                        {"PATH": "/usr/bin:/bin", "HOME": scratch})
    target = Path(sys.argv[1]) / "gh"
    shutil.copyfile(tool, target)
    target.chmod(0o700)
PYTHON
```

Under `$rollout_config`, install the following private inputs mode `0600`:

- `hosts.json` maps `cx23`, `cx33` and `cax21` to distinct private WireGuard
  IPv4 `address` values and their existing `domain` parents, for example
  `{"cx23":{"address":"<private IPv4>","domain":"<cx23 DNS parent>"}}`
  with the other two entries present.
- One `<host>.known_hosts` per guest. Each file contains one line in the form
  `<alias> ssh-ed25519 <key>` using the independently authenticated host key.
  A host replacement requires independent authentication and explicit pin
  replacement before rollouts can continue.
- One `<host>.health.json` per guest with exactly `email`, `password` and
  `organisation`. Use only the synthetic account and witness UUID from
  enrollment. Do not put these credentials in the unit's environment.
- `rollout.conf` contains the reviewed full commit actually running on all
  three hosts and the absolute installed adapter path:

  ```ini
  SECPAL_FCOS_BASELINE=<reviewed full commit already running on all three hosts>
  SECPAL_FCOS_ADAPTER=<absolute path to installed fcos_lab_rollout_adapter.py>
  ```

Verify `loginctl show-user "$USER" -p Linger`. Use
`python3 -I "$rollout_lib/fcos_lab_rollout.py" --state-directory "$rollout_state" --inspect`
to check the protected-main fingerprint independently of the guests. Before
enabling the timer, verify the standing credential and negative tests on
all three guests. With protected main still at the installed fingerprint,
start the service once with `systemctl --user start secpal-fcos-lab-rollout.service`
to record its observed baseline. Confirm the journal contains the enrolled
baseline and no pending rollout. Verify the units with
`systemd-analyze --user verify` before enabling them.

Enable the qualified adapter and timer with
`systemctl --user enable --now secpal-fcos-lab-rollout.timer`, then admit one
separately reviewed compatible frontend index change through protected main.
Do not deploy it manually. Use
`systemctl --user list-timers secpal-fcos-lab-rollout.timer`,
`journalctl --user -u secpal-fcos-lab-rollout.service` and
`$rollout_state/rollout.json` to verify detection, sequence and halt behavior.
Read each guest's root-only `/var/lib/secpal-fcos-lab-rollout/accepted.json`
through independent administration to compare revision, index digest,
native child and image configuration with the actual running image.
Record private evidence for staging on all three, sequential activation,
positive application acceptance, rollback and idempotence before calling
the rollout qualified.

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

To remove standing authority, first pause the timer and allow any active
service to finish or reconcile. Remove the dedicated authorized-keys file
and sudoers rule, then verify that the key is rejected. Keep the guest
journal, images and active Quadlet drop-in until the running frontend is
independently verified and reconciled to the desired fixture. Removing the
active drop-in without reconciliation would change the image on a later
restart.

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
