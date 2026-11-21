<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# FCOS lab container rollouts

For host updates and the next controlled rebuild, start at the
[FCOS operations handoff](#fcos-operations-handoff).

This coordinator sequences compatible, migration-free changes to the
[FCOS application fixture](fcos-application-poc.md). The production update
and RecoverySet requirements remain under
[deployment #93](https://github.com/SecPal/deployment/issues/93). The user timer
and coordinator provide protected-main release detection, staged rollout and
interruption recovery. The guest adapter handles frontend image updates and
reviewed migration-free API/PHP-FPM updates. Qualify a genuine release on
all three hosts before relying on a new rollout lane.

## Release source and discovery

The runner fetches the fixed SecPal/deployment `refs/heads/main` over HTTPS.
The desired release is the commit and a fingerprint of the versioned
application renderer, its inputs, and the edge and security configuration.
Changes outside those inputs cannot trigger activation. The runner reads
Git objects as data and executes its installed copy of the coordinator.
Live credentials, host access and observed running state remain private.

The existing `FCOS Lab Release Discovery` workflow reports candidates for
each maintained upstream. The frontend proposal compares the latest
successful publisher run on upstream main with the active **lab** source
pin. An identical, older, diverged or superseded publication produces no
proposal. The read-only job verifies the publisher's exact signed index and
build evidence, requires both native children and the matching clean source,
Grype and Trivy results, and checks the corresponding runtime smoke results.
The exact upstream workflow run and attempt are recorded in the draft.

The publisher archive download requires an Actions read credential scoped to
`SecPal/frontend`. Set `FCOS_FRONTEND_ACTIONS_READ_TOKEN` as a deployment
repository secret through the existing administrator path. The token is used
solely for the archive download. The built-in workflow token handles
discovery and the read-backs in the proposal job.
[GitHub artifact download permissions](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact).

The write job is limited to protected main and creates a draft on a branch
named for the candidate digest and current main commit. A previous proposal
for the same digest or another open proposal in that lane prevents further
writes. If main advances before a PR is opened, the next run can use the new
base. The job requires an unchanged main commit, a still-current publisher run and a GitHub-verified
commit containing only the two lab pin edits. It leaves existing branches
and PRs in place. Review the proposed compatibility against the current
base. GitHub continues to enforce its normal reviews and required checks.
After the accepted merge the existing timer handles deployment.

For draft creation, give a dedicated, expiring fine-grained personal access
token access only to `SecPal/deployment` with Contents and Pull requests
read/write. Add it directly to the repository Actions secret
`FCOS_FRONTEND_PROPOSAL_WRITE_TOKEN` after any required organization approval.
Only branch, signed commit and draft PR creation use that token. The built-in
workflow token retains read permissions, and the organization can keep PR
creation by that token disabled. A PR opened with the dedicated token issues
the usual GitHub PR event and follows the existing checks and merge gates.
Set `FCOS_LAB_RELEASE_PROPOSALS=true` after confirming the credential is
approved and stored. Unset the variable to suspend draft creation.
[GitHub token event behavior](https://docs.github.com/en/actions/concepts/security/github_token#when-github_token-triggers-workflow-runs).

The existing reports for API/PHP-FPM, HAProxy, CrowdSec, SPOA, OWASP CRS and
PostgreSQL can feed the same proposal mechanism once each component has
its own admitted provenance, compatibility and rollout scope. PostgreSQL
remains on major 18 and its approved image layout. CRS also needs ruleset
authenticity. Version proposals use immutable publisher identities. SecPal's
product SemVer release decisions remain with the product publishers.

## Migration-free release lanes

The adapter accepts the lab-only `LAB_FRONTEND_DIGEST` and
`LAB_FRONTEND_SOURCE_COMMIT` overrides in
`scripts/integration_runtime_contract.py`. Without these overrides it reads
the frontend pin of the enrolled fixture. Production rendering continues to
use its existing frontend pin. The frontend lane updates that image alone.
Health checks still exercise PostgreSQL, the application and inspection
services on every host. This keeps those services running during frontend
activation and makes the previous frontend a compatible rollback target.
Qualification of other components can extend these same five operations.

The backend lane uses a complete reviewed set of lab-only pins in
`scripts/integration_runtime_contract.py`: `LAB_API_SOURCE_COMMIT`,
`LAB_API_PAIR_DIGEST`, `LAB_API_DIGEST`, `LAB_PHP_FPM_DIGEST` and
`LAB_API_VEX_EXPIRES_AT`, plus `LAB_API_COMPATIBILITY_SHA256`. Use the admitted publisher artifact and current
security qualification for that exact pair. Keep the frontend pin, fixture
source and production pins fixed within a backend release.

The existing discovery workflow also checks the latest successful API
publisher on upstream `main` against the active lab backend source pin. It
uses the API publisher's public run-scoped GHCR discovery tag to locate a
candidate, then verifies the exact signed pair digest, native indexes and
both images' signed security and smoke evidence. For a retried acceptance,
the original candidate attempt and the successful acceptance attempt must
agree with their respective signed records. Stale security evidence and
unchanged or non-descendant sources are ineligible. The proposal's security
deadline comes from the signed source scan database deadlines.

Backend discovery needs no cross-repository artifact credential. The
repository-scoped proposal write secret already used by the frontend
can create the signed backend draft. The draft changes only
`docs/fcos-lab-backend-proposal.md`, which sits outside the timer's release
inputs. It adds no lab pins or compatibility record. Before approving a
rollout, replace the draft file with the exact reviewed pins and the
compatibility record described below. Review the private rehearsals and
the validity of the exact publisher evidence again before merging.

The controller and each guest verify the publisher signature on the pair and
both component indexes, including the pair's exact native platform bindings.
Each guest stages its native children and validates the staged Nginx and
PHP-FPM configuration and generated Quadlets before activation.
Before backend dispatch the controller checks the guest helper's closed
operation identifiers and applies the existing SecPal evidence architecture
validator. The temporary admission input combines the protected release's
canonical declaration with the backend operation identities. Its contents
do not change the release fingerprint. The controller verifies the
validator and companion files against the existing fixture renderer's
authority pins. The guest requires the installed helper's exact SHA-256 to
match the protected source before staging an image or switching a release.

PHP code, Composer dependencies and PHP/FPM requirements may change. The guest
compares the Laravel-registered migrations (including dependency migrations)
and checked-in schema dumps in the old and staged FPM images in networkless
containers without runtime mounts or credentials.
It checks the PostgreSQL 18 cluster identity, schema (including ownership and
grants) and migration ledger again before switching or accepting the release.
Changes that require a migration stay under the broader #93 contract.

### Backend compatibility evidence

Before proposing a backend pin change, render a disposable
[least-privilege stack](fcos-application-poc.md#separate-runtime-and-migration-authority-on-a-fresh-fixture)
on each native architecture. Follow the
[isolated networking procedure](fcos-application-poc.md#arm64-postgresql-process-crash-qualification)
on both architectures. Use the [logical restore procedure](fcos-application-poc.md#cross-host-logical-restore)
for the database, applying the archive instead of running the migration unit.
Restore representative synthetic data from the enrolled PostgreSQL 18
schema and ledger. Use separate storage, slot-local credentials and queues,
and the same restricted runtime grants, including read-only access to the
migration ledger. Test the exact signed predecessor and candidate pairs.

On the disposable database, run the role helper's `prepare` operation
before starting PostgreSQL. Apply its reviewed `grant-role-contract` SQL to
the empty database, restore using `pg_restore --role=secpal_owner --no-owner
--no-acl`, and apply the `restrict-migration-ledger` grant change. Set the
runtime password from the slot's protected credential file and enable only
the runtime login.
Keep the migration login disabled and remove its disposable credential
files before starting the application. Run the existing database authority
probe to check the restored grants. For each rehearsal pair, set only the
five backend roles' `Image=` overrides in the disposable Quadlets to the
verified native Nginx and FPM manifests.

1. Start the candidate over the restored schema with migration execution
   disabled. Check Composer platform requirements and the PHP/FPM runtime.
   Verify that `php artisan migrate:status` succeeds with no pending migrations,
   including migrations registered by dependencies. Compare the complete
   registered migration definitions and the ledger with the predecessor's.
2. Reuse the [database and application checks](fcos-application-poc.md#execute-the-database-and-application-checks)
   against the isolated fixture.
   Check login, `/v1/me`, existing organisation and record reads, authenticated
   writes and read-back, tenant boundaries, and both worker queue receipts.
   Confirm one scheduler is active and observe an expected scheduled task.
   Exercise the affected data formats and job contracts explicitly.
   Confirm that DDL with the runtime role is denied and the clone's cluster
   identity, schema and ledger are unchanged. Record an architecture-specific
   success record only when these checks pass.
3. For rollback evidence, exercise the exact predecessor on the same clone
   **after** the candidate writes representative records and enqueues
   representative pending jobs. Verify the predecessor reads those records and
   handles those jobs through the same checks. Leave rollback unqualified if
   affected formats or jobs lack coverage or any check fails.

In the pin PR, review the private rehearsal records against both signed pairs,
the exact test coverage and the restored schema and ledger. Do not publish
test data or credentials. Add the following keys to
`config/quadlet/fcos-lab-rollout/backend-compatibility.json`:

| Key                               | Required value                                                                                                                                                                                     |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`                  | `1`                                                                                                                                                                                                |
| `previous_pair`, `candidate_pair` | Exact signed OCI pair digests                                                                                                                                                                      |
| `schema`                          | SHA-256 of `pg_dump --schema-only --no-owner --no-privileges` against the rehearsal database, dropping lines beginning with PostgreSQL's `\restrict` and `\unrestrict` markers followed by a space |
| `ledger`                          | SHA-256 of the unaligned single SQL result plus its terminating newline from `SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id), '[]'::jsonb) FROM public.migrations AS m`                        |
| `forward`                         | Object with exactly `linux/amd64` and `linux/arm64`, each referencing the distinct private successful rehearsal record as a `sha256:…` digest                                                      |
| `rollback`                        | `null` or the same two-platform map referencing separate successful predecessor rehearsal records                                                                                                  |

Set `LAB_API_COMPATIBILITY_SHA256` to the lowercase SHA-256 of the exact JSON
file bytes. This binds the reviewed record to the existing release fingerprint.
Every guest verifies the file hash and pair and compares the schema and
ledger to its live database before staging. Missing or failed rehearsals
leave the candidate ineligible. The guest also continues to snapshot
ownership and grants for drift detection; the cross-host rehearsal must
check those permissions explicitly.

Activation stops API HTTP, the workers, scheduler and FPM before updating
their image references. It starts FPM before API HTTP and the background
units. The guest checks the pair and worker cardinality and compares the
container IDs and start times of PostgreSQL, frontend, HAProxy, CrowdSec
and SPOA across the switch. Rollback uses the locally retained predecessor
and requires the same database snapshot and separate backward compatibility
evidence. Without backward evidence, a failed switch or acceptance halts for
a forward fix or an independently approved recovery. A previously admitted backend pair
also needs current security qualification before it may be restarted.
An ambiguous interruption stops the
controller at the recorded host. Reconcile the observed guest state through
the existing administrator path before resuming.

The coordinator invokes the installed adapter with an operation, host,
platform, and the candidate and previous Git revisions and fingerprints.
Preparation must succeed on CX23, CX33 and CAX21 before any activation.
The controller verifies the OCI index with the existing GitHub attestation
toolchain, including the exact publisher workflow and source commit on main.
It binds each signed native child to its host. The guest independently
checks the requested revision and fingerprint against protected main, independently
verifies the supplied publisher bundle and immutable index with the same pinned
verifier, checks the native child, pulls it as the rootless runtime user,
and validates the affected Quadlets and image drop-ins in isolation.

| Operation  | Guest and controller behavior                                                                                                                                                                                               |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `observe`  | Read the installed Quadlet and running container identities. Return exactly the observed 64-character fingerprint and newline for an admitted state. Reject drift and mixed state.                                          |
| `prepare`  | Match the accepted predecessor and the permitted release lane. Verify and stage native images, validate the candidate and persist both release identities before any switch.                                                |
| `activate` | Select the frontend unit or the complete backend group from the prepared record. Verify running native manifests, image configuration and unchanged roles and layout.                                                       |
| `accept`   | Check real TLS, private app/API routing, authentication and the synthetic organisation, plus PostgreSQL cluster identity, both queues, one scheduler, rootless/SELinux and AppSec inspection. Persist the accepted release. |
| `rollback` | Restore the admitted previous release and verify its health. Keep the PostgreSQL container, volumes and private inputs intact.                                                                                              |

An explicit rejection returns exit code 10 from `accept`. Other errors halt
on an ambiguous result. Successful operations other than `observe` have no
standard output. Neither application credentials nor guest administrator
credentials are passed as command-line arguments.

For an existing enrollment, install the reviewed guest helper at the same
fixed path on each guest and verify `observe` against its accepted baseline.
Keep the existing policy, sudoers entry, SSH restrictions, state, and pinned
GitHub CLI. The controller then installs the reviewed adapter and OCI fetcher
at their existing paths. Keep the timer and its accepted state. Perform this
upgrade before merging a backend pin change. Link the existing reviewed
`SecPal/.github` evidence architecture checkout at
`$HOME/.local/lib/secpal-fcos-lab-rollout/evidence-architecture`. Verify the
checkout against the accepted authority and confirm its locked dependencies
are installed. The validator and its companion modules run from the resolved
checkout. Missing or rejected validator admission blocks backend operations.

## One-time guest administrator handoff

An independent administrator does this once on each existing lab guest.
Use the existing authenticated management path. The controller's standing
credential must never be its broadly authorized bootstrap key. Confirm the
guest's machine ID, WireGuard source, SSH host identity and installed fixture
before installing the exact reviewed source revision.

1. Create one dedicated synthetic organisational unit named
   `FCOS lab rollout witness` using the existing private fixture. Record its
   UUID and use a synthetic account permitted to read that unit and create
   a child within it. The acceptance check writes one synthetic child for
   each distinct release fingerprint using the existing application POST
   route. Read-back of the exact child under the witness makes a retry
   idempotent. AppSec inspection remains active. Prepare the root-only input `/secure/guest.json` with
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

## Host maintenance and workload assignment

The FCOS host contract applies before assigning an application. Confirm
the Fedora-signed deployment, authenticated SSH, direct WireGuard, SELinux
Enforcing, and rootless Podman and the user Quadlet generator. Apply
the same host maintenance configuration after enrolling a new host or
when maintaining an existing host. A host with no workload still has a
complete host acceptance.

The five-minute container timer covers the enrolled SecPal fixture.
Frontend deployment is live-qualified. The backend lane admits reviewed
migration-free API, FPM, worker and scheduler changes through the shared
release coordinator. Its first live code change still needs qualification.
Discovery of PostgreSQL, HAProxy, CrowdSec, SPOA and CRS versions is
informational. Those roles have no automatic rollout in this fixture.
CX23, CX33 and CAX21 in that order is the qualified frontend test sequence.
Before changing a host's fixture assignment, pause its existing lab rollout
and reconcile enrollment. Independently administered workloads use their
own reviewed pins and lifecycle.

### Select the native update mode

Choose a mode for the host's current workload assignment. Use one native
update driver at a time.

| Mode                                   | Driver                                                                       | When to reboot                                                                              |
| -------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Independently restartable              | Zincati Stable with a weekly UTC window                                      | Zincati may reboot in the window                                                            |
| Workloads with cross-host dependencies | rpm-ostree with `AutomaticUpdatePolicy=stage`                                | After the selected host is admitted for maintenance and the previous host passes acceptance |
| Reproducible test                      | Both automatic drivers paused, with the admitted deployment pinned if needed | As required for the exact version under test                                                |

For an independently restartable host, confirm that its local data,
networking, and service startup do not depend on other hosts being updated
in any particular order. Confirm the local zone, installed workload
assignment, maintenance window, and independent recovery path. Qualify
one controlled OS update and reboot with the assigned-workload acceptance
below before enabling periodic maintenance. Disable
`rpm-ostreed-automatic.timer`, allow any transaction to finish, and set
`AutomaticUpdatePolicy=none` in `/etc/rpm-ostreed.conf`. Run
`rpm-ostree reload`. Ensure there is no unreviewed pending deployment.
Replace the controlled Zincati update configuration with one reviewed
periodic window, then restart `zincati.service` outside that window.

```toml
[updates]
enabled = true
strategy = "periodic"

[updates.periodic]
time_zone = "UTC"

[[updates.periodic.window]]
days = ["Sun"]
start_time = "01:00"
length_minutes = 30
```

Verify the effective Zincati strategy in the journal, the disabled native
timer and the unchanged boot ID. A window constrains local reboot timing.
It cannot certify the health of another host or provide HA coordination.
[Zincati update strategies](https://coreos.github.io/zincati/usage/updates-strategy/)

### Stage Stable updates for controlled activation

For dependent workloads, keep `[updates] enabled = false` in
`/etc/zincati/config.d/90-secpal-controlled.toml`. For an enrolled host tracking
`ostree-image-signed:docker://quay.io/fedora/fedora-coreos:stable`, set
`AutomaticUpdatePolicy=stage` in the `[Daemon]` section of
`/etc/rpm-ostreed.conf`. As the host administrator, run
`rpm-ostree reload`, then `systemctl enable --now rpm-ostreed-automatic.timer`.
Verify the active timer, its last service result, the staged and booted
deployments, and the unchanged boot ID.
[rpm-ostreed configuration](https://github.com/coreos/rpm-ostree/blob/main/man/rpm-ostreed.conf.xml)

Staging queues a deployment for the next boot. Treat an unrelated reboot as
an activation risk while a candidate is staged. Pause the timer with
`systemctl disable --now rpm-ostreed-automatic.timer` and allow an in-flight
staging operation to settle before inspecting or selecting a version. For
the Zincati mode, set `enabled = false` and restart `zincati.service` outside
the normal reboot window. Read back the state of both drivers. To
hold the booted version across a reboot, inspect the pending deployment,
then use `rpm-ostree cleanup -p` if it may be discarded. Verify that no
pending deployment remains. For an
exact test version, admit the signed native digest and stage it with
`rpm-ostree rebase --disallow-downgrade ostree-image-signed:docker://quay.io/fedora/fedora-coreos@sha256:<native-digest>`.
Leave both automatic drivers paused for the test. Resume the selected
driver after returning to signed Stable tracking. Pause the independent container timer during
reproducible tests or OS activation, and select SecPal versions by exact
reviewed release inputs. Resume the applicable timers after read-back.

### Activate one staged host at a time

1. Pause the container rollout for the affected enrollment. Confirm no
   rollout or staging transaction is active. Inspect the staged signed
   version/digest, current boot ID and recovery access. Retain the known-good
   deployment. Compare the installed workload assignments before reboot.
2. Authorize the reboot for one host. Reauthenticate over the direct
   WireGuard path. Require a different boot ID, the expected deployment,
   matching SSH identity, SELinux Enforcing and a functioning rootless
   Podman/Quadlet setup. Test ready services only for the workloads assigned
   there. For the SecPal fixture, include database, worker, scheduler, HTTPS
   and AppSec acceptance.
3. Record acceptance before authorizing another host. Halt on a failed read-back
   and retain the previous deployment or use independent recovery. A weekly
   local window cannot enforce the previous host's readiness.
   [Zincati update strategies](https://coreos.github.io/zincati/usage/updates-strategy/)

Keep unattended reboots disabled for dependent workloads. For an
independently restartable host, the controlled update, health checks and
independent recovery above qualify enabling the native periodic strategy.
Record its first unattended reboot separately when a newer release is
available.

## FCOS operations handoff

| Status                       | Scope                                                                                                                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LIVE QUALIFIED               | Retained multiarch FCOS installs, direct IPv4/IPv6 WireGuard and pinned SSH, SELinux and rootless Podman/Quadlet. Native Stable staging and controlled FCOS 45 activation passed on all three lab hosts. The frontend lab timer has delivered a real release. |
| CONFIGURED / READY           | Zincati periodic maintenance on the current independently restartable lab assignments. The existing lab backend adapter, signed-pair admission and proposals.                                                                                                 |
| NOT YET QUALIFIED            | First unattended Zincati reboot, first live changed-code backend release, independent off-host restoration of the development host and its public endpoints, and public application automatic deployment on FCOS.                                             |
| LATER PRODUCTION REQUIREMENT | Complete production credential custody, data recovery, activated application update/migration/rollback and any coordination required by the actual topology.                                                                                                  |

The current lab assignments use separate PostgreSQL clusters and local
Podman networks. Each host moved from FCOS `44.20261023.3.1` to
`45.20261030.3.1` through one controlled reboot before the next host
was admitted. The checks used pinned SSH over direct WireGuard on both
address families, independent public bootstrap SSH, the new boot ID,
SELinux, the running Quadlets, persistent volumes and database read-back.
The existing container coordinator returned the accepted fingerprint.

For these assignments, Zincati is the registered update driver and has
checked Fedora's update graph. The native rpm-ostree automatic timer is
disabled. The next allowed windows are Sunday in UTC:

| Host  | Window      |
| ----- | ----------- |
| CX23  | 01:00–01:30 |
| CX33  | 03:00–03:30 |
| CAX21 | 05:00–05:30 |

Persistent Zincati pause and resume were verified on CX23 without a reboot.
Review the mode again when assignments change. These windows are local
maintenance settings for currently independent hosts.

### Provision a host independently of its workloads

Use the exact reviewed source and accepted evidence under
[Host Foundation #425](https://github.com/SecPal/deployment/issues/425) and its
[draft provisioning runbook](https://github.com/SecPal/deployment/blob/7538a295cb6e2202913c90606b2825591fa6d951/docs/fcos-provisioning-foundation.md).
Verify the native signed Stable Metal artifact, Butane and Ignition for
amd64 or arm64. Reuse the authenticated Rescue and Console trust path, then
bind the actual disk and immutable provider identity before installing.
Preserve provider protections. The draft distinguishes historical
multiarch installs from the signed-RPM installer and provider-custody
acceptance still required for the foundation delivery.

For a fresh install, authenticate the new SSH key through the Console path.
Generate the WireGuard key on the host. Use the existing
`secpal-test-bootstrap` and `secpal-test-network` replacement contract for an
authorized test slot with the current generation. Check retirement of the
previous peer and SSH pin, direct IPv4 and IPv6, split routes, firewall
rejection, and pinned SSH. Keep independent public bootstrap/Console
recovery. Compare the same host and WireGuard identities after an ordinary
reboot. Verify SELinux and rootless Podman/Quadlet before assigning a workload.
Use the scoped helper's installed runbook at
`/usr/local/share/doc/secpal-test-network/README.txt`.

### Inputs that must survive the old secpal.dev

Make the following checks from a separate, authorized workstation or
recovery host before authorizing disk overwrite. An encrypted archive and
its recovery authority must both be accessible without starting secpal.dev.
Keep root and operator credentials out of Git and out of Codex output.

| Authority or state                      | Recovery source                                                                                                                                                                                                                                                                                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source and release identity             | Protected Git refs and verified commits for deployment, API, frontend and governance. Export any unpublished work, admitted release identities, public access inventory and nonversioned operational instructions to external custody.                                                                                                                        |
| Provider, public DNS and TLS            | Independently accessible provider Console/Rescue account, MFA and break-glass material, exact resource identity and protections, reviewed firewall and DNS bindings, TLS renewal authority. Install the broker's protected configuration and scoped credential through the independent administrator.                                                         |
| Management connectivity                 | Root-owned NetworkManager/WireGuard configuration for both the hub link and direct test link, exact peer reservations, last applied generations, recovery SSH keys and independently pinned public host keys. Retain key continuity for unchanged machines under existing custody. Prepare authorized replacement for the reinstalled host's keys.            |
| Accounts and local operations           | User IDs and mappings, systemd units and settings, Codex/maintenance lease boundaries, installer executables and constrained administrative policy. The administrator exports any local material that cannot be reproduced from reviewed Git. Preserve separate Codex, Polyscope and application accounts.                                                    |
| Rollout controller                      | Protected `~/.config/secpal-fcos-lab-rollout/` and `~/.local/state/secpal-fcos-lab-rollout/`, with host pins, scoped SSH credential, witnesses and accepted journal. Record the exact reviewed installed helper and adapter. Keep service definitions and verifier pins from Git.                                                                             |
| Public application and development data | A consistent off-host copy of PostgreSQL data and roles and the associated private and public file trees, exact runtime and edge configuration, and independently recoverable application encryption/decryption and other durable keys. Capture developer state required after disk loss. Verify the recovery metadata and read-back from a separate machine. |

### Restore secpal.dev in order

1. From the authorized recovery machine, prove independent Console access,
   backups, decryption, signed native boot inputs and the external configuration
   inventory. Order the restore before enabling public traffic or maintenance
   services. Preserve provider identity, primary addresses and protections.
   The test broker's fixed allowlist excludes secpal.dev. Bootstrap the
   development host under the independent provider administrator.
2. Install the new host from admitted FCOS artifacts and authenticate the new
   SSH host key through Console. Update host pins through that authenticated
   path. Rebuild the hub and direct WireGuard profiles from the retained
   non-secret configuration and firewall policy. Generate fresh controller
   WireGuard keys on the reinstalled host. Replace its public keys at the
   hub and guests through their authorized administration, retire the old
   controller keys, and verify direct IPv4/IPv6 SSH and pin identity from
   outside secpal.dev. Keep the peer identities of guests whose installations
   remain in place.
3. Restore the restricted accounts and reviewed tools. As `codex`, reinstall
   the verified Codex CLI, sign in using `codex login --device-auth` where
   authorized, and verify `codex login status`. Reauthorize the intended
   GitHub account with `gh auth login --hostname github.com --web` and
   verify `gh auth status`. Restore the authorized SSH signing key or register
   a newly generated signing key in GitHub and verify a signed commit. Codex
   and GitHub logins can be issued again. Operator SSH keys and public TLS certificates can also be reissued with independent authority. Preserve the durable encryption keys required by existing data. Keep deployment credentials scoped
   to their respective roles.
   [Codex CLI documentation](https://developers.openai.com/codex/cli)
4. Restore the lab controller using the [existing setup](#controller-setup-and-qualification)
   with the protected inputs and timer disabled. Reconcile live host assignments
   and `observe` results with the saved journal. For a blocked journal,
   use `--recover` only after all affected hosts agree. Verify user lingering
   and the reviewed main fingerprint, then resume the lab timer and observe
   one ordinary run. The host OS mode is selected separately.

### Public application recovery and later updates

Treat `app.secpal.dev` and `api.secpal.dev` as a separate public workload
assignment. Before any public cutover, obtain the applicable host and
workload admission, restore the last accepted pair-aware release in
isolation, and verify exact digests, routing, TLS, authenticated data
read-back, workers and scheduler. Use the
[state recovery boundary](architecture/production-state.md#postgresql-and-application-recovery-boundary).
For Managed production recovery, follow the existing
[RecoverySet contract](https://github.com/SecPal/deployment/issues/109)
and [host-loss drill](https://github.com/SecPal/deployment/issues/110).
The lab proofs leave this public FCOS workload admission outstanding.

The current development maintenance's demo auto-discovery is retired.
The update contract [#93](https://github.com/SecPal/deployment/issues/93)
defines the reviewed reference workflow on its admitted host stack.
After admitting the public workload on FCOS, reuse its protected release
inputs and require publisher proof, explicit migration authority, a current
valid RecoverySet, compatible rollback and live acceptance before
enabling an automatic public rollout. The existing lab timer remains scoped
to the enrolled private fixture. The native FCOS OS driver follows the
host's selected maintenance mode.
