<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# FCOS lab container rollouts

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

### Stage Stable updates without automatic reboots

Keep `[updates] enabled = false` in
`/etc/zincati/config.d/90-secpal-controlled.toml`. Use one native update
driver at a time. For an enrolled host tracking
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
staging operation to settle before inspecting or selecting a version. For an
exact test version, admit the signed native digest and stage it with
`rpm-ostree rebase --disallow-downgrade ostree-image-signed:docker://quay.io/fedora/fedora-coreos@sha256:<native-digest>`.
Leave the timer paused for the test. Resume automatic staging after returning
to signed Stable tracking. Pause the independent container timer during
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

Automatic staging and reboot acceptance are separate. Keep unattended
reboots disabled until the health gate and recovery have been qualified on
the selected topology.

### Restore the controller after reinstalling secpal.dev

1. Restore authenticated access and the direct WireGuard peers using the
   existing restricted management path. Restore protected keys only for
   deliberately retained identities. After guest reprovisioning, authenticate
   the regenerated SSH and WireGuard identities and revoke the old peer
   through the existing restricted replacement workflow before enrollment.
2. From reviewed main, restore the controller user, its installed scripts,
   verification tools, timer and user-manager state. Restore the private
   rollout key, SSH host pins, witness settings and state directory from
   protected custody. Use the controller setup above for file paths and
   ownership. Keep the container timer disabled during recovery.
3. Check the actual assignments over authenticated SSH. For the still-enrolled
   fixture run `observe` on every member and reconcile the accepted
   fingerprint with the saved controller journal. Use the documented
   `--recover` path for a blocked journal only after all members agree.
   Check protected main and then resume the timer. Hosts without this
   assignment retain their local OS maintenance policy and require no
   SecPal rollout enrollment.
