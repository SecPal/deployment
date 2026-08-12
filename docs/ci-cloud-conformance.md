<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Ephemeral Debian 13 cloud conformance

## Purpose and boundary

This infrastructure creates disposable, non-production Debian 13 hosts for
testing one explicitly selected `SecPal/deployment` commit. It is CI test
infrastructure only. It is not a production installation path, inventory,
provider decision, or managed-hosting system.

GitHub-hosted Ubuntu can prove integration behavior on its own effective
kernel, packages, and runner image. It cannot prove the D.1 Debian 13/trixie
host contract. In particular, Ubuntu package provenance, kernel policy,
AppArmor state, Podman build, and rootless networking are not Debian evidence.
The cloud matrix exists to collect those facts on official Debian 13 images
and to fail when a representative environment diverges from D.1.

No host may contain customer data, production secrets, DNS, certificates,
backup data, production inventories, application credentials, or provider
credentials. Every host and all of its state are disposable test fixtures.

## Implemented and planned matrix

| Provider       | Image                                 | Architecture | CPU evidence          | Status                        |
| -------------- | ------------------------------------- | ------------ | --------------------- | ----------------------------- |
| DigitalOcean   | official `debian-13-x64`              | `amd64`      | Premium Intel profile | implemented, one host per run |
| DigitalOcean   | official `debian-13-x64`              | `amd64`      | Premium AMD profile   | implemented, one host per run |
| Google Compute | `debian-cloud/debian-13-arm64` family | `arm64`      | Axion/C4A             | implemented, one host per run |

The DigitalOcean root is
[`infra/ci-cloud/digitalocean`](../infra/ci-cloud/digitalocean). It uses the
fixed `fra1` region and one fixed 4-vCPU/8-GB/160-GB premium size for each CPU
vendor. Guest-visible `MemTotal` is recorded exactly, but the provider's
nominal 8-GB label is not treated as proof of 8 GiB available inside the guest.
Memory remains descriptive until a workload-bearing D.10 measurement justifies
a universal admission floor. Image, region, size, count, and TTL are not
workflow inputs. The non-production conformance root
accepts exactly the official `debian-13-x64` slug, resolves it once through the
provider, provisions that numeric image ID, and records the resolved ID in the
closed evidence document. This deliberately exercises the current Debian 13
image rather than pretending the moving provider catalog is a production
deployment pin. OpenTofu `1.12.5` and the DigitalOcean provider `2.99.1` are
exact constraints; the provider lock file is reviewed and committed.

The independent GCP root is
[`infra/ci-cloud/gcp`](../infra/ci-cloud/gcp). It resolves the official
`debian-cloud/debian-13-arm64` family to one exact image self-link and uses
only `c4a-standard-4` in `europe-west3-a`, with one 120-GiB
`hyperdisk-balanced` boot disk. C4A is the reviewed Google Axion machine
series; the collector additionally requires effective `arm64` architecture
and an Axion/Neoverse CPU model. The resolved image name must match Google's
codename-bearing `debian-13-trixie-arm64-vYYYYMMDD` form. OpenTofu `1.12.5`
and Google provider `7.40.0` are exact constraints with a committed dependency
lock file. The provider's automatic Terraform-attribution label is explicitly
disabled so the instance and disk retain the exact seven-label janitor
ownership contract.

DigitalOcean plan availability is account-specific. If the API rejects the
fixed AMD size because the account tier does not expose it, provisioning fails
closed and cleanup still runs; the workflow never substitutes another size,
CPU profile, image, or region. The Intel profile can therefore establish the
first proof of concept without making AMD capacity or additional spend a
prerequisite. Enabling the reviewed AMD size remains an external account action
after that proof of concept succeeds.

Only one provider profile can run at a time. The workflow has a 70-minute
provision/test limit, cleanup has a separate 20-minute limit, and ownership
expires after two hours with a hard three-hour OpenTofu ceiling. Concurrency
serializes all runs, never cancels an active run, and uses GitHub's bounded
FIFO-by-wait-start queue so separately dispatched profiles are not silently
replaced while another profile is active; dispatch order itself is not
guaranteed. Because the pinned actionlint release predates this GitHub syntax,
its exact unknown-key diagnostic is ignored only for this workflow. The trusted
validator admits the exact top-level concurrency mapping and forbids job-level
concurrency, so that compatibility exception cannot hide another queue block.
These limits are the cost and abuse controls; a price assumption is not a
security control.

## Trust phases

```text
trusted workflow and scripts from main
        |
        | token exists only in the OpenTofu apply process
        v
one tagged Debian 13 VM + firewall + public SSH key
        |
        | no DigitalOcean/GitHub/GCP credential in this process
        v
strict-host SSH from the trusted main orchestration script
        |
        | fetch exact validated 40-character target SHA
        | run only scripts/ci-cloud/target-conformance.sh from that SHA
        v
trusted collector streamed from main; bounded JSON + summary
        |
        | token exists only in a separate always() cleanup job
        v
exact tofu destroy from the run's preserved state
```

The workflow never checks out `target_sha` on the GitHub runner. The target
entrypoint runs only as the unprivileged `secpal-ci` user on the disposable
VM. Its environment is constructed with `env -i`, has no GitHub token, and has
no DigitalOcean or Google credential. The account has no sudo authority. Code
from the target cannot alter the trusted OpenTofu configuration, cleanup job,
janitor, collector, or runner shell process that holds provider credentials.

The DigitalOcean token appears only in the trusted `tofu apply`, exact
`tofu destroy`, and trusted janitor process environments. It is not written to
OpenTofu variables, state, outputs, artifacts, VM user data, or evidence.
`actions/checkout` disables credential persistence.

GCP uses GitHub OIDC and Workload Identity Federation. Only the GCP apply,
cleanup, and janitor jobs receive `id-token: write`. The pinned authentication
action creates a short-lived access token without creating an ADC file or
exporting credential variables to later steps. That token enters only the
trusted OpenTofu apply/destroy or janitor process. No Google credential reaches
SSH, the VM, OpenTofu state, evidence, or target code.

The unique per-run ownership tag is attached to a Cloud Firewall before the
Droplet can be created. The Droplet depends on that tag-targeted firewall, so
the runner `/32` restriction does not wait for a post-creation Droplet-ID
attachment.

## DigitalOcean environment configuration

Create a protected GitHub Environment named `ci-cloud-digitalocean`. Restrict
deployments to `main` and add one secret named `DIGITALOCEAN_ACCESS_TOKEN`.
Do not require an environment reviewer: the explicit manual
`workflow_dispatch` from `main`, its closed inputs, and repository write access
are the intentional authorization for a run. Create a second main-only
environment named `ci-cloud-digitalocean-cleanup` with the same dedicated
secret and no reviewer wait; exact cleanup and the TTL janitor must never wait
for human approval after resources exist. Both environments must reject other
branches. The token must be dedicated to this repository's CI and use
DigitalOcean custom scopes rather than `api:read` or `api:write`:

- `droplet:read`, `droplet:create`, and `droplet:delete`;
- required read dependencies `regions:read`, `sizes:read`, `actions:read`, and
  `image:read`;
- `firewall:read`, `firewall:create`, `firewall:update`, and
  `firewall:delete`;
- `ssh_key:read`, `ssh_key:create`, and `ssh_key:delete`; and
- `tag:read`, `tag:create`, and `tag:delete`.

Do not grant database, registry, domain, project, block-storage, Kubernetes,
Spaces, monitoring, or account-wide alias scopes. A missing environment,
secret, main-branch authorization, or required scope fails closed.

## Google Cloud environment and IAM configuration

Create main-only GitHub Environments named `ci-cloud-gcp` and
`ci-cloud-gcp-cleanup`. Neither environment requires a reviewer: the explicit
manual `workflow_dispatch` from `main` is the intentional authorization for
provisioning, while exact cleanup and the TTL janitor must never wait after
resources exist. Add these Environment variables, not secrets, to both:

```text
GCP_PROJECT_ID=secpal-dev
GCP_WORKLOAD_IDENTITY_PROVIDER=projects/94792370946/locations/global/workloadIdentityPools/secpal/providers/github
GCP_SERVICE_ACCOUNT=gcp-service-account@secpal-dev.iam.gserviceaccount.com
```

The provider must use issuer `https://token.actions.githubusercontent.com/`,
default audience, the documented GitHub claim mappings, and a condition that
requires repository `SecPal/deployment`, owner `SecPal`, ref
`refs/heads/main`, one of the two environments above, and only
`cloud-conformance.yml` or `cloud-janitor.yml` from `main`. The repository
principal receives only `roles/iam.workloadIdentityUser` on the dedicated
service account. Never create a service-account JSON key.

Link the non-production project to an active billing account, then enable the
Compute API and the IAM, Resource Manager, Service Account Credentials, and
Security Token Service APIs required by service-account-backed WIF. These are
one-time project-administrator operations. Then create the project custom role from
[`iam-role.yaml`](../infra/ci-cloud/gcp/iam-role.yaml) and bind only that role
to the dedicated service account:

```bash
gcloud billing projects describe secpal-dev \
  --format="yaml(billingAccountName,billingEnabled)"
gcloud services enable \
  compute.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project=secpal-dev
gcloud iam roles create secpalCloudConformanceOperator \
  --project=secpal-dev \
  --file=infra/ci-cloud/gcp/iam-role.yaml
gcloud projects add-iam-policy-binding secpal-dev \
  --member=serviceAccount:gcp-service-account@secpal-dev.iam.gserviceaccount.com \
  --role=projects/secpal-dev/roles/secpalCloudConformanceOperator
```

If the custom role already exists, update it from the reviewed file instead of
running `roles create` again:

```bash
gcloud iam roles update secpalCloudConformanceOperator \
  --project=secpal-dev \
  --file=infra/ci-cloud/gcp/iam-role.yaml
```

The billing check must report `billingEnabled: true`. Enabling billing applies
to the whole project, not only to these CI fixtures; `secpal-dev` must remain a
non-production project with no customer data. Never grant the CI service
account Owner, Editor, Compute Admin, IAM administration, or
`iam.serviceAccounts.actAs` to bypass a denied operation.

The role contains only the concrete instance, disk, VPC, firewall, operation
polling, image-read, label, and service-use permissions required by the root
and the bounded janitor. It deliberately excludes Owner, Editor, Compute
Admin, IAM administration, `iam.serviceAccounts.actAs`, and service-account
attachment. The `network` fields used to attach the fixed subnetwork and
firewall rules to the per-run VPC require `compute.networks.updatePolicy` in
addition to their resource-specific create permissions; see the official
[`subnetworks.insert`](https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks/insert)
and
[`firewalls.insert`](https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert)
field-level authorization contracts. Review the first real provider API trace
and remove any permission that proves unused; do not add broad predefined roles
to bypass a denial.

## Closed selection and remote execution

The manual workflow accepts exactly two inputs:

- `target_sha`: a full 40-character hexadecimal commit SHA; and
- `provider_profile`: `digitalocean-intel`, `digitalocean-amd`, or
  `gcp-axion`.

The workflow rejects other refs and normalizes a valid SHA to lowercase before
it reaches OpenTofu or SSH. It accepts no branch, repository URL, shell text,
provider variable, count, image, size, or region. The trusted remote runner
reads the exact image identity and machine type selected by OpenTofu state and
passes them to the trusted collector. The closed schema admits only the fixed
DigitalOcean numeric image ID or the official exact GCP Debian 13 arm64 image
self-link with its matching fixed machine type. The trusted remote runner then
initializes a new public checkout, fetches only the selected commit, verifies
`HEAD` byte-for-byte against the SHA, and invokes the single fixed target path
under a 40-minute timeout. The bootstrap target entrypoint runs the production
host contract and negative validators. A later D.1a-compatible commit can
extend that same narrow entrypoint with the reviewed real rootless
Podman/Quadlet lifecycle.

After the target exits, the runner starts the main-controlled collector by
absolute path under an empty environment and Python isolated mode. The
collector retains only the fixed operator home needed to observe effective
rootless Podman state; Python user-site startup hooks are disabled, and the GCP
metadata probe disables curl configuration before any other curl option. Target
output is discarded without creating a shared temporary file. Target-owned
Python or curl startup configuration therefore cannot replace the collector or
suppress cloud-identity evidence.

The provider image may already carry subordinate-ID policy when the trusted
bootstrap creates `secpal-ci`. Before SSH is admitted, the root-owned host
setup removes
every well-formed range assigned to that account and installs the single fixed
`200000:65536` UID and GID ranges. Malformed databases or a failed exact
postcondition stop bootstrap admission instead of leaving ambiguous mappings.

The trusted bootstrap establishes the root-owned, empty Quadlet definition
directory and restricts the effective generator search path to it. The target
account cannot populate that directory. Before PR #22 can run its real units, a
follow-up must add one trusted, root-owned, main-controlled fixture installer to
this bootstrap.
That installer must be a one-shot service triggered only by a fixed staging
path; accept an explicit allowlist of regular Quadlet filenames from the
already SHA-verified checkout; reject symlinks, path traversal, unknown files,
and oversized content; copy only those files as root-owned mode `0644` into the
fixed definition directory; never source or execute target content; and disable
its trigger before the unprivileged lifecycle begins. The collector must then
prove the complete tree ownership, restricted search path, generated units,
and effective workload behavior. Merely extending the unprivileged target
script cannot create the required root-owned trust boundary.

## Ephemeral SSH and initial host identity

Every run creates a new Ed25519 keypair on the GitHub runner. Only the public
key enters OpenTofu and the selected provider. The private key is mode `0600`, is never
an output, state value, artifact, or repository file, and is removed before
the provisioning/test job ends. The disposable operator account is initially
created without an authorized key. A single trusted shell payload from `main`
instead stages the public key as root-owned mode `0600`; GCP does not receive
an instance-level `ssh-keys` metadata entry. DigitalOcean receives that payload
through Droplet `user_data`; GCP receives the identical reviewed payload through
the public-image guest agent's documented `startup-script` metadata key. This
provider-native transport split avoids assuming that two unrelated image
families implement the same cloud-config lifecycle. DigitalOcean's image may
use cloud-init to consume user data, but the contract relies only on its
documented first-boot shell-script interface, not cloud-config module ordering
or a runner-installed schema version. The key comment is bound to the exact
workflow run ID and attempt. The payload validates the run-bound key
and runner IPv4, generates the image's missing Ed25519 host key if necessary,
fully validates a separate diagnostic `sshd`, and arms its
ten-minute crash-recovery timer using explicit runtime-scoped systemd service
and timer units that are validated before systemd loads them. It then masks the
primary service and socket and immediately starts that restricted listener
while the timer remains armed. The generated unit uses OpenSSH's systemd
readiness notification, and every activation restarts the unit so `systemctl`
does not return until the newly loaded daemon has bound its listener. Only
after that readiness signal, an active-service check, and verification that the
primary units are inactive does it stop and verify the timer. The
diagnostic service additionally restarts after an unexpected process failure.
Those retries are rate-limited to five starts per two minutes. Preparation is
idempotent: after any failure with an already
validated run context, the EXIT handler rebuilds the password-disabled identity and
root-owned inputs and attempts to start the restricted daemon immediately. It
never deletes the only diagnostic material merely because initial preparation
was incomplete. If initial validation fails before masking, the provider
listener remains available only under its already restrictive cloud firewall;
if the process is interrupted after masking but before the immediate start,
the armed timer supplies the same restricted listener after ten minutes. If
even the bounded recovery cannot construct a valid daemon, the transition
fails rather than opening an unvalidated fallback. The installer creates a
password-disabled `secpal-ci-diagnostic` account with a root-owned runtime home that is
independent of later operator-user creation. The daemon accepts only that
account from the runner IPv4 with the ephemeral Ed25519 key, denies root, passwords,
forwarding, TTYs, user startup files, revoked or alternate key/principal
sources, and every command except a fixed reporter that emits one reserved
marker and, if available, one schema-closed host-setup stage and exit status.
Its public key remains root-owned and read-only mode `0644`,
while its configuration remains root-only under `/run`; temporary key,
configuration, and unit files remain mode `0600` until atomic publication. It
verifies that every published diagnostic artifact is a root-owned regular file
with its exact intended mode before systemd can load or start the daemon. It
neither exposes a shell nor can execute the selected target revision. The
root-owned failure helper is executable but independently restricts writes to
UID 0, allowing the diagnostic account to read only the closed non-secret
marker. If trusted host setup writes that marker, the reporter appends only its
validated stage and exit status; it never exposes the unrestricted operator
account to retrieve the marker.

Both disposable SSH identities use the literal, impossible `*NP*` password
marker and verify that exact effective `/etc/shadow` field before admitting a
listener. They are deliberately not locked with a leading `!`: Debian
OpenSSH documents that its portable account-accessibility check rejects such a
locked Linux account before public-key authentication. PAM-enabled behavior is
stack-dependent, so the design does not treat an account lock as its password
security boundary. Password and keyboard-interactive authentication remain
disabled by the effective daemon policies, so `*NP*` does not create a
password login path. Reboot
admission revalidates the operator name, UID/GID, primary group, home, shell,
supplementary groups, and password marker before trusting the persistent setup
marker. See Debian's
[`sshd(8)` account-accessibility contract](https://manpages.debian.org/trixie/openssh-server/sshd.8.en.html#AUTHENTICATION).

Trusted host setup validates and
normalizes the fixed subordinate-ID ranges, service policy, and AppArmor
evidence before atomically publishing a root-owned `secpal-ci` key file in a
root-owned persistent directory under `/var/lib/secpal-ci` in its final SSH
stage. The temporary
directory and key remain mode
`0700` and `0600` through the atomic rename; the published paths become `0755`
and `0644` only immediately before SSH activation. The prioritized SSH drop-in
uses the `%u` username token so no other account resolves to that file,
requires an accepted Ed25519 public-key algorithm, disables command-backed
keys, revoked keys, trusted user CAs and principal sources, user startup files,
server-forced environments, TTYs, forwarding, forced commands, chroots, and
connection-refusal or zero-session policy, requires strict key-file modes, and
restricts login to `secpal-ci`. Immediately before publication, host setup
validates SSH syntax and both operator/root configurations using the validated
runner source IPv4, the route-selected local listener IPv4, and TCP port 22. It
also rejects any effective `DenyUsers`, `DenyGroups`, or `AllowGroups` gate that
could silently exclude the operator. A provider-image `Match Address`, `Match
Host`, or `Match LocalAddress` rule, alternate public-key source, incompatible
algorithm list, or extra access gate therefore fails admission. Only after
those checks and key publication does host setup re-arm recovery and stop the
diagnostic daemon, unmask the primary units, explicitly disable socket activation, enable
the main SSH service, and atomically publish a root-owned mode `0400` completion
marker. Before stopping the diagnostic daemon, it re-arms the recovery timer;
the timer remains active until the main service is verified active and socket
activation is verified inactive. Thus an abrupt interruption during the
handoff restores the restricted listener without relying on an EXIT handler.
That marker is the rollback-safe setup commit: normal operator SSH is started
only after it exists. If main SSH activation fails,
the published operator key and marker are revoked, the main service is masked
again, and the restricted diagnostic daemon is restored. After successful
activation, setup is complete; stopping the still-armed recovery timer and
removing the stopped diagnostic identity,
runtime units, key, command, and configuration is best-effort retirement and
cannot roll a committed host back into a failed state. Any retirement residue
remains root-owned, has no main-SSH authorization, and has no active diagnostic
listener. This prevents the runner from
logging in while `usermod` replaces provider-image subordinate-ID ranges and
keeps key publication outside an operator-owned directory. The EXIT handler is
active before the first fallible host-setup
initialization. If an earlier trusted setup stage fails, it first writes the
closed failure marker when possible, revokes any partially published operator
key, and only then enables the same bounded diagnostic access. It never starts
normal operator SSH on a failed setup path. If native bootstrap fails after the
installer has armed the fallback but before trusted host setup can finish, the
independent timer still exposes only the forced diagnostic command.
The runner recognizes its reserved exit status and records bounded
bootstrap-failure evidence. A schema-valid terminal host-setup marker stops
readiness probes immediately; otherwise host-key discovery and operator
readiness share one absolute 15-minute bootstrap deadline. The restricted
diagnostic listener is normally available immediately; the delayed timer is
only the interruption-recovery path and cannot accidentally start a second,
shorter timeout.
The runner treats failed native bootstrap as terminal and never
checks out or executes target code in that case.

The persistent mask also survives an unexpected reboot before trusted setup.
Because the diagnostic timer is intentionally transient, such a reboot fails
closed with no SSH listener; exact workflow cleanup or the TTL janitor then
destroys the inaccessible fixture. After successful setup, the persistent
operator key and completion marker survive reboot. If the provider invokes the
native bootstrap again, its idempotent entry validates the marker,
state-directory ownership and modes, exact
run-bound public key, root-owned prioritized configuration, the same effective
operator/root SSH policy and connection contexts used by initial admission,
the persistently enabled primary service, and disabled socket activation before
it skips diagnostic installation. It intentionally does not require the service
to be active while boot units may still be starting.
Any missing, mismatched, symlinked, or malformed state revokes the persistent
operator key and rebuilds only the restricted fallback instead of trusting a
boolean marker. Normal service enablement and the persistent committed state,
not a provider-neutral cloud-config phase, restore SSH after an admitted reboot.

DigitalOcean initially embeds that public key
in the image's root account as part of Droplet creation; the trusted user-data
payload sets `PermitRootLogin no`, creates the dedicated `secpal-ci` account,
and restarts a validated SSH configuration. Before target code runs, the trusted runner uses
the same key and strict known-host entry to require the root public-key attempt
to fail, then immediately rechecks the disposable operator account over the
same transport. It records effective root denial only when the root attempt
fails with SSH's authentication/connection status while that operator recheck
succeeds; it does not depend on localized SSH diagnostic text.
Password SSH is disabled. Only the runner's validated public IPv4 `/32` can
reach TCP 22, through the pre-created tag-targeted firewall.

DigitalOcean does not provide the new guest's SSH host key over a separate
authenticated provisioning API. The runner therefore performs a bounded
trust-on-first-use bootstrap: it requires one Ed25519 key from two consecutive
`ssh-keyscan` observations, allows up to 15 minutes for masked SSH to be
released by trusted host setup or the restricted fail-safe, hashes the resulting `known_hosts` entry,
and then uses `StrictHostKeyChecking=yes` for every command. The remaining assumption
is that no active network attacker substitutes both first observations. The
per-run firewall, fresh user key, single resolved OpenTofu address, and short
lifetime reduce that window but do not turn TOFU into provider-attested host
identity. A future provider feature exposing an authenticated host-key channel
should replace this bootstrap.

The VM has no attached provider credential. The GCP instance has no service
account block, disables legacy metadata endpoints through the current official
image defaults, blocks project SSH keys, carries no instance SSH key, and
exposes no cloud API scope or identity token. Provider metadata may expose
ordinary instance facts, but it is not a source of cloud-control authority.

## Ownership, cleanup, and orphan protection

Every managed resource name contains the exact GitHub run ID and run attempt.
The Droplet additionally has exactly five unique per-run tags encoding SecPal
CI ownership, repository, full target SHA, creation epoch, and expiration
epoch. The GCP instance and separately managed boot disk carry an exact closed
seven-label contract for the same identity and TTL dimensions. Target code
cannot choose names, tags, or labels.

The independent cleanup job uses `if: ${{ always() }}`, downloads only that
run's short-lived non-secret OpenTofu state artifact, and performs exact
`tofu destroy`. It never deletes by prefix, account, project, or broad tag.
Cleanup does not require SSH or a reachable VM.

The scheduled TTL janitor is a second trusted workflow. It lists Droplets,
accepts only resources with all five unambiguous tags carrying one consistent
run identity, verifies the full SHA, repository, name, chronology, and maximum
TTL, retrieves the exact Droplet again, revalidates the metadata, and deletes
only its numeric resource ID. It fails closed on extra, missing, duplicate, or
contradictory metadata.

The GCP janitor is bounded to `secpal-dev/europe-west3-a`, and only to instance
and disk APIs. It accepts exactly seven labels, verifies the fixed provider
location, numeric resource ID, deterministic run-specific name, full SHA,
chronology, and maximum TTL, then retrieves and compares the exact resource
again immediately before deleting it by name. It deletes instances before
disks and waits for each zonal operation. It never deletes from a name prefix,
project-wide filter, or ambiguous label subset.

Provider resources that cannot carry the closed ownership metadata are not
janitor deletion candidates. If normal state cleanup never runs, DigitalOcean
firewalls, public keys, and tag objects or GCP VPC/subnet/firewall objects can
remain. Deleting them after the labeled compute fixture has disappeared needs
an additional provider-authenticated ownership channel. A follow-up must add
that channel before extending deletion and must never infer ownership from an
`spci-` name alone. Billable DigitalOcean Droplets and GCP instances/disks are
covered now; the remaining limitation is explicit.

## Evidence and interpretation

Each reachable host produces JSON validated against the committed closed schema
plus a concise Markdown summary. Incomplete, schema-invalid, oversized,
unknown, credential-shaped, or internally contradictory evidence fails.
If orchestration fails before the full collector can complete, the trusted
runner instead failure-atomically publishes a separate
`bootstrap-failure.json` and concise summary. The JSON is validated against the
committed closed bootstrap-failure schema, and both files are completely staged
before either final path is published. They contain only the validated
run/provider identity, orchestration start/end times, fixed failure stage, exit
status, and `CI_CLOUD_REMOTE_ORCHESTRATION` invariant. When the trusted host
setup itself fails, the evidence may additionally contain exactly one closed
stage (`initialize`, `subordinate-ids`, `service-policy`, `apparmor`, or `ssh`)
and its exit status. A host-key-stage failure instead records only counters for
the closed categories `connection_refused`, `connection_timeout`, `no_key`,
`multiple_keys`, `changed_key`, and `other`. Refused and timed-out connections
come from a bounded IPv4 TCP probe and stable operating-system error codes,
not locale- or version-dependent `ssh-keyscan` text; raw scanner errors and
observed key material are discarded. That root-owned marker is limited to 128 bytes, validated
before use, and contains no command output. A failed write leaves neither new
artifact behind. The fallback never copies target output, environments, cloud
credentials, provider boot logs, or arbitrary command output into that
artifact. A missing provider evidence directory is a hard upload failure rather
than a warning. Target code cannot run until native bootstrap has committed the
closed operator identity and SSH policy.

Preflight renders the common provider payload with the exact embedded trusted
scripts, checks it as strict Bash, and statically admits both provider-native
transport bindings and the exact SSH policy. Mutation tests reject Linux
account-lock commands, missing `*NP*` postconditions, and a reboot guard that
does not revalidate the complete operator identity. A separate quality job
starts a real OpenSSH daemon against a namespace-isolated password database. It
proves `*NP*` public-key admission, portable leading-`!` rejection without PAM,
and production-like `UsePAM yes` plus `*NP*` admission while all password
methods remain disabled. This targeted smoke does not simulate the provider's
guest agent or systemd handoff. Runtime validation remains authoritative for
the provider image and complete bootstrap behavior.

Evidence includes:

- workflow/run identity, exact target SHA, provider, location, profile, fixed
  machine type, resolved provider image identity, time, exit status, result, and named
  failed invariants;
- `/etc/os-release`, `uname`, architecture, kernel, CPU vendor/model,
  virtualization, CPU/memory/disk facts, root filesystem and OverlayFS facts,
  required tools, clock synchronization, and effective root-SSH denial;
- root-owned authenticated APT `InRelease` origins/suites, archive-keyring
  presence, and each selected kernel/runtime/bootstrap package's actual
  `apt-cache policy` Release origin and codename rather than a global suite
  inference;
  every bootstrap and runtime package's exact installed version,
  architecture, origin, and suite, forbidden package absence, and effective
  security-only unattended-update/reboot and runtime-package exclusion policy;
- Podman, crun features, Netavark, Aardvark, pasta/passt, uidmap, cgroup,
  systemd, effective OCI runtime, effective network backend, and rootless
  network command, including an effective subordinate-ID mapping probe;
- linger/user-manager/DBus state, the root-owned restricted Quadlet search
  path, Podman storage driver, disabled system- and user-scope API services,
  socket activation, TCP/Unix listeners, manual `podman system service`
  processes, complete process visibility, auto-update state, and effective
  SecPal/GHCR mirror, rewrite, and insecure-transport facts; and
- host AppArmor state, rootless Podman `apparmorEnabled`, and Podman
  `seccompEnabled` as three independent facts.

The trusted root-only host setup records loaded and enforcing AppArmor policy
counts in a root-owned, non-writable `/run` snapshot. The unprivileged collector
validates that file's parent and file ownership, type, mode, size, and closed
contents before using it. `podman apparmorEnabled=false` does not mean host
AppArmor is disabled. The collector fails D.1 host admission when kernel
AppArmor or enforcing profiles are absent, while recording rootless container
AppArmor capability separately.
It does not claim a per-container profile unless later workload evidence
actually observes one. Seccomp is a separate hard runtime fact.

Evidence proves reproducibility of the reviewed Debian 13, rootless Podman,
and Quadlet host-capability contract on the exact representative VM that ran.
It binds a run to the resolved provider image ID and exact installed package
versions while requiring those packages to come from the authenticated Debian
13 suites. It does not make the provider slug or Debian package repositories
immutable across separate conformance runs; that variability is intentional
only for this isolated, non-production compatibility probe.
The empty root-owned definition tree does not prove PR #22 units, workload
AppArmor confinement, production service-account paths, or product lifecycle
behavior. Evidence also does not prove production readiness, customer workload
capacity, backup/restore, public networking, every provider image, or universal
hardware compatibility.
Three successful representative hosts demonstrate independent reproducibility;
they do not prove that all hardware is compatible.

## Running an exact commit

1. Confirm the selected provider's protected environments and dedicated
   credential model are ready.
2. Open **Actions → Debian 13 Cloud Conformance → Run workflow** on `main`.
3. Paste the full commit SHA and choose exactly one provider profile.
4. Inspect the bounded evidence artifact and the independent cleanup job.
5. Treat any named invariant, missing evidence, cleanup failure, or janitor
   ambiguity as a failure.

Earlier workflow revisions performed real DigitalOcean Intel, DigitalOcean AMD,
and GCP Axion provisioning attempts and exact cleanup. Intel and Axion did not
reach trusted host setup, while the AMD API rejected the fixed size as outside
the account tier; none produced conformance evidence. Those failures are not
success evidence for this revision. The provider-native bootstrap change still
requires a fresh `main` run that creates, tests, records complete evidence from,
and destroys the host. Start with DigitalOcean Intel; do not enable or fund AMD
capacity merely to bypass that proof-of-concept gate.

## Primary references

- [DigitalOcean Linux image slugs](https://docs.digitalocean.com/products/droplets/details/images/)
- [DigitalOcean Droplet CPU profiles](https://docs.digitalocean.com/products/droplets/details/features/)
- [DigitalOcean custom API scopes](https://docs.digitalocean.com/reference/api/scopes/)
- [DigitalOcean Droplet user data](https://docs.digitalocean.com/products/droplets/how-to/provide-user-data/)
- [DigitalOcean OpenTofu/Terraform provider](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs)
- [OpenTofu CLI](https://opentofu.org/docs/cli/)
- [Google Debian image families](https://cloud.google.com/compute/docs/images/os-details)
- [Google C4A machine series](https://cloud.google.com/compute/docs/general-purpose-machines#c4a_series)
- [Google Compute Engine Linux startup scripts](https://cloud.google.com/compute/docs/instances/startup-scripts/linux)
- [Google GitHub Actions Workload Identity Federation](https://github.com/google-github-actions/auth#workload-identity-federation)
- [GitHub OIDC deployment hardening](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments)
