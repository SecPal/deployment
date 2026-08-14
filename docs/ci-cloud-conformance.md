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

| Provider       | Image                                 | Architecture | CPU evidence          | Status                             |
| -------------- | ------------------------------------- | ------------ | --------------------- | ---------------------------------- |
| DigitalOcean   | official `debian-13-x64`              | `amd64`      | Premium Intel profile | implemented; real lifecycle passed |
| DigitalOcean   | official `debian-13-x64`              | `amd64`      | Premium AMD profile   | implemented; real lifecycle passed |
| Google Compute | `debian-cloud/debian-13-arm64` family | `arm64`      | Axion/C4A             | implemented; real lifecycle passed |

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

Only one provider profile can run at a time. DigitalOcean has a 70-minute
provision/test limit and a two-hour TTL. GCP has a 100-minute limit so its
additional bounded stop/detach/start phase plus remote test fit before GitHub
termination, and a three-hour TTL leaves room for the separate 20-minute exact
cleanup job. Three hours remains the hard OpenTofu TTL ceiling. Concurrency
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
        | run only fixed v1 phases of target-conformance.sh as UID 20000
        v
trusted baseline -> target prepare/start -> trusted live collector -> target cleanup
        |
        | trusted post-cleanup collector; bounded JSON + summary
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
exporting credential variables to later steps. Separate short-lived tokens
enter only the trusted OpenTofu apply, exact VM-identity transition, destroy,
or janitor processes. No Workload Identity Federation credential reaches SSH,
the VM, OpenTofu state, evidence, or target code.

The identity-transition script gives curl its Bearer header through a config
line read from standard input. This is curl's documented `--config -` behavior
and deliberately keeps the token value out of the process argument list. The
local contract exercises that exact config line through the real curl parser
and a loopback HTTP server; its separate fake Compute API still verifies the
bounded request sequence without contacting GCP.

GCE attaches the project's default Compute Engine service account when an
instance-insert request omits `serviceAccounts`; an absent OpenTofu
`service_account` block therefore is unsafe. Provisioning instead names a
dedicated user-managed bootstrap service account which has no project/resource
roles, no user-managed keys, no federation trust, and an empty OAuth scope set.
It is intentionally incapable of useful cloud API access. The first native
startup-script invocation performs only a dependency-free, fail-closed metadata
identity gate. It waits for both an instance-specific admission marker with the
exact value `true` written by the trusted control plane and the documented HTTP
200 response with an empty body from the service-account metadata directory
before any diagnostic-SSH, package, operator-key, or target setup action. The
trusted runner verifies the exact bootstrap identity and its empty
scope set, obtains a fresh OIDC token, stops the exact run-bound instance, calls
the bounded Compute API operation with `{"scopes":[]}`, and verifies the stopped
instance has no service accounts. Only then does it add the admission marker,
restart the instance, and verify both the marker and identity-free running
state. GCE reruns the startup script after the start. If the newly provisioned
instance was already identity-free, the runner only writes the marker while it
remains running; the bounded waiting startup script then continues without an
unnecessary stop. The remote target step is structurally gated on completion of
this transition and receives no cloud token. Because GCE can release an
ephemeral external IPv4 when an instance stops, the pre-stop OpenTofu address
is never used for remote access. The same trusted transition reads exactly one
current `natIP` from the final identity-free running instance, admits it as a
public IPv4, and atomically hands it to the later uncredentialed SSH step. A
missing, private, or ambiguous address stops the run before target execution.

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

Add one additional variable only to the provisioning environment
`ci-cloud-gcp`:

```text
GCP_BOOTSTRAP_SERVICE_ACCOUNT=<ROLE_FREE_SERVICE_ACCOUNT_ID>@secpal-dev.iam.gserviceaccount.com
```

The provider must use issuer `https://token.actions.githubusercontent.com/`,
default audience, the documented GitHub claim mappings, and a condition that
requires repository `SecPal/deployment`, owner `SecPal`, ref
`refs/heads/main`, one of the two environments above, and only
`cloud-conformance.yml` or `cloud-janitor.yml` from `main`. The repository
principal receives only `roles/iam.workloadIdentityUser` on the dedicated
service account. Never create a service-account JSON key.

Create that bootstrap identity once with a deliberately chosen account ID. Do
not use the default Compute service account or the WIF control identity. Grant
it no IAM role and create no key or federation binding for it. Grant the WIF
control identity `roles/iam.serviceAccountUser` only on this one service-account
resource; this is the exact resource-level `iam.serviceAccounts.actAs` needed
to attach the inert identity during `instances.insert`:

```bash
# Replace this quoted placeholder with the deliberately chosen account ID.
export GCP_BOOTSTRAP_SERVICE_ACCOUNT_ID='ROLE_FREE_SERVICE_ACCOUNT_ID'
export GCP_BOOTSTRAP_SERVICE_ACCOUNT="${GCP_BOOTSTRAP_SERVICE_ACCOUNT_ID}@secpal-dev.iam.gserviceaccount.com"

gcloud iam service-accounts create "$GCP_BOOTSTRAP_SERVICE_ACCOUNT_ID" \
  --project=secpal-dev \
  --display-name="SecPal disposable conformance bootstrap"
gcloud iam service-accounts add-iam-policy-binding \
  "$GCP_BOOTSTRAP_SERVICE_ACCOUNT" \
  --project=secpal-dev \
  --member=serviceAccount:gcp-service-account@secpal-dev.iam.gserviceaccount.com \
  --role=roles/iam.serviceAccountUser
```

The following project-role query must print no rows for the bootstrap identity,
and the key query must print no user-managed key. Its own IAM policy may contain
only the resource-level `roles/iam.serviceAccountUser` binding above:

```bash
gcloud projects get-iam-policy secpal-dev \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${GCP_BOOTSTRAP_SERVICE_ACCOUNT}" \
  --format="table(bindings.role)"
gcloud iam service-accounts keys list \
  --iam-account="$GCP_BOOTSTRAP_SERVICE_ACCOUNT" \
  --managed-by=user \
  --project=secpal-dev
gcloud iam service-accounts get-iam-policy \
  "$GCP_BOOTSTRAP_SERVICE_ACCOUNT" \
  --project=secpal-dev
```

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
project-level `iam.serviceAccounts.actAs` to bypass a denied operation. The
single resource-level exception for the inert bootstrap identity is defined
above and must not be broadened.

The project custom role contains only the concrete instance, disk, VPC,
firewall, operation
polling, image-read, label, identity-removal, and service-use permissions
required by the root and the bounded janitor. The identity transition adds
only `compute.instances.stop`, `compute.instances.setServiceAccount`, and
`compute.instances.start`. It deliberately excludes Owner, Editor, Compute
Admin, IAM administration, and `iam.serviceAccounts.actAs`. The latter exists
only through `roles/iam.serviceAccountUser` on the exact inert bootstrap service
account, never at project scope. The identity-removal request omits `email` and
submits only `{"scopes":[]}`, matching Google's `--no-service-account`
semantics. The `network` fields used to attach the fixed subnetwork and firewall
rules to the per-run VPC require `compute.networks.updatePolicy` in addition to their
resource-specific create permissions; see the official
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
`HEAD` byte-for-byte against the SHA, and invokes the single fixed target path.
The versioned interface admits exactly `v1 host`,
`v1 workload-prepare-start`, and `v1 workload-cleanup`; no workflow input or
target output can select a command, executable, source path, Quadlet path,
collector field, or additional argument. Every phase runs as UID/GID 20000
with a phase-specific timeout and an empty environment containing only the
fixed home, locale, path, exact SHA, and SHA-derived 12-hex fixture instance.
The trusted wrapper also enters the literal checkout before target execution
and applies a 32-MiB per-file process limit to every phase. The target cannot
select either boundary.
The target account has no sudo authority. The `host` phase retains the D.1
contract suite. PR #22 owns the implementation of the two workload phases and
may cross the root-owned publication boundary only through the fixed trusted
fixture client.

The trusted runner creates one unrelated rootless control network and volume,
records a main-controlled baseline of every rootless Podman container, network,
and volume, invokes target prepare/start, streams the main-controlled live
collector, then requests target cleanup and streams the main-controlled
post-cleanup collector. Live admission requires the baseline plus exactly the
closed fixture resource set; post-cleanup admission requires the exact baseline.
An unprefixed, wrongly named, or leaked target resource cannot
disappear from the trusted inventory merely because it is outside the fixture
prefix.
It attempts cleanup and the post-cleanup observation even when prepare/start
fails or a handled `INT`, `TERM`, or `HUP` arrives while the host remains
reachable. Target phase status is preserved but is never evidence that a
workload existed or was removed. The collector runs by absolute path under an
empty environment and Python isolated mode. The
collector retains only the fixed operator home needed to observe effective
rootless Podman state; Python user-site startup hooks are disabled, and the GCP
metadata probe disables curl configuration before any other curl option. Target
output is discarded without creating a shared temporary file. Target-owned
Python or curl startup configuration therefore cannot replace the collector or
suppress cloud-identity evidence. The final GCP collector applies the same
metadata semantics as the early bootstrap gate: HTTP 200 with a bounded empty
`service-accounts/` directory proves identity absence, while a non-empty body
records identity presence. It discards the body after classification and treats
404, transport failure, truncation, or a malformed response as an unsuccessful
probe rather than evidence of absence.

The provider image may already carry subordinate-ID policy when the trusted
bootstrap creates `secpal-ci`. Before SSH is admitted, the root-owned host
setup removes
every well-formed range assigned to that account and installs the single fixed
`200000:65536` UID and GID ranges. Malformed databases or a failed exact
postcondition stop bootstrap admission instead of leaving ambiguous mappings.

The trusted bootstrap establishes the root-owned, initially empty Quadlet
definition directory and restricts the effective generator search path to it.
The target account cannot write that directory. A main-controlled fixture
bridge can promote one target-produced snapshot across that boundary without
granting sudo or a general root file-copy interface.

The main-controlled bootstrap installs the root-owned client as a fixed
executable for the disposable operator; it is not loaded from `target_sha`.
That unprivileged client publishes only an operation, a bounded instance ID, a
random request ID, and the complete closed set of 16 expected integration
filenames below one fixed staging path. No source path or command crosses the
request boundary. The manifest is canonical JSON with exact JSON types and no
duplicate keys. The root-owned one-shot installer rejects missing, extra,
non-regular, multiply linked, symlinked, changing, non-UTF-8, NUL-containing,
or oversized inputs. It snapshots at most 64 KiB per unit and 512 KiB in total,
then atomically installs only the derived destinations as root-owned mode
`0644`. It never imports a target-controlled Python module, sources a target
shell fragment, invokes a target command, or starts a generated user unit.

The root process stops the install operation's non-persistent path trigger
before it parses the request and never writes to or removes anything from the
user-controlled staging tree. The removal trigger remains armed only while a
root-recorded `removing` transition may need to resume; it is stopped before a
terminal removal result is published. Automatic removal retries are bounded to
three activations in 60 seconds. The systemd filesystem sandbox exposes only
the fixed trusted destination and state directories as writable. Replacing the
staging path can cause only a fail-closed request or self-inflicted denial of
service, not a privileged write or unlink through a swapped intermediate path.
The unprivileged client removes its own request after reading the bounded
root-owned result.

Before publication, the installer records the exact filename, size, and SHA-256
set in root-only runtime state. A separate fixed cleanup request must match the
same instance and every installed digest; ambiguity stops cleanup without broad
deletion. Both operations share one non-blocking, root-owned lock, so concurrent
install and removal requests cannot interleave trusted state transitions. The
cleanup state changes atomically to `removing` before the first unlink; a later
exact request can resume safely after interruption while still rejecting a
missing file from an allegedly complete `active` snapshot. An interrupted
removal publishes only the closed `retrying`/`internal-error` status and leaves
its bounded trigger armed; success or a terminal admission rejection stops it.
Neither trigger is enabled across a reboot. Both root services use fixed
commands, private networking, `NoNewPrivileges`, and a strict protected
filesystem view. The bounded result contains only a closed admission reason
code, never an exception string. Target code can deny service to its own
disposable test by submitting a bad request, but cannot select a root command,
destination, unrelated file, or cloud credential.

The reviewed Python installer and client are gzip/base64-encoded only for
provider payload transport so DigitalOcean's 64-KiB user-data ceiling retains
explicit headroom; each decoded root-owned file is byte-for-byte the reviewed
main-controlled source. Compression does not move trust to the tested revision.

This prerequisite supplies the trusted protocol and independent observations;
it does not implement the PR #22 product runtime. After this change merges,
PR #22 must update from that merged `main` commit, adopt the unprivileged
fixture client for its fixed cloud phases, and only then run one exact updated
PR #22 SHA on DigitalOcean Intel, DigitalOcean AMD, and GCP Axion. All three
bounded artifacts require review before a workload-conformance claim. This
prerequisite by itself does not prove that PR #22, a SecPal product image, or
any product container ran in cloud.

## Ephemeral SSH and initial host identity

Every run creates a new Ed25519 keypair on the GitHub runner. Only the public
key enters OpenTofu and the selected provider. The private key is mode `0600`, is never
an output, state value, artifact, or repository file, and is removed before
the provisioning/test job ends. The disposable operator account is initially
created without an authorized key. A single trusted shell payload from `main`
retains only the public key in root-only bootstrap state across the controlled
kernel reboot and stages it as root-owned mode `0600` only on the admitted
second boot; GCP does not receive an instance-level `ssh-keys` metadata entry.
DigitalOcean receives that payload
through Droplet `user_data`; GCP receives the identical reviewed payload through
the public-image guest agent's documented `startup-script` metadata key. This
provider-native transport split avoids assuming that two unrelated image
families implement the same cloud-config lifecycle. DigitalOcean's image may
use cloud-init to consume user data, but the contract relies only on its
documented first-boot shell-script interface, not cloud-config module ordering
or a runner-installed schema version. The key comment is bound to the exact
workflow run ID and attempt. The payload validates the run-bound key
and runner IPv4, generates the image's missing Ed25519 host key if necessary,
fully validates a separate diagnostic `sshd`, and installs its ten-minute
crash-recovery timer plus an independent recovery service using explicit
bootstrap-only systemd units that are validated before systemd loads them. The
installer first publishes a primary-SSH boot gate and then enables the
diagnostic service across the single authenticated kernel reboot. A root-owned,
atomically published selector chooses diagnostic SSH; the diagnostic unit
requires that selector, while the primary unit requires its absence. Its unit
orders itself after network readiness and before
the trusted continuation, and recreates the required `/run/sshd` and
`/run/secpal-ci-evidence` directories on every boot. It then masks the
primary service and socket and immediately starts that restricted listener
after selecting it. The generated unit uses OpenSSH's systemd
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
if the process is interrupted after selector publication, that same selector
makes a reboot start only the restricted listener; the installer EXIT handler
also retries its immediate activation. If
even the bounded recovery cannot construct a valid daemon, the transition
fails rather than opening an unvalidated fallback. The installer creates a
password-disabled `secpal-ci-diagnostic` account with a root-owned
bootstrap-only home that is
independent of later operator-user creation. The daemon accepts only that
account from the runner IPv4 with the ephemeral Ed25519 key, denies root, passwords,
forwarding, TTYs, user startup files, revoked or alternate key/principal
sources, and every command except a fixed reporter that emits one reserved
marker and, if available, one schema-closed host-setup stage and exit status.
Its public key remains root-owned and read-only mode `0644` under
`/var/lib/secpal-ci-diagnostic`, while its configuration remains root-only
under `/etc/ssh`, its fixed reporter is installed under `/usr/local/sbin`, and
its units remain under `/etc/systemd/system`; temporary key, configuration,
command, and unit files remain private until atomic publication. It
verifies that every published diagnostic artifact is a root-owned regular file
with its exact intended mode before systemd can load or start the daemon. It
neither exposes a shell nor can execute the selected target revision. The
root-owned failure helper is executable but independently restricts writes to
UID 0, allowing the diagnostic account to read only the closed non-secret
marker. If trusted host setup writes that marker, the reporter appends only its
validated stage and exit status; it never exposes the unrestricted operator
account to retrieve the marker.

Before operator SSH can be published, the trusted first boot replaces the
provider APT configuration with the closed signed Debian 13 sources, refreshes
their indexes, and installs the architecture-specific
`linux-image-cloud-amd64` or `linux-image-cloud-arm64` meta package. These are
Debian's kernel packages for cloud platforms, matching the kernel family the
official cloud image actually selects at boot. The bootstrap admits the meta
package's single, exact versioned image dependency only when the image package
is installed at its current authenticated APT candidate version and the
corresponding regular `/boot/vmlinuz-*` image exists. It deliberately does not
require the optional `/vmlinuz` convenience symlink, which official Debian
cloud images can omit.
The expected kernel release and initial Linux boot ID
are written atomically with the bounded run context under a root-owned mode
`0700` state directory. Only then is a root-owned continuation unit enabled and
exactly one reboot requested. This explicit disposable-fixture transition is
not production update automation and does not weaken D.1's prohibition on
automatic production reboots; unattended upgrades remain configured with
automatic reboot disabled.

On the next boot, the trusted continuation validates the state type,
ownership, mode, size, field count, and closed formats before using it. The
restricted diagnostic listener is an explicit ordering dependency, and the
continuation validates or creates its root-owned evidence directory and arms
the closed failure writer before it reads any persisted state. A malformed or
missing transition state can therefore report `continuation-state` rather than
degrading to an undifferentiated SSH timeout. It
immediately disables later automatic invocations, then reconstructs the
restricted diagnostic inputs from the persisted public context and restarts
the already reboot-enabled restricted listener, proves that the boot ID
changed, and requires `uname -r` to equal the previously authenticated image
package's kernel release exactly. The continuation contains
no reboot command, so a mismatch cannot form a reboot loop. Only after those
checks does it recreate the root-only staged operator key and invoke trusted
host setup. The persistent `pending` guard remains until host setup commits so
a concurrent GCP startup-script invocation cannot begin a second bootstrap or
reboot. Success then removes the continuation unit and persistent transition
state. Failure records the current closed continuation phase only when no more
specific host-setup failure marker already exists, so `kernel-verify`,
`apparmor`, or `ssh` remain authoritative. When the diagnostic channel cannot be
reconstructed, the host remains inaccessible and eligible only for exact
workflow cleanup or the ownership-gated TTL janitor.

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
diagnostic daemon, unmask the primary units, explicitly disable socket activation,
and enable the main SSH service. While the diagnostic selector still exists,
the primary boot gate prevents premature activation. Host setup then atomically
removes the selector, restarts the main service, verifies it active with socket
activation inactive, and only then publishes a root-owned mode `0400`
completion marker. Before stopping the diagnostic daemon, it re-arms the
recovery timer; the timer targets a separate recovery unit that recreates the
selector, masks primary SSH, and restores the restricted listener whenever the
completion marker is still absent. The initial diagnostic transition, operator
handoff, and recovery command serialize their state changes with the same
root-owned mode `0600` file lock under `/run`. The operator handoff holds this
kernel-managed lock through primary-listener verification and atomic marker
publication. A recovery process whose timer expires concurrently waits for the
lock and rechecks the marker only after acquiring it. Process termination closes
the file descriptor and releases the lock automatically, so recovery remains
available without a stale userspace lock. Thus an abrupt interruption during
the handoff retains deterministic recovery without relying on an EXIT handler,
even after the selector has moved to operator mode. The marker is the rollback-safe
setup commit and records an already verified operator listener. If main SSH
activation or marker publication fails,
the published operator key and marker are revoked, the main service is masked
again, and the restricted diagnostic daemon is restored. After successful
activation, setup is complete; stopping the still-armed recovery timer and
removing the stopped diagnostic identity,
bootstrap-only units, key, command, configuration, home, and state directory
is best-effort retirement and
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

The persistent mask also survives an unexpected reboot before the authenticated
kernel-transition state is fully published. Once the restricted diagnostic
service and its closed inputs have been atomically published and enabled, that
service survives such a reboot while still exposing only the fixed reporter to
the run-bound key and runner IPv4. The service retains its evidence runtime
directory across the controlled diagnostic-to-operator handoff, so a rollback
can publish its closed failure marker before restoring the restricted listener.
Before diagnostic selection, the provider listener remains the only boot
choice. After selection and until a verified operator handoff, the restricted
diagnostic listener is the only boot choice. Removing the selector changes the
boot choice atomically to the already prepared operator service, while the
independent recovery unit can reverse that choice until the completion marker
is published. Successful retirement first stops the timer and waits for any
running recovery unit before removing its command and unit. Only these closed
and serialized transition states may continue trusted setup.
After successful setup,
the persistent operator key and completion marker survive reboot. If the provider invokes the
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

The target-visible VM has no attached provider credential. GCE initially
receives only the explicitly configured role-free, scope-free bootstrap
identity; the privileged project default identity is never attached. The
trusted startup script admits no host or target setup until the separate
control-plane transition has removed and twice verified that bootstrap
identity and written the instance-specific admission marker. Identity absence
alone is deliberately insufficient admission. The admitted GCP instance disables legacy metadata
endpoints through the current official image defaults, blocks project SSH
keys, carries no instance SSH key, and exposes no cloud API scope or identity
token. Provider metadata may expose ordinary instance facts, but it is not a
source of cloud-control authority.

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
Cleanup does not require SSH or a reachable VM. The validation job publishes
the original, closed run-attempt identity once; provisioning, evidence, and
cleanup reuse that value, so a GitHub failed-job rerun cannot drift to a new
artifact name. A targeted rerun of a provider job is skipped because it cannot
refresh the validation job's resource identity; use a full workflow rerun or a
new dispatch when a new fixture is intended. A cleanup-only rerun continues to
select the original state. Cleanup initializes the locked provider at most
three times, with ten- and twenty-second delays and a 90-second bound per
attempt. The nominal retry schedule is five minutes; even if every process
requires the full forced-termination grace, the hard bound remains below six
minutes before cleanup fails closed to the janitor.

The scheduled TTL janitor is a second trusted workflow. It lists Droplets,
accepts only resources with all five unambiguous tags carrying one consistent
run identity, verifies the full SHA, repository, name, chronology, and maximum
TTL, retrieves the exact Droplet again, revalidates the metadata, and deletes
only its numeric resource ID. It fails closed on extra, missing, duplicate, or
contradictory metadata.
It runs hourly at minute 17. DigitalOcean fixtures expire after two hours, so
an expired Droplet is normally removed by the first following schedule—within
roughly three hours of creation plus any GitHub queue delay—even when exact
cleanup never succeeded. GCP fixtures expire after three hours to accommodate
their longer bounded provider phase and exact cleanup; the GCP janitor handles
them on its first subsequent schedule.

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
plus a concise Markdown summary. Schema version 2 keeps the D.1 production-host
admission result separate from the D.1a workload result; the overall result can
pass only when both pass and every target and collector phase exits zero.
The D.1 host phase status contributes only to D.1 host admission; baseline,
live, cleanup, and workload phase statuses contribute only to D.1a admission.
Incomplete, schema-invalid, oversized,
unknown, credential-shaped, or internally contradictory evidence fails.
If orchestration fails before the full collector can complete, the trusted
runner instead failure-atomically publishes a separate
`bootstrap-failure.json` and concise summary. The JSON is validated against the
committed closed bootstrap-failure schema, and both files are completely staged
before either final path is published. They contain only the validated
run/provider identity, orchestration start/end times, fixed failure stage, exit
status, and `CI_CLOUD_REMOTE_ORCHESTRATION` invariant. When the trusted host
setup itself fails, the evidence may additionally contain exactly one closed
stage (`diagnostic-ssh`, `apt-sources`, `apt-update`, `kernel-install`,
`package-install`, `operator-identity`, `host-policy`, `kernel-admission`,
`reboot-state`, `continuation-state`, `kernel-verify`, `host-setup`,
`host-initialize`, `subordinate-ids`, `service-policy`, `apparmor`, or `ssh`)
and its exit status. The stage changes immediately before each fallible phase,
so an early provider bootstrap failure does not collapse into an ambiguous
`initialize` result. A host-key-stage failure instead records only counters for
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
transport bindings and the exact SSH policy. The closed, run-bound Ed25519
public-key input is limited to 128 bytes, and the maximum admitted rendering
must retain at least 256 bytes below DigitalOcean's 64 KiB user-data limit.
Mutation tests reject Linux
account-lock commands, missing `*NP*` postconditions, and a reboot guard that
does not revalidate the complete operator identity. They also reject removal
of the authenticated kernel candidate, changed-boot-ID, exact running-kernel,
single-reboot, persistent-state retirement, or diagnostic-before-operator
ordering guards. A separate quality job
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
  presence, and each selected runtime/bootstrap package's actual APT-policy
  Release origin and codename rather than a global suite inference;
  the running kernel's exact owning package, installed status, architecture,
  Debian Kernel Team maintainer, safe root-owned dpkg databases, package-file
  verification, and whether the exact running version remains available from
  active authenticated Debian APT policy; a version absent from those indexes
  is recorded as unavailable and fails admission rather than treating local
  dpkg state as proof of Debian origin;
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
  `seccompEnabled` as three independent facts;
- the exact 16-file root-owned Quadlet snapshot with paths, modes, and SHA-256
  digests; the effective sole search path; and each generated user-service
  fragment and drop-in path, owner, group, and mode;
- the exact ten-container logical-role set, singleton counts for scheduler and
  activity-hash-chain worker, effective rootless/crun/security/namespace facts,
  the closed role-to-network topology, the gateway's sole loopback publication,
  immutable local image references, migration exit, healthy state for every
  health-bearing role, and running state for the remaining long-lived roles;
  and
- a pre-target full rootless Podman inventory and distinct post-cleanup
  observation requiring exact restoration of that inventory, including absence
  of every target-added container, network, and volume regardless of its name;
  exact `no-new-privileges` admission and Podman 5.4 `Healthcheck`/network-name
  field interpretation; and
- exact absence of every
  integration unit, generated service, container, network, and volume while
  the deliberately unrelated control network and volume remain present.

The Unix-listener admission recognizes listeners in the rootful and rootless
Podman runtime directories, including nonstandard socket-activation paths, and
listeners owned by an actual `podman` process. The exact Debian Netavark
`/run/podman/nv-proxy.sock` path is the sole pathname exception: it is network
plumbing and remains independently covered by the admitted Netavark package
and backend facts.

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
The workload collector establishes only the bounded facts represented by the
closed D.1a schema. It does not prove per-container AppArmor confinement unless
that fact is separately added to the trusted protocol, production
service-account paths, production readiness, customer workload
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

For PR #22 specifically, merge this prerequisite first, update PR #22 from the
merged commit, implement only its fixed-client target phases, and dispatch the
three providers against one exact resulting PR #22 SHA. Evidence from an older
PR #22 SHA cannot exercise this main-controlled protocol and is not admissible.

Real `main` runs have completed the full provision, Debian 13 conformance,
bounded-evidence, and exact-cleanup lifecycle for every implemented profile:

| Profile              | Tested target SHA                          | Successful run                                                               |
| -------------------- | ------------------------------------------ | ---------------------------------------------------------------------------- |
| DigitalOcean / Intel | `80300294a12891201a551419f6144af058852313` | [31671500152](https://github.com/SecPal/deployment/actions/runs/31671500152) |
| DigitalOcean / AMD   | `80300294a12891201a551419f6144af058852313` | [31672125657](https://github.com/SecPal/deployment/actions/runs/31672125657) |
| GCP / Axion          | `b04f00a3a7871e143446c352c1a13a42932890dd` | [31732827718](https://github.com/SecPal/deployment/actions/runs/31732827718) |

The GCP evidence records the official Debian 13 arm64 image on
`c4a-standard-4`, effective `arm64` with an ARM Neoverse-V2 CPU, a successful
cloud-identity probe, and no attached VM cloud identity. Its target entrypoint
passed, bounded evidence uploaded, and the independent exact cleanup completed.

These foundation runs did not all test the same target SHA: the DigitalOcean
proofs predate the final GCP identity correction. They establish that each
closed provider profile can complete its lifecycle, but they are not a claim
that one identical reviewed revision has passed the full three-profile matrix.
A deliberate same-SHA matrix run is the next reproducibility check.

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
- [GCE service accounts for instances](https://cloud.google.com/compute/docs/access/service-accounts)
- [GCE instance service-account update API](https://cloud.google.com/compute/docs/reference/rest/v1/instances/setServiceAccount)
- [Google GitHub Actions Workload Identity Federation](https://github.com/google-github-actions/auth#workload-identity-federation)
- [GitHub OIDC deployment hardening](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments)
