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

| Provider       | Image                          | Architecture | CPU evidence          | Status                           |
| -------------- | ------------------------------ | ------------ | --------------------- | -------------------------------- |
| DigitalOcean   | official `debian-13-x64`       | `amd64`      | Premium Intel profile | implemented, one host per run    |
| DigitalOcean   | official `debian-13-x64`       | `amd64`      | Premium AMD profile   | implemented, one host per run    |
| Google Compute | official Debian 13 arm64 image | `arm64`      | Axion/C4A             | deferred to the next provider PR |

The DigitalOcean root is
[`infra/ci-cloud/digitalocean`](../infra/ci-cloud/digitalocean). It uses the
fixed `fra1` region and one fixed 8-vCPU/16-GB/320-GB premium size for each CPU
vendor. The larger-than-minimum memory tier avoids treating guest-visible
memory lost to platform overhead as an 8-GiB D.1 pass. Image, region, size,
count, and TTL are not workflow inputs. OpenTofu `1.12.5` and the
DigitalOcean provider `2.99.1` are exact constraints; the provider lock file
is reviewed and committed.

Only one provider profile can run at a time. The workflow has a 70-minute
provision/test limit, cleanup has a separate 20-minute limit, and ownership
expires after two hours with a hard three-hour OpenTofu ceiling. Concurrency
serializes all runs and never cancels an active run. These limits are the cost
and abuse controls; a price assumption is not a security control.

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

## DigitalOcean environment configuration

Create a protected GitHub Environment named `ci-cloud-digitalocean`. Restrict
deployments to `main`, require intentional reviewer approval, and add one
secret named `DIGITALOCEAN_ACCESS_TOKEN`. Create a second main-only environment
named `ci-cloud-digitalocean-cleanup` with the same dedicated secret but no
reviewer wait; exact cleanup and the TTL janitor must never wait for a second
human approval after resources exist. Both environments must reject other
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
secret, approval, or required scope fails closed.

## Immutable selection and remote execution

The manual workflow accepts exactly two inputs:

- `target_sha`: a full 40-character hexadecimal commit SHA; and
- `provider_profile`: `digitalocean-intel` or `digitalocean-amd`.

The workflow rejects other refs and normalizes a valid SHA to lowercase before
it reaches OpenTofu or SSH. It accepts no branch, repository URL, shell text,
provider variable, count, image, size, or region. The trusted remote runner
initializes a new public checkout, fetches only the selected commit, verifies
`HEAD` byte-for-byte against the SHA, and invokes the single fixed target path
under a 40-minute timeout. The bootstrap target entrypoint runs the production
host contract and negative validators. A later D.1a-compatible commit can
extend that same narrow entrypoint with the reviewed real rootless
Podman/Quadlet lifecycle.

## Ephemeral SSH and initial host identity

Every run creates a new Ed25519 keypair on the GitHub runner. Only the public
key enters OpenTofu and DigitalOcean. The private key is mode `0600`, is never
an output, state value, artifact, or repository file, and is removed before
the provisioning/test job ends. Password and root SSH are disabled. Only the
runner's validated public IPv4 `/32` can reach TCP 22.

DigitalOcean does not provide the new guest's SSH host key over a separate
authenticated provisioning API. The runner therefore performs a bounded
trust-on-first-use bootstrap: it requires one Ed25519 key from two consecutive
`ssh-keyscan` observations, hashes the resulting `known_hosts` entry, and then
uses `StrictHostKeyChecking=yes` for every command. The remaining assumption
is that no active network attacker substitutes both first observations. The
per-run firewall, fresh user key, single resolved OpenTofu address, and short
lifetime reduce that window but do not turn TOFU into provider-attested host
identity. A future provider feature exposing an authenticated host-key channel
should replace this bootstrap.

The VM has no attached provider credential. DigitalOcean's metadata endpoint
may expose ordinary instance facts, but no provisioning token is copied to the
host and metadata is not a source of cloud-control authority.

## Ownership, cleanup, and orphan protection

Every managed resource name contains the exact GitHub run ID and run attempt.
The Droplet additionally has exactly five unique per-run tags encoding SecPal
CI ownership, repository, full target SHA, creation epoch, and expiration
epoch. Target code cannot choose names or tags.

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

This first janitor intentionally covers the billable Droplet only. If normal
state cleanup never runs, free orphaned firewalls, uploaded public keys, and
tag objects can remain. Deleting those safely after the Droplet has already
disappeared needs an additional provider-side ownership channel; a follow-up
must add that channel before extending janitor deletion. It must not infer
ownership from the `spci-` name alone. This limitation is explicit rather than
silently weakening orphan protection.

## Evidence and interpretation

Each reachable host produces closed-schema JSON plus a concise Markdown
summary. Incomplete, oversized, unknown, credential-shaped, or internally
contradictory evidence fails. Evidence includes:

- workflow/run identity, exact target SHA, provider, region, profile, time,
  exit status, result, and named failed invariants;
- `/etc/os-release`, `uname`, architecture, kernel, CPU vendor/model,
  virtualization, CPU/memory/disk facts, APT source hosts/suites, archive
  keyring version, and installed runtime package versions;
- Podman, crun features, Netavark, Aardvark, pasta/passt, uidmap, cgroup,
  systemd, effective OCI runtime, effective network backend, and rootless
  network command; and
- host AppArmor state, rootless Podman `apparmorEnabled`, and Podman
  `seccompEnabled` as three independent facts.

`podman apparmorEnabled=false` does not mean host AppArmor is disabled. The
collector fails D.1 host admission when kernel AppArmor or enforcing profiles
are absent, while recording rootless container AppArmor capability separately.
It does not claim a per-container profile unless later workload evidence
actually observes one. Seccomp is a separate hard runtime fact.

Evidence proves reproducibility of the reviewed Debian 13, rootless Podman,
and later Quadlet contract on the exact representative VM that ran. It does
not prove production readiness, customer workload capacity, backup/restore,
public networking, every provider image, or universal hardware compatibility.
Three successful representative hosts demonstrate independent reproducibility;
they do not prove that all hardware is compatible.

## Running an exact commit

1. Confirm the protected environment and dedicated scoped token are ready.
2. Open **Actions → Debian 13 Cloud Conformance → Run workflow** on `main`.
3. Paste the full commit SHA and choose exactly one provider profile.
4. Review the environment approval, then inspect the bounded evidence artifact
   and the independent cleanup job.
5. Treat any named invariant, missing evidence, cleanup failure, or janitor
   ambiguity as a failure.

No real cloud run was performed while adding this foundation because no cloud
credential was available in the development workspace.

## GCP/Axion follow-up contract

The GCP root must be a separate `infra/ci-cloud/gcp` implementation; it must
not introduce a generic multi-cloud module. Repository/environment
configuration will supply real values for `GCP_PROJECT_ID`, the full Workload
Identity Provider resource name, and the dedicated CI service-account email.
Those values are placeholders until an operator creates them; this repository
does not invent project numbers, IDs, or account names.

Authentication must use GitHub OIDC and Google Workload Identity Federation,
never a service-account JSON key. Only the trusted provisioning and cleanup job
gets `id-token: write`. The provider must map and condition the repository and
ref claims so only `SecPal/deployment` on `refs/heads/main`, through a protected
`ci-cloud-gcp` environment, can impersonate the dedicated identity. The IAM
binding must name that repository principal, not an organization-wide pool.

The dedicated identity needs a reviewed custom role containing only the
specific Compute instance, disk, network/subnetwork, firewall, image-read, and
label operations used by the future root. It must not receive Owner, Editor,
organization-wide, service-account-administration, or unrelated project
permissions. The WIF principal receives only
`roles/iam.workloadIdentityUser` on that dedicated service account. The custom
project role should start from the concrete calls the root will need:
`compute.instances.create`, `get`, `list`, `delete`, and `setLabels`;
`compute.disks.create`, `get`, `delete`, `setLabels`, and `use`;
`compute.firewalls.create`, `get`, `delete`, and `update`;
`compute.networks.create`, `get`, and `delete`; `compute.subnetworks.create`,
`get`, `delete`, and `use`; `compute.images.get` and `useReadOnly`;
`compute.machineTypes.get`; `compute.zones.get`; `compute.projects.get`; and
`serviceusage.services.use`. Implementation must remove any unused permission
after its API-call trace is reviewed and must add none merely for convenience.
Because the VM must have no service account, the role must not include
`iam.serviceAccounts.actAs`.

The C4A VM must use the official Debian 13 arm64 image, an exact allowlisted
machine type and zone, labels equivalent to the DigitalOcean TTL contract, and
no useful attached VM service account or broad cloud API scope. ADC files and
OIDC-derived values must be removed before remote execution and must never
enter the VM, state artifact, or evidence. The GCP provider path also requires
an exact-state cleanup job and a labels-gated TTL janitor before it can be
enabled.

## Primary references

- [DigitalOcean Linux image slugs](https://docs.digitalocean.com/products/droplets/details/images/)
- [DigitalOcean Droplet CPU profiles](https://docs.digitalocean.com/products/droplets/details/features/)
- [DigitalOcean custom API scopes](https://docs.digitalocean.com/reference/api/scopes/)
- [DigitalOcean OpenTofu/Terraform provider](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs)
- [OpenTofu CLI](https://opentofu.org/docs/cli/)
- [Google GitHub Actions Workload Identity Federation](https://github.com/google-github-actions/auth#workload-identity-federation)
- [GitHub OIDC deployment hardening](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments)
