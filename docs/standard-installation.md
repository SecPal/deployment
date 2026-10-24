<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Standard Installation: public single-node host base

Issue [#92](https://github.com/SecPal/deployment/issues/92), Phase 1, separates
installation from admission. This entry point prepares public host material on
the currently qualified Rocky Linux 10.2 architecture. It requires a dedicated
blank host and an explicitly authorized administrator. It never escalates
privileges or runs on a target automatically.

## Inputs and owners

The existing production inventory is the sole host/account/path configuration
source. The existing #104 firewall document supplies DIRECT management CIDRs and
DHCP uplinks. Both inputs pass their existing closed validators. Documentation
addresses are rejected by the executable CLI.

| Material               | Existing owner                                                      | Phase-1 use                                                                           |
| ---------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Rocky/packages/runtime | #80; production-host validator, Rocky preparation contract/observer | Native identity, signed RPM admission, rootless checks                                |
| PostgreSQL 18          | #81; PostgreSQL declaration and renderer                            | Exact package pins and public configuration subset                                    |
| Podman/Quadlet/systemd | #80; canonical production inventory                                 | Non-login account, subordinate IDs, root-owned Quadlet search, lingering user manager |
| Host ingress           | #104; host-firewall helper and contract                             | Existing apply/read-back and boot restoration                                         |
| HAProxy/DIRECT         | #219/#220; supply admission and DIRECT renderer                     | Exact package identity and inactive loopback preview                                  |
| Enrollment readiness   | #241; trusted in-process readiness interface                        | Independent native and artifact admission remain mandatory                            |

Public PostgreSQL configuration is staged under `/etc/secpal/host-base`;
`roles.sql` is excluded. The loopback nft rules are staged for later database
materialization and are not applied by Phase 1. No database is initialized.

The HAProxy preview binds only `127.0.0.1:18085` and is syntax-checked without
starting HAProxy. PostgreSQL and HAProxy remain masked. No TLS private key,
customer route, application Quadlet, schema, migration or runtime credential is
installed. The existing #104 DIRECT ingress rules retain their 80/443 admission;
no customer listener is started. The reviewed source export includes the
generic #241 enrollment client; Phase 1 never invokes its identity operations.

## Authorized target procedure

These are operator instructions for a separately approved target. The corrected
XDG path below has not yet been executed on CX33: fresh exact-source scanner
qualification and independent review are prerequisites for further mutations.

1. Confirm Rocky 10.2, the selected native architecture and SELinux Enforcing.
   The static hostname must match the canonical inventory.
   Supply the reviewed non-secret production inventory and #104 DIRECT firewall
   document. Management CIDRs must include the operator connection; SSH on a
   different port is rejected. Confirm console access before applying ingress.
2. Stage the selected reviewed deployment source export in an administrator-owned
   directory, retaining scripts, schemas and canonical configuration together.
   Source ancestors must be root-owned and non-writable by other identities.
   Root execution checks this authority and uses a private bytecode cache.
   Do not transfer credentials or ignored workspace artifacts to the target.
3. If the minimal OS lacks Python input-validation tools, explicitly install
   these public prerequisites through the reviewed Rocky repositories:

   ```sh
   dnf4 -y --releasever=10 --disablerepo='*' \
     --enablerepo=baseos,appstream,extras '--setopt=*.gpgcheck=1' \
     install python3 python3-jsonschema python3-pyyaml
   ```

4. Inspect the public plan using the actual reviewed input paths:

   ```sh
   python3 -I scripts/standard-installation.py --plan \
     --inventory /root/secpal-input/inventory.yaml \
     --firewall /root/secpal-input/host-firewall.json
   ```

5. After target mutation is authorized, run as its administrator:

   ```sh
   python3 -I scripts/standard-installation.py --install \
     --inventory /root/secpal-input/inventory.yaml \
     --firewall /root/secpal-input/host-firewall.json
   ```

6. Repeat that exact installation command. A correctly prepared target reports
   `PUBLIC_BASE_UNCHANGED`. Then verify independently of the installation path:

   ```sh
   python3 -I scripts/standard-installation.py --verify \
     --inventory /root/secpal-input/inventory.yaml \
     --firewall /root/secpal-input/host-firewall.json
   ```

Installation returns zero only after public-base verification.
`PUBLIC_BASE_INSTALLED` and `PUBLIC_BASE_UNCHANGED` describe that bounded result.
Successful public verification reports `PUBLIC_BASE_VERIFIED; NOT_ADMITTED`
with exit status **2**: the host CLI has no independent Enrollment admission
authority. Failure is exit status **1**, with a bounded diagnostic.
A plan is a preview and establishes no host fact.

Only missing public packages are installed. PostgreSQL and HAProxy must match
the existing reviewed pins; conflicting installed pins fail. Correct public
files retain bytes, inode and modification time. Conflicting files, unsafe
ownership, symlinks, existing deployment/data authority, active product services,
foreign firewall/systemd authority, incompatible accounts, subordinate-ID
collisions and enabled automatic updates fail closed. Known secret/data paths
are inspected through metadata; expected public configuration is compared byte
for byte. A partial public-file write is a conflict
requiring administrator review, never a silent replacement.

The runtime home follows #80: root-owned, service primary GID and mode
`0750`. Podman 5.8.2 requires the runtime identity to own its XDG configuration
directory. Its `.config`, `.cache` and `.local` directories are therefore
service-owned, mode `0700`. The installer retains the unchanged root-only
ancestry checks in `Native.directory`, `trusted` and `publish` for administrative
files. It never publishes administrative configuration below these writable
directories.

The sole storage configuration is `/etc/secpal/host-base/storage.conf`, under
root-owned ancestry. A bounded command running as the service identity creates
and verifies the native `.config/containers/storage.conf` symlink to it and the
XDG data directory. It does not introduce another environment/configuration
source. A changed link or ownership is rejected. The runtime identity can
replace its own link but cannot modify the administrative file; every
verification still compares the effective Podman graphroot with the inventory.
The root-owned Quadlet search path and #80 home contract are unchanged.
Existing state is verified without adopting unrelated accounts or workloads.

For the failed `f50333a` bootstrap only, installation recognizes the exact old
root-owned `.config`, `containers` and `systemd` directory metadata, the exact
public storage bytes, and the two existing service-owned `/dev/null` Podman masks.
Unexpected entries, ownership, modes, file types or contents reject the repair
before installation mutations. After preserving and verifying the public
storage bytes at the protected path, the installer removes only that verified
old public file and individually transfers those three directories to the
service UID/GID with mode `0700`. The mask inodes remain unchanged. All root
writes finish before the parent becomes runtime-writable; subsequent XDG writes
run unprivileged. There is no recursive ownership change, data cleanup or OS
reinstallation. Repetition verifies this resulting state without changing it. Reconcile incompatible platforms or foreign
firewall/update policies through existing operator procedures before retrying.
The installer never requests a reboot. The running user manager must expose
exactly the reviewed Quadlet search path through the existing direct
show-environment query. A stale active manager is rejected; a system-level
daemon-reload does not repair its inherited environment. Reconciliation of an
existing manager requires its own operator-controlled procedure.

For the inventory graphroot, native SELinux equivalence uses the installed
container-selinux policy for `/var/lib/containers/storage`. This follows the
[containers/storage labeling procedure](https://github.com/containers/storage/blob/main/docs/containers-storage.conf.5.md#selinux-labeling).
Only an empty, previously unconfigured store receives its initial label.
Existing local file-context rules must match this one managed equivalence;
foreign rules, a populated unadmitted store or label drift require review.
Repeated execution verifies policy and actual labels without relabeling.

## Independent admission through READY_FOR_ENROLLMENT

Installation success cannot grant `READY_FOR_ENROLLMENT`. No CLI flag,
serialized policy JSON, boolean approval, cached ready marker or historical
API/frontend integration digest can confer admission.

`admit_for_enrollment` follows #241's existing trusted readiness callback
convention. It first re-verifies the public base, then requires trusted
native-conformance and OCI-admission callbacks to admit current observations.
Existing trusted control owns these callbacks and must bind the selected
deployment source, exact host and current artifacts. Missing callbacks,
rejected evidence and returned raw decision objects fail. The host CLI
supplies neither callback.

The existing OCI owner must authenticate exact current API/frontend subjects
and the publisher/security decision, including freshness/expiry. Missing,
unknown, expired or `REVIEW_REQUIRED` admission must raise before that owner
returns. This entry point introduces no replacement vulnerability policy,
release manifest, approval file or image selection. It does not pull or run
product images while admission is unavailable.

Remaining native work requires separate target authorization:

- Run existing #80 native host/SELinux/Quadlet qualification with its reviewed,
  pre-staged immutable non-secret probe image and the installed service account.
  Repeat public-base verification afterwards.
- Independently admit actual source-/host-bound observations through the
  existing native owner. Fixtures and target success output cannot grant trust.
- Obtain current exact-subject OCI security admission through the existing
  publisher/policy owner. A preceding image attestation does not establish
  successful final publication acceptance.
- If separately authorized, reboot the isolated fresh host and repeat native
  conformance and public verification. Check nftables restoration, the user
  manager and dormant PostgreSQL/HAProxy/product roles.
- Only subsequent #241 Enrollment may create a fresh Host Identity. #100
  Activation and later data/application materialization remain separate.

The PostgreSQL qualifier creates test database authority and is excluded.
The GCP bootstrap is not invoked.

## Evidence status

`tests/standard-installation.py` exercises real temporary public files with
simulated OS commands: first installation, unchanged repetition, conflicts,
canonical runtime rejection and the independent-admission boundary.
These are source-level regression results.

The first native CX33 run of `f50333a57c49598584fddd7e3039953dade2e6fa`
on freshly installed Rocky 10.2 failed closed at `podman info`: root-owned
`.config` is incompatible with Podman 5.8.2. Plan execution and five native
negative input cases passed; installation and public verification failed.
This evidence establishes the regression, not successful host conformance.

**NOT EXECUTED for this corrected source:** native repair/installation, unchanged
repetition, Podman/systemd/Quadlet acceptance, reboot and terminal
`READY_FOR_ENROLLMENT` admission. Source tests cannot replace those observations.
The bounded non-production
[#248](https://github.com/SecPal/deployment/issues/248) evidence retains its
original scope and does not qualify this corrected path.

Current API/frontend publication acceptance remains an external admission
blocker. This implementation does not assert production readiness.
