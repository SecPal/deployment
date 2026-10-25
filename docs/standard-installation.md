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

## Architecture dispatch for this Phase-1 path

The versioned `.secpal/evidence-architecture.json` declares this CLI's reachable,
trusted, fallible operations and the narrowly scoped native #80 qualification
composition described below. It is source material, not an ignored approval
file or persisted PASS. Other cloud, migration, enrollment, activation and
product-workload tools remain outside this dispatch scope.

Run the accepted maintained governance executable against the **actual active
deployment worktree**, followed by the existing repository enforcement:

```sh
python3 -I "$SECPAL_GOVERNANCE_CHECKOUT/scripts/secpal-evidence-architecture.py" \
  --repository-root "$PWD" --repository SecPal/deployment --dispatch
python3 tests/standard-installation.py
python3 tests/native-host-qualification.py
python3 tests/rocky-evidence-architecture.py
scripts/validate-rocky-evidence-architecture.py
```

`SECPAL_GOVERNANCE_CHECKOUT` denotes the existing accepted checkout, not a new
installer or host configuration source. Record its exact commit and executable
identities with the run. Implementation qualification uses shared commit
`744964a0fa7dd6887fe617431f77d52622f0d2c7`, executable blob
`7df49235acd15250609bf2c2d2189dc32cb3480c`.

Standalone `--repository-root` is the supported invocation for this explicit
operator-run CLI. Managed API dispatch additionally requires its actual
maintained managed scope and `--managed-worktree deployment=ABSOLUTE_ACTIVE_WORKTREE`.
Do not invent a scope, substitute another clone, or use self-check/baseline-only
success as dispatch admission. No Polyscope configuration or runtime change
is required for this standalone procedure.

### Completeness, diagnostics and authoritative owners

The inventory includes the existing pre-CLI source-authority guard, named
process operations, filesystem/host-material
boundaries and six reachable #80 RPM-observer operations. Every entry is
reachable, fallible and trusted, with a unique semantic diagnostic.
`tests/standard-installation.py` compares the inventory to actual diagnostic,
run and change calls, traces used RPM-observer methods, and rejects missing
operations, false flags, opaque/duplicate diagnostics, unlisted calls and
unprotected Native methods.

The small diagnostic adapter preserves existing closed security failures and
the RPM observer's operation enum; it redacts foreign exception text.
Filesystem failures identify the inspected/published material. Legacy storage
removal, mode restriction and ownership transfer have distinct identities.
Runtime-user lookup now lies inside the existing command-observation boundary.
The public-base diagnostic adapter does not add package or host mutations.
The bounded native qualification operations below have their own declared scope.

The central expression evaluator cannot execute the real multi-statement
Python owners below. The canonical companion's supported **broader
repository-specific enforcement path** applies. No simplified predicate or
wrapper substitutes for production code. Generic `pure_surfaces` and
`invariant_declarations` are therefore empty; the central report has zero
generic agreement executions. This does not claim an absence of invariants.

| Invariant/role                                    | Existing owner and executable evidence                                                                                                                                                                                                                   |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protected ancestry and single-link public files   | `scripts/host-firewall.py:trusted` owns the invariant; `Native.trusted` independently enforces it. The existing root-path agreement test executes both real functions on the same accepting/rejecting POSIX metadata and asserts each expected decision. |
| Root-owned home and Quadlet search                | `validate-production-contract.py` path/search validators; the existing planned-home agreement and stale-manager tests execute those owners.                                                                                                              |
| OS/RPM, signer, subordinate IDs, rootless runtime | Existing #80 normalization/admission functions are called directly. Existing Rocky architecture validator/suites enforce purity and layer boundaries.                                                                                                    |
| PostgreSQL and DIRECT public rendering            | Existing #81 and #219/#220 renderers; existing equivalence tests bind actual output bytes. Plan composition observes reviewed public source material and is not declared pure.                                                                           |
| Firewall and boot restoration                     | Existing #104 owner and byte-identical helper; existing firewall suites and native read-back remain required.                                                                                                                                            |
| Readiness and OCI admission                       | Existing #241 trusted callbacks; absent/rejected/raw/expired-admission tests remain binding. CLI success cannot supply callbacks.                                                                                                                        |

These metadata agreement cases are representation evidence, not native Podman
acceptance. No `evidence-agreement-results.json` claims unsupported generic
execution. Fresh real agreement tests, repository coverage, canonical dispatch
validation and independent architecture review together qualify the broader
path. Central validation alone can accept an incomplete nonempty inventory;
the repository completeness tests must also pass.

Independent architecture review must confirm scope, semantic grouping, actual
owners, broader-surface enforcement and absence of undeclared or opaque
reachable boundaries. Exact-source security qualification and required CI
remain mandatory. The declaration grants no native, OCI or production admission.

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

## Native #80 qualification on the existing Phase-1 host

Owner #364 composes the existing #80 owners without changing the GCP qualification
target or its control/schema-v4 binding. The harness remains byte-identical:
SHA-256 `436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac`.

Before privileged execution, independently authenticate protected deployment and
control commits, successful required security/contract CI, canonical dispatch
against the actual source, the existing provider resource/Primary IP identities,
both protection flags and the previously authenticated SSH host key. Export only
the exact accepted public source; verify every exported file against that Git
source before executing it. The CLI's SHA arguments record these independently
obtained bindings; they cannot authenticate source or create execution authority.

Run `scripts/qualify-native-host.py` explicitly as the existing administrator,
first with `--stage-fixture`, then with `--qualify`. Both calls require:

- `--inventory` and `--firewall`: the existing public Phase-1 inputs.
- `--source-sha` and `--control-sha`: complete, independently accepted commit IDs.
- `--host-identity hetzner:163717938`: the independently authenticated CX33 resource.
- `--execution-id`: a fresh numeric operator-run identity, recorded before execution
  (for example UTC epoch microseconds); this is **not** a GitHub Actions run ID.
- `--output`: a new file in an existing administrator-owned private evidence directory.

Both modes verify the public base before and after their operation. Staging
pulls only the canonical digest-bound Alpine fixture under `secpal-deploy`,
with an empty public authentication file and certificate directory, TLS
verification and explicit platform. This nonsecret temporary material lives
below trusted `/run` ancestry, traversable by the service account; private
qualification observations instead live below the administrator's protected
evidence directory. Canonical ancestry checks are not relaxed.
The existing `rocky_preparation_contract.admit_fixture_repo_digests` admits the
complete bounded `RepoDigests` set and exact architecture child; singular
`Digest`, tags, registry fallback and arbitrary image selection are absent.
A correctly staged image is verified without another pull. No store contents
are removed. The GCP preparer is never invoked.

Qualification collects current signed-RPM observations through the existing
collector, executes the unchanged harness and uses its existing numeric failure
trace and explicit-message classifier/semantic line mapping. Combined stdout/
stderr stays bounded and private; only closed operation/reason identities are
published on failure. The TERM-first 45-minute deadline allows the existing
cleanup traps 180 seconds before KILL; the outer capture deadline is longer. A root-owned control hook independently observes
the generated Quadlet properties before start, then the actual runtime identity
and workload process status after successful start and before returning to
target assertions. The canonical pre-start authority contract is not applied to
systemd's changed execution timestamps/PID after start. Effective least authority is rechecked by the
existing harness predicate, not a second UID/capability/seccomp policy.
Fresh AVC records are independently re-normalized through
`selinux_isolation_contract.admit_selinux_isolation`; effective Quadlet
properties use `quadlet_authority_contract.admit_quadlet_authority`.
Both the pre-run and post-run qualification resource sets must be empty. The
harness owns exact cleanup; control never prunes or deletes pre-existing state.

Output is `NATIVE_EVIDENCE_COLLECTED; INDEPENDENT_ADMISSION_REQUIRED`, never
readiness. The trusted operator retrieves the observations over the authenticated
SSH channel and executes `qualify-native-host.py:admit_execution` from the
independently accepted control source, supplying **separately obtained** expected
source/control/harness/host/architecture/boot/execution bindings. It must not
derive expected bindings from the returned envelope. The API re-executes the
real SELinux/Quadlet/least-authority owners and
`rocky-control.py:validate_operator_native_qualification` against those
observations. The latter scopes the existing closed v4 schema to the trusted
operator's exact source without changing the historical GCP schema or CLI.
Unknown fields, missing/changed bindings, unsigned RPM facts, conflicting AVC/
Quadlet observations, weakened process state and incomplete cleanup fail closed.

The versioned dispatch inventory includes the actual composition call sites,
reachable package-observer closure and the existing immutable harness semantic
line mapping. `tests/native-host-qualification.py` supplies executable
source/coverage and real-owner positive/negative representation tests, including
first staging and unchanged repetition. The existing broader repository-specific
architecture enforcement route applies; no expression wrapper or stored agreement
PASS is introduced. Independent architecture review remains mandatory.

**Native status for this extension: NOT EXECUTED until its exact source, reviews,
scanner qualification and CI are accepted.** Representation tests are not native
MCS/AVC evidence. API/frontend OCI admission, enrollment, activation and production
acceptance remain separate. No product image is selected or started here.

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
