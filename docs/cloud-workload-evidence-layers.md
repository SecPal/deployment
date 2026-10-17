<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: MIT
-->

# Current workload evidence layers

## Operational status

The `rocky-host` qualification in
`.github/workflows/rocky-cloud-qualification.yml` connects the maintained
workload pipeline (#119/#121/#122) after independent host admission. Trusted bootstrap
pins the workload source manifest. Trusted control streams the exact public
components over the existing authenticated SSH transport; the guest verifies
the entire closed set against those bootstrap-owned SHA-256 values before
installing the existing fixture installer and collector. This keeps the
existing metadata size/expansion limits intact. The bounded guest runner
creates a fresh UID/GID 20000 fixture identity with no provider credentials,
checks the current boot/control/run binding, and checks out exactly the existing
frozen target `402c22b0a1d69a5a3dba74ffb68cf016caba606b`. The host harness digest
remains `436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac`.
It does not silently test current main instead. Changing that reviewed pair
requires a separate accepted source change.

The runner collects baseline facts, calls the target's prepare phase without
administrator authority, invokes trusted Quadlet normalization/activation, and
collects live facts. Cleanup, cleanup normalization and post-cleanup observation
are attempted even after failure or interruption. The existing fixture installer
owns bounded administrator publication; target code never receives arbitrary
sudo or cleanup authority. Existing unrelated control resources must survive
workload cleanup. The entire ephemeral guest and its controls are subsequently
removed by the existing exact provider cleanup.

`admit-rocky-workload.py` only unpacks bounded, control/target/run-bound transport
and invokes the existing assembler and independent validator on trusted control.
Those owners enforce purity before module loading and around admission.
Target code cannot supply a grading result. Failed phase/collection statuses
remain failures. Only schema-validated evidence is published; qualification also
requires successful collection and admission. Target output is drained through
the existing closed diagnostic consumer rather than published as raw logs.

Repository tests establish this orchestration contract, not actual provider
execution. #123 remains open until its real create/host/workload/destroy evidence
is accepted. The two reviewed GCP profiles represent two architectures on one
provider; they cannot establish multi-provider portability. GCP remains deferred
under #299/#292. A fresh exact-profile, control/target and budget-bound execution
authorization is required before dispatch. No source merge authorizes that run.

The workload's PostgreSQL 18 is an integration-only disposable fixture, not
host-native production PostgreSQL. Its Caddy gateway is a test fixture.
Standalone Rocky host qualification retains its separate evidence contract.
A workload PASS alone cannot establish host admission, provider cleanup,
production acceptance or multi-provider coverage.

## Component interfaces

The collection interface is one self-contained streamable file,
`scripts/ci-cloud/collect-workload-evidence.py`. Its `COLLECTION_SURFACE` names
operations that observe Podman, systemd, processes, files, namespaces, and
runtime state. `normalize_quadlet_runtime` belongs to this surface: it performs
target-side systemd work despite its historical name. `NORMALIZATION_SURFACE`
names pure conversions of already observed representations. The declarations
are immutable mappings and have executable interface tests. Collection emits
bounded facts and a completeness marker; it does not emit a workload result or
failed-invariant list.

`schemas/ci-cloud-evidence.schema.json` owns structural shape and bounds.
`scripts/ci-cloud/workload-admission.py` owns workload conformance decisions.
Assembly calls that controller module after collection. The independent
validator loads the same module and recomputes the decision from the complete
document. Neither controller path accepts a target-reported workload result.

| Semantic concept               | Authoritative definition                                                                                                      | Consuming boundaries                                                               |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Roles and cardinality          | Collector `ROLES`, `GENERATED_LOGICAL_NAMES`, `ROLE_CONTRACTS`; controller admission evaluates exact census                   | Collector names, schema role/logical-name enums, assembly, validator               |
| Quadlet and generated identity | Collector `expected_unit_names` and `expected_generated_source`                                                               | Collection, named schema definitions, controller admission                         |
| Image identity and provenance  | Canonical integration image contract mirrored by collector `expected_image_identity`; existing image-contract agreement tests | Collection facts, schema digest shape, controller admission                        |
| Networks and bound ports       | Collector `ROLE_CONTRACTS` and `expected_gateway_port`; controller admission evaluates observed names/ports                   | Pure endpoint normalization, schema network/port definitions, controller admission |
| Execution and identity         | Collector `ROLE_CONTRACTS`, service-state and ID-map helpers                                                                  | Collection, normalization, schema container/ID-map facts, controller admission     |
| Mounts and tmpfs               | Collector `ROLE_CONTRACTS`, `expected_role_mounts`, `expected_role_tmpfs`                                                     | Pure mount/tmpfs normalization, schema, controller admission                       |
| Process census                 | Controller `exact_process_map` and the collector's named opaque-executable contract value                                     | Collection facts, named schema process fact/list, controller admission             |
| SELinux and seccomp            | Controller `selinux_labels_match` and current container invariant checks                                                      | Collection facts, schema container shape, controller admission                     |
| Cleanup ownership              | Collector role/network/volume names; controller cleanup inventory evaluation                                                  | Collection, named schema cleanup inventory, controller admission                   |
| Exact target revision          | Workflow target SHA, collector phase binding, controller `WORKLOAD_TARGET_BINDING`                                            | Named schema target SHA, assembly, independent validator                           |

`tests/ci-cloud-workload-layers.py` checks declared exports, schema agreement,
current positive representations, and rejection at the schema, validator, or
admission boundary. The existing workload suite remains the detailed behavior
contract.

## Current workload purity boundary

`workload-purity.py` checks the accepted #121 normalization export and the
frozen admission contract before the controller loads either workload module.
Closed import, imported-member, module-attribute, builtin, and global surfaces
cover the declared pure functions and their reachable local helpers. Python's
`symtable` determines which names are global across nested scopes and
comprehensions. The controller also scopes a Python audit hook to the actual
workload admission call; process, filesystem, network, and other audited system
capabilities produce named workload failures. Evidence reading and summary
writing occur outside that guarded call. Admission receives a private copy of
parsed facts; changing that copy is rejected without altering collected evidence.
Audited violations remain recorded even when admission catches their exception.
The static check runs before preflight imports workload modules. Static mutations
and adversarial controller tests run in repository preflight. The current #121 admission
decisions and workload invariants remain the authority for valid and invalid
evidence; no provider run is part of this purity check.

These controls protect against accidental architectural drift, reachable
impurity, capability growth, and boundary bypasses during normal development.
They are not a Python sandbox, a defense against a hostile committer who can
change both the checker and checked code, or a replacement for code review,
signed commits, and branch protection. PR #74 was a historical design reference
only; its superseded workload assumptions are not part of this contract.

## Independent host qualification

The current workload envelope contains trusted workflow identity, phase and
collection statuses, bounded normalization diagnostics, and independently
admitted workload observations. It does not claim host or production acceptance.
Rocky host qualification uses its existing separate evidence contract.
The retired Debian/APT/AppArmor host envelope and collector are preserved in Git
history rather than required by current workload validation.
