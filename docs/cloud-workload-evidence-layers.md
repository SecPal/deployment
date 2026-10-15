<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: MIT
-->

# Current workload evidence layers

The target receives one self-contained streamed file,
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
contract. Purity enforcement for these declared surfaces belongs to #122.
