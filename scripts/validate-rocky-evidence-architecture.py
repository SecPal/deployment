#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static architecture gate for Rocky preparation evidence."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import symtable
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "scripts/ci-cloud/rocky_preparation_contract.py"
DEFAULT_COLLECTOR = ROOT / "scripts/ci-cloud/collect-rocky-preparation.py"
DEFAULT_PREPARATION = ROOT / "scripts/ci-cloud/prepare-rocky-host.sh"
DEFAULT_ISOLATION_CONTRACT = ROOT / "scripts/selinux_isolation_contract.py"
DEFAULT_QUALIFICATION_SCHEMA = (
    ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json"
)
DEFAULT_QUALIFICATION_HARNESS = ROOT / "scripts/qualify-production-host.sh"
DEFAULT_QUALIFICATION_RUNNER = (
    ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh"
)
DEFAULT_ROCKY_CONTROL = ROOT / "scripts/ci-cloud/rocky-control.py"
DEFAULT_WORKFLOW = ROOT / ".github/workflows/rocky-cloud-qualification.yml"
DEFAULT_TARGET_FAILURE_CLASSIFIER = (
    ROOT / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
)
DEFAULT_TARGET_REPLAY_VERIFIER = (
    ROOT / "scripts/ci-cloud/verify-rocky-target-qualification-replay.py"
)
DEFAULT_TARGET_FAILURE_SCHEMA = (
    ROOT / "schemas/rocky-cloud-target-qualification-failure.schema.json"
)
DEFAULT_TARGET_TRACE = ROOT / "scripts/ci-cloud/rocky-target-qualification-trace.sh"
DEFAULT_RELOAD_OBSERVER = (
    ROOT / "scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py"
)
EXPECTED_TARGET_SHA = "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6"
EXPECTED_HARNESS_SHA256 = (
    "269c13090f5065bdc344c3a04b17316939b3cc2d2e2e5b28bd1da8efb9f7272c"
)
HISTORICAL_PRE_269_TARGET_SHA = "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6"
HISTORICAL_PRE_269_HARNESS_SHA256 = (
    "f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"
)
HISTORICAL_PRE_265_TARGET_SHA = "539d5faa6549be62060c8e20028caf200e5eca01"
HISTORICAL_PRE_265_HARNESS_SHA256 = (
    "f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"
)
HISTORICAL_CLEANUP_TARGET_SHA = "293977ae93408a7bb812619de58649ab8a92d438"
EXPECTED_TARGET_LINE_RULES = (
    (456, 462, "qualify-host-identity"),
    (464, 467, "qualify-administrator-execution"),
    (468, 471, "qualify-fixture-reference"),
    (472, 493, "qualify-service-account"),
    (497, 500, "qualify-selinux-host"),
    (502, 515, "qualify-native-architecture"),
    (517, 520, "qualify-cgroup"),
    (521, 537, "qualify-rootless-runtime"),
    (538, 541, "qualify-fixture-presence"),
    (543, 552, "qualify-fixture-setup"),
    (554, 613, "qualify-quadlet-authority"),
    (614, 614, "qualify-quadlet-daemon-reload"),
    (615, 637, "qualify-quadlet-authority"),
    (638, 638, "qualify-quadlet-start"),
    (639, 639, "qualify-quadlet-active-state"),
    (641, 652, "qualify-quadlet-authority"),
    (653, 658, "qualify-workload-primary"),
    (659, 665, "qualify-seccomp"),
    (668, 668, "qualify-selinux-storage-directory-create"),
    (670, 674, "qualify-workload-primary"),
    (675, 678, "qualify-workload-secondary"),
    (680, 686, "qualify-selinux-storage"),
    (690, 696, "qualify-avc-correlation"),
    (700, 706, "qualify-selinux-policy-restoration"),
    (709, 715, "qualify-avc-correlation"),
    (717, 725, "qualify-selinux-policy-restoration"),
    (728, 744, "qualify-avc-correlation"),
    (753, 756, "qualify-runtime-fallback-absence"),
    (758, 758, "qualification-harness"),
)
FAILURE_SCHEMA = ROOT / "schemas/rocky-cloud-preparation-failure-evidence.schema.json"
FORBIDDEN_PURE_IMPORTS = {
    "asyncio", "datetime", "grp", "http", "os", "pathlib", "pwd", "requests",
    "shutil", "socket", "subprocess", "tempfile", "time", "urllib",
}
FORBIDDEN_PURE_CALLS = {"open", "exec", "eval", "compile", "__import__"}
COLLECTOR_FILESYSTEM_CAPABILITIES = {
    "chmod", "exists", "glob", "is_file", "read_bytes", "read_text", "replace",
    "resolve", "unlink", "write_bytes", "write_text",
}
RUNTIME_ADMISSION_OPERATIONS = {
    "admit-runtime-cgroup",
    "admit-runtime-container-host-absence",
    "admit-runtime-network-backend",
    "admit-runtime-oci-runtime",
    "admit-runtime-podman-version",
    "admit-runtime-rootless",
    "admit-runtime-seccomp",
    "admit-runtime-service-locality",
    "admit-runtime-socket-path-absence",
    "admit-runtime-socket-unit-disabled",
    "admit-runtime-systemd-user",
}
RUNTIME_INVARIANT_OWNERS = {
    operation.removeprefix("admit-"): (
        "rocky_preparation_contract." + operation.replace("-", "_")
    )
    for operation in RUNTIME_ADMISSION_OPERATIONS
}


class ArchitectureError(RuntimeError):
    pass


def parse(path: Path) -> ast.Module:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as error:
        raise ArchitectureError(f"cannot parse architecture component: {path}") from error


def assignment_string(tree: ast.Module, name: str) -> str | None:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    return None


def assignment_string_dict(tree: ast.Module, name: str) -> dict[str, str] | None:
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            continue
        if not isinstance(node.value, ast.Dict):
            return None
        pairs: list[tuple[str, str]] = []
        for key, value in zip(node.value.keys, node.value.values, strict=True):
            if (
                not isinstance(key, ast.Constant)
                or not isinstance(key.value, str)
                or not isinstance(value, ast.Constant)
                or not isinstance(value.value, str)
            ):
                return None
            pairs.append((key.value, value.value))
        if len(pairs) != len(dict(pairs)):
            return None
        return dict(pairs)
    return None


def assignment_literal(tree: ast.Module, name: str) -> object:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError) as error:
                raise ArchitectureError(
                    f"architecture constant is not literal: {name}"
                ) from error
    raise ArchitectureError(f"architecture constant is missing: {name}")


def schema_const_pairs(document: object) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(document, dict):
        properties = document.get("properties")
        required = document.get("required")
        if (
            isinstance(properties, dict)
            and isinstance(required, list)
            and all(isinstance(item, str) for item in required)
        ):
            target = properties.get("target_sha")
            harness = properties.get("harness_sha256")
            if (
                {"target_sha", "harness_sha256"} <= set(required)
                and isinstance(target, dict)
                and isinstance(target.get("const"), str)
                and isinstance(harness, dict)
                and isinstance(harness.get("const"), str)
            ):
                pairs.append((target["const"], harness["const"]))
        for value in document.values():
            pairs.extend(schema_const_pairs(value))
    elif isinstance(document, list):
        for value in document:
            pairs.extend(schema_const_pairs(value))
    return pairs


def schema_const_pair_at(document: object, *path: object) -> tuple[str, str] | None:
    """Return one exact required target/harness pair at a closed schema path."""

    node = document
    for component in path:
        if isinstance(component, str) and isinstance(node, dict):
            node = node.get(component)
        elif (
            isinstance(component, int)
            and isinstance(node, list)
            and 0 <= component < len(node)
        ):
            node = node[component]
        else:
            return None
    if not isinstance(node, dict):
        return None
    properties = node.get("properties")
    if not isinstance(properties, dict):
        return None
    target = properties.get("target_sha")
    harness = properties.get("harness_sha256")
    if not isinstance(target, dict) or not isinstance(harness, dict):
        return None
    if not isinstance(target.get("const"), str) or not isinstance(
        harness.get("const"), str
    ):
        return None
    return target["const"], harness["const"]


def validate_pure_contract(path: Path) -> None:
    tree = parse(path)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_PURE_CALLS:
            raise ArchitectureError(f"forbidden pure capability: {node.func.id}")
        elif isinstance(node, ast.Attribute) and node.attr in {"read_text", "read_bytes", "write_text", "write_bytes", "resolve", "exists"}:
            raise ArchitectureError(f"forbidden pure capability: {node.attr}")
    forbidden = sorted(imports & FORBIDDEN_PURE_IMPORTS)
    if forbidden:
        raise ArchitectureError(f"forbidden pure capability import: {','.join(forbidden)}")
    if assignment_string(tree, "RESPONSIBILITY") != "normalization,admission,assembly":
        raise ArchitectureError("pure contract responsibility declaration is invalid")
    source = path.read_text(encoding="utf-8")
    if '"fixture-arm64-child": "rocky_preparation_contract.admit_fixture_identity"' not in source:
        raise ArchitectureError("authoritative fixture invariant owner is absent")
    if '"fixture-amd64-child": "rocky_preparation_contract.admit_fixture_identity"' not in source:
        raise ArchitectureError("authoritative amd64 fixture invariant owner is absent")
    if '"rocky-package-signing-key": "rocky_preparation_contract.admit_rocky_signing_key"' not in source:
        raise ArchitectureError("authoritative package-signing invariant owner is absent")
    if (
        '"authenticated-native-packages": "rocky_preparation_contract.admit_package"'
        not in source
    ):
        raise ArchitectureError(
            "authoritative authenticated-package invariant owner is absent"
        )
    invariant_owners = assignment_string_dict(tree, "INVARIANT_OWNERS")
    if invariant_owners is None or any(
        invariant_owners.get(invariant) != owner
        for invariant, owner in RUNTIME_INVARIANT_OWNERS.items()
    ):
        raise ArchitectureError("authoritative runtime invariant ownership is incomplete")
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    if any(
        isinstance(value, ast.Constant) and value.value == "remoteSocket"
        for function in functions.values()
        for value in ast.walk(function)
    ):
        raise ArchitectureError(
            "Podman remoteSocket information is not authoritative admission input"
        )
    rejection_operations = {
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "reject"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    }
    if (
        "admit-runtime" in rejection_operations
        or not RUNTIME_ADMISSION_OPERATIONS <= rejection_operations
    ):
        raise ArchitectureError("runtime admission semantic boundaries are collapsed")
    runtime_helpers = {
        operation: operation.replace("-", "_")
        for operation in RUNTIME_ADMISSION_OPERATIONS
    }
    runtime_orchestrator = functions.get("admit_runtime")
    if runtime_orchestrator is None:
        raise ArchitectureError("runtime admission orchestrator is absent")
    orchestrator_calls = [
        node.func.id
        for node in ast.walk(runtime_orchestrator)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    if sorted(orchestrator_calls) != sorted(runtime_helpers.values()):
        raise ArchitectureError("runtime admission owners are not exactly reachable")
    for operation, helper_name in runtime_helpers.items():
        helper = functions.get(helper_name)
        if helper is None:
            raise ArchitectureError("runtime admission owner is absent")
        helper_rejections = [
            node.args[1].value
            for node in ast.walk(helper)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "reject"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ]
        if helper_rejections != [operation]:
            raise ArchitectureError("runtime admission owner has an invalid boundary")
    for required in (
        "normalize_observations",
        "admit_facts",
        "assemble_preparation_evidence",
        "normalize_and_admit",
    ):
        if required not in functions:
            raise ArchitectureError("explicit layered responsibility surface is absent")
    admit_facts_calls = [
        node.func.id
        for node in ast.walk(functions["admit_facts"])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    if admit_facts_calls.count("admit_runtime") != 1:
        raise ArchitectureError("runtime admission orchestrator is not reachable")
    for name, node in functions.items():
        calls = {
            call.func.id
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        }
        if name == "normalize_observations" and any(call.startswith("admit_") for call in calls):
            raise ArchitectureError("normalization surface performs admission")
        if name == "admit_facts" and any(call.startswith("normalize_") for call in calls):
            raise ArchitectureError("admission surface performs normalization")
        if name == "assemble_preparation_evidence" and any(
            call.startswith(("normalize_", "admit_")) for call in calls
        ):
            raise ArchitectureError("assembly surface owns semantic processing")
    orchestrator_calls = {
        call.func.id
        for call in ast.walk(functions["normalize_and_admit"])
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    if orchestrator_calls != {
        "normalize_observations",
        "admit_facts",
        "assemble_preparation_evidence",
    }:
        raise ArchitectureError("pure orchestration crosses an undeclared responsibility surface")
    native_orchestrator = functions.get("normalize_and_admit_native_packages")
    if native_orchestrator is None:
        raise ArchitectureError("authenticated native package orchestration is absent")
    native_calls = {
        call.func.id
        for call in ast.walk(native_orchestrator)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    if native_calls != {
        "normalize_native_package_observations",
        "admit_native_package_observations",
    }:
        raise ArchitectureError(
            "authenticated native package boundaries are collapsed"
        )


def responsibility_set(tree: ast.Module) -> set[str]:
    value = assignment_string(tree, "RESPONSIBILITY")
    return set(value.split(",")) if value else set()


def validate_component_complexity(contract_path: Path, collector_path: Path) -> None:
    for path in (contract_path, collector_path):
        responsibilities = responsibility_set(parse(path))
        if {"observation", "normalization", "admission", "assembly"} <= responsibilities:
            raise ArchitectureError("evidence component collapses all semantic responsibilities")
    collector = collector_path.read_text(encoding="utf-8")
    if "INVARIANT_OWNERS" in collector or '"fixture-arm64-child"' in collector or '"fixture-amd64-child"' in collector:
        raise ArchitectureError("duplicate declared invariant ownership")
    if "EXTERNAL_DOMAINS" in collector and "COHERENT_EXTERNAL_CONTRACT" not in collector:
        raise ArchitectureError("multiple external domains lack a reviewed coherent contract")


def validate_diagnostic_contract(contract_path: Path, collector_path: Path) -> None:
    try:
        schema = json.loads(FAILURE_SCHEMA.read_text(encoding="utf-8"))
        diagnostic = schema["properties"]["collection_diagnostic"]["properties"]
        schema_operations = set(diagnostic["operation"]["enum"])
        schema_reasons = set(diagnostic["reason"]["enum"])
        layer_rules = schema["properties"]["collection_diagnostic"]["allOf"]
        reason_groups = schema["properties"]["collection_diagnostic"][
            "x-secpal-operation-reason-groups"
        ]
        layered_operation_list = [
            operation
            for rule in layer_rules
            for operation in rule["if"]["properties"]["operation"]["enum"]
        ]
        layer_operations = set(layered_operation_list)
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ArchitectureError("collection diagnostic schema is unavailable") from error
    collector_tree = parse(collector_path)
    contract_tree = parse(contract_path)
    declared_operations: set[str] = set()
    for node in ast.walk(collector_tree):
        if isinstance(node, ast.ClassDef) and node.name == "ObservationOperation":
            for statement in node.body:
                if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                    declared_operations.add(statement.value.value)
    for node in ast.walk(contract_tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "reject" and len(node.args) >= 2:
            operation = node.args[1]
            if isinstance(operation, ast.Constant) and isinstance(operation.value, str):
                declared_operations.add(operation.value)
    declared_operations.update({"assemble-evidence", "validate-collector-diagnostic"})
    missing = sorted(declared_operations - schema_operations)
    if missing:
        raise ArchitectureError(f"diagnostic operations missing from closed schema: {','.join(missing)}")
    if layer_operations != schema_operations or len(layered_operation_list) != len(layer_operations):
        raise ArchitectureError("every diagnostic operation must have exactly one layer contract")
    reason_operation_list = [
        operation
        for group in reason_groups
        for operation in group["operations"]
    ]
    if (
        set(reason_operation_list) != schema_operations
        or len(reason_operation_list) != len(schema_operations)
        or any(
            not set(group["reasons"]) <= schema_reasons
            for group in reason_groups
        )
    ):
        raise ArchitectureError(
            "every diagnostic operation must have exactly one closed reason contract"
        )
    required_reasons = {
        "command-failed", "observation-failed", "observation-limit-exceeded",
        "representation-invalid", "subject-invalid", "wrong-type",
        "duplicate-observation", "cardinality-invalid", "invariant-failed",
        "internal-error", "postcondition-failed",
    }
    if not required_reasons <= schema_reasons:
        raise ArchitectureError("diagnostic reasons are incomplete")


def enclosing_function(tree: ast.Module, target: ast.AST) -> str | None:
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    current = parents.get(target)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parents.get(current)
    return None


def is_direct_observer_method(tree: ast.Module, target: ast.AST) -> bool:
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    current = parents.get(target)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = parents.get(current)
            return isinstance(owner, ast.ClassDef) and owner.name == "Observer"
        current = parents.get(current)
    return False


def validate_subprocess_scopes(source: str, path: Path) -> None:
    tree = parse(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name == "subprocess" and alias.asname is not None
                for alias in node.names
            ):
                raise ArchitectureError(
                    "opaque observation uses an aliased subprocess import"
                )
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            raise ArchitectureError(
                "opaque observation uses a subprocess from-import"
            )

    try:
        root = symtable.symtable(source, str(path), "exec")
    except SyntaxError as error:
        raise ArchitectureError("cannot build collector scope table") from error

    def table_kind(table: symtable.SymbolTable) -> str:
        kind = table.get_type()
        value = getattr(kind, "value", kind)
        if not isinstance(value, str):
            raise ArchitectureError("unknown Python symbol-table scope kind")
        return value

    def visit(table: symtable.SymbolTable, parent: symtable.SymbolTable | None) -> None:
        if "subprocess" in table.get_identifiers():
            symbol = table.lookup("subprocess")
            if symbol.is_referenced():
                allowed = (
                    table_kind(table) == "function"
                    and table.get_name() == "run"
                    and parent is not None
                    and table_kind(parent) == "class"
                    and parent.get_name() == "Observer"
                )
                if not allowed:
                    raise ArchitectureError(
                        "opaque observation lacks a closed semantic operation"
                    )
        for child in table.get_children():
            visit(child, table)

    visit(root, None)

    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    hidden_scopes = (
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or node.id != "subprocess":
            continue
        if not is_direct_observer_method(tree, node):
            raise ArchitectureError(
                "opaque observation exists outside direct Observer.run scope"
            )
        current = parents.get(node)
        while current is not None and not isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            if isinstance(current, hidden_scopes):
                raise ArchitectureError(
                    "opaque observation exists in a hidden expression scope"
                )
            current = parents.get(current)


def validate_collector(path: Path) -> None:
    tree = parse(path)
    source = path.read_text(encoding="utf-8")
    validate_subprocess_scopes(source, path)
    if not {"observation", "orchestration"} <= responsibility_set(tree):
        raise ArchitectureError("collector responsibility declaration is invalid")
    if "COHERENT_EXTERNAL_CONTRACT = \"rocky-preparation-evidence-v1\"" not in source:
        raise ArchitectureError("collector external domains lack a coherent contract")
    if "{{json .RepoDigests}}" not in source or "{{.Digest}}" in source:
        raise ArchitectureError("fixture observation must use complete RepoDigests membership")
    if "ObservationOperation" not in source:
        raise ArchitectureError("closed observation operation set is absent")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value == "download"
        ):
            raise ArchitectureError(
                "post-install package payload transfer is forbidden"
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in COLLECTOR_FILESYSTEM_CAPABILITIES
            and not is_direct_observer_method(tree, node)
        ):
            if node.func.attr == "resolve" and enclosing_function(tree, node) is None:
                continue
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "observer":
                continue
            raise ArchitectureError(
                "filesystem observation exists outside the Observer owner"
            )
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "contract"
            and node.func.attr.startswith("normalize_")
            and node.func.attr
            not in {"normalize_and_admit", "normalize_and_admit_native_packages"}
        ):
            raise ArchitectureError("collector performs normalization before handoff")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id == "observer":
                if not node.args or not isinstance(node.args[0], ast.Attribute) or not isinstance(node.args[0].value, ast.Name) or node.args[0].value.id != "ObservationOperation":
                    raise ArchitectureError("opaque observation lacks a closed semantic operation")


def validate_preparation(path: Path) -> None:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ArchitectureError("cannot read Rocky preparation script") from error
    marker = 'current_phase="fixture"'
    if marker not in source:
        raise ArchitectureError("fixture preparation boundary is absent")
    fixture = source[source.index(marker):]
    if "--admit-fixture-repo-digests" not in fixture:
        raise ArchitectureError("preparation does not delegate fixture invariant ownership")
    if "jq -e" in fixture or "{{.Digest}}" in fixture:
        raise ArchitectureError("preparation independently redefines fixture identity")


def validate_selinux_isolation_architecture(
    contract_path: Path,
    schema_path: Path,
    harness_path: Path,
    runner_path: Path,
    control_path: Path,
) -> None:
    tree = parse(contract_path)
    source = contract_path.read_text(encoding="utf-8")
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in FORBIDDEN_PURE_CALLS
        ):
            raise ArchitectureError(
                f"forbidden SELinux isolation capability: {node.func.id}"
            )
    forbidden = sorted(imports & (FORBIDDEN_PURE_IMPORTS - {"datetime"}))
    if forbidden:
        raise ArchitectureError(
            "forbidden SELinux isolation capability import: "
            + ",".join(forbidden)
        )
    if assignment_string(tree, "RESPONSIBILITY") != "normalization,admission":
        raise ArchitectureError("SELinux isolation responsibility is invalid")
    owner = "selinux_isolation_contract.admit_selinux_isolation"
    if assignment_string(tree, "INVARIANT_OWNER") != owner:
        raise ArchitectureError("SELinux isolation invariant owner is invalid")
    functions = {
        node.name for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    if not {
        "normalize_context",
        "normalize_context_relationship",
        "normalize_unique_enforcing_avc",
        "admit_selinux_isolation",
        "validate_isolation_evidence",
        "diagnose_avc_correlation_bytes",
        "capture_avc_correlation_diagnostic",
        "validate_avc_correlation_diagnostic",
    } <= functions:
        raise ArchitectureError("SELinux isolation layered surface is incomplete")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema_target = schema["properties"]["target_sha"]["const"]
        native_target = schema["properties"]["native_observation"]["properties"][
            "target_sha"
        ]["const"]
        schema_owner = schema["$defs"]["selinux_isolation"]["properties"][
            "invariant_owner"
        ]["const"]
        maximum = schema["$defs"]["normalized_context"]["properties"][
            "mcs_categories"
        ]["items"]["maximum"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ArchitectureError("SELinux isolation schema projection is invalid") from error
    if (
        schema_target != EXPECTED_TARGET_SHA
        or native_target != EXPECTED_TARGET_SHA
        or schema_owner != owner
        or maximum != 1023
    ):
        raise ArchitectureError("SELinux isolation schema projection disagrees")
    consumers: dict[Path, str] = {}
    for path in (harness_path, runner_path, control_path):
        try:
            consumer = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ArchitectureError("SELinux isolation consumer is unavailable") from error
        if "selinux_isolation_contract" not in consumer:
            raise ArchitectureError("SELinux isolation consumer omits its owner")
        consumers[path] = consumer
    harness = consumers[harness_path]
    runner = consumers[runner_path]
    control = consumers[control_path]
    if (
        "diagnose_avc_correlation_bytes(" not in harness
        or "capture_avc_correlation_diagnostic(" not in harness
        or "publish_avc_correlation_diagnostic() {" not in harness
        or 'SECPAL_AVC_CORRELATION_DIAGNOSTIC_FD:-}" == 6' not in harness
        or 'SECPAL_AVC_CORRELATION_DIAGNOSTIC_FD=6' not in runner
        or '--avc-correlation-diagnostic "$avc_correlation_diagnostic"' not in runner
        or "contract.validate_avc_correlation_diagnostic(projection)" not in control
    ):
        raise ArchitectureError("bounded AVC diagnostic ownership or transport disagrees")
    if (
        "subprocess" in source
        or "pathlib" in source
        or "open(" in source
        or any(clock in source for clock in ("datetime.now", "datetime.utcnow", "datetime.today"))
    ):
        raise ArchitectureError("SELinux isolation owner performs external observation")


def validate_target_qualification_binding(
    workflow_path: Path,
    harness_path: Path,
    runner_path: Path,
    classifier_path: Path,
    replay_verifier_path: Path,
    failure_schema_path: Path,
    trace_path: Path,
    reload_observer_path: Path,
) -> None:
    """Enforce agreement with the workflow-owned current target identity."""

    try:
        workflow = workflow_path.read_text(encoding="utf-8")
        harness = harness_path.read_bytes()
        runner = runner_path.read_text(encoding="utf-8")
        classifier = classifier_path.read_text(encoding="utf-8")
        replay_verifier = replay_verifier_path.read_text(encoding="utf-8")
        failure_schema = json.loads(failure_schema_path.read_text(encoding="utf-8"))
        trace = trace_path.read_text(encoding="utf-8")
        reload_observer = reload_observer_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ArchitectureError(
            "target-qualification binding component is unavailable"
        ) from error

    target_matches = re.findall(
        r"^\s*readonly expected_target_sha=([0-9a-f]{40})$", workflow, re.MULTILINE
    )
    harness_matches = re.findall(
        r"^\s*readonly expected_harness_sha256=([0-9a-f]{64})$",
        workflow,
        re.MULTILINE,
    )
    if len(target_matches) != 1 or len(harness_matches) != 1:
        raise ArchitectureError("workflow must own one exact target/harness pair")
    expected_target = EXPECTED_TARGET_SHA
    expected_harness = EXPECTED_HARNESS_SHA256
    current_target_gate = '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ]]'
    cleanup_target_gate = (
        '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ||\n'
        '                "${RAW_TARGET_SHA,,}" == '
        '"$historical_cleanup_target_sha" ]]'
    )
    if (
        target_matches != [expected_target]
        or harness_matches != [expected_harness]
        or workflow.count(current_target_gate) != 2
        or workflow.count(
            "readonly historical_cleanup_target_sha="
            + HISTORICAL_CLEANUP_TARGET_SHA
        )
        != 1
        or workflow.count(cleanup_target_gate) != 1
        or "sha256sum scripts/qualify-production-host.sh" not in workflow
        or '"$expected_harness_sha256" ]]' not in workflow
        or hashlib.sha256(harness).hexdigest() != expected_harness
    ):
        raise ArchitectureError("workflow target/harness authentication disagrees")

    classifier_tree = parse(classifier_path)
    if (
        assignment_string(classifier_tree, "EXPECTED_TARGET_SHA") != expected_target
        or assignment_string(classifier_tree, "EXPECTED_HARNESS_SHA256")
        != expected_harness
        or assignment_string(classifier_tree, "HISTORICAL_PRE_265_TARGET_SHA")
        != HISTORICAL_PRE_265_TARGET_SHA
        or assignment_string(classifier_tree, "HISTORICAL_PRE_265_HARNESS_SHA256")
        != HISTORICAL_PRE_265_HARNESS_SHA256
        or assignment_string(classifier_tree, "HISTORICAL_PRE_269_TARGET_SHA")
        != HISTORICAL_PRE_269_TARGET_SHA
        or assignment_string(classifier_tree, "HISTORICAL_PRE_269_HARNESS_SHA256")
        != HISTORICAL_PRE_269_HARNESS_SHA256
    ):
        raise ArchitectureError("diagnostic classifier target/harness binding disagrees")

    verifier_tree = parse(replay_verifier_path)
    legacy_replay_control = assignment_string(
        classifier_tree, "LEGACY_REPLAY_OPTIONAL_CONTROL_SHA"
    )
    if (
        legacy_replay_control is None
        or json.dumps(failure_schema).count(legacy_replay_control) != 1
        or "classifier.LEGACY_REPLAY_OPTIONAL_CONTROL_SHA" not in replay_verifier
        or assignment_literal(verifier_tree, "REPLAY_COMPONENT_ORDER")
        != assignment_literal(classifier_tree, "REPLAY_COMPONENT_ORDER")
        or 'replayed = b"\\0".join(' not in replay_verifier
        or 'document["diagnostic_input_sha256"]' not in replay_verifier
        or "classifier.classify_failure(" not in replay_verifier
        or "classifier.replay_line_rules(" not in replay_verifier
        or "require_available=True" not in replay_verifier
        or 'payload.endswith(b"\\n")' not in classifier
        or 'payload[:-1].decode("ascii").split("\\n")' not in classifier
        or "not 1 <= int(match.group(1)) <= 255" not in classifier
        or 'payload.endswith(b"\\n")' not in replay_verifier
        or 'payload[:-1].decode("ascii").split("\\n")' not in replay_verifier
        or "not 1 <= int(match.group(1)) <= 255" not in replay_verifier
        or "object_pairs_hook=unique_json_object" not in classifier
        or "parse_constant=reject_json_constant" not in classifier
        or "object_pairs_hook=unique_json_object" not in replay_verifier
        or "parse_constant=reject_json_constant" not in replay_verifier
        or "replay_start_observation_admitted" not in classifier
        or "replay_active_observation_admitted" not in classifier
        or "replay_primary_observation_admitted" not in classifier
        or "classifier.replay_start_observation_admitted" not in replay_verifier
        or "classifier.replay_active_observation_admitted" not in replay_verifier
        or "classifier.replay_primary_observation_admitted" not in replay_verifier
        or "HISTORICAL_PRE_269_LINE_RULES" not in classifier
    ):
        raise ArchitectureError("closed replay verifier disagrees with classifier input authority")
    if (
        "MAX_AVC_CORRELATION_DIAGNOSTIC_BYTES = 12_288" not in classifier
        or "build_avc_correlation_diagnostic(" not in classifier
        or "contract.validate_avc_correlation_diagnostic(projection)" not in classifier
        or 'projection.get("correlation_outcome") == "admitted"' not in classifier
        or failure_schema.get("properties", {}).get("schema_version", {}).get("enum")
        != [1, 2, 3]
        or "avc_correlation_diagnostic" not in failure_schema.get("properties", {})
    ):
        raise ArchitectureError("bounded AVC failure diagnostic admission disagrees")

    line_rules = assignment_literal(classifier_tree, "LINE_RULES")
    if line_rules != EXPECTED_TARGET_LINE_RULES:
        raise ArchitectureError("current diagnostic line map disagrees")
    reload_line = 614
    if (
        f"10#$frame == {reload_line}" not in trace
        or f"or {reload_line} not in frames" not in reload_observer
    ):
        raise ArchitectureError("daemon-reload diagnostic source mapping disagrees")

    runner_target = f"readonly expected_target_sha={expected_target}"
    runner_harness = f"readonly expected_harness_sha256={expected_harness}"
    pair_gate = '[[ "$target_sha" != "$expected_target_sha" ||'
    if (
        runner_target not in runner
        or runner_harness not in runner
        or pair_gate not in runner
        or '"$qualification_harness_sha256" != "$expected_harness_sha256" ]]'
        not in runner
        or runner.index(pair_gate) >= runner.index("[[ -f /var/lib/secpal-rocky/prepared ]]")
        or runner.index(pair_gate) >= runner.index("getent ahostsv4 github.com")
        or runner.index(pair_gate)
        >= runner.index('bash "$work_root/scripts/qualify-production-host.sh"')
    ):
        raise ArchitectureError("guest target/harness authentication disagrees")

    schema_pair_sequence = [
        schema_const_pair_at(failure_schema, "allOf", 0, "then"),
        schema_const_pair_at(
            failure_schema, "allOf", 0, "if", "anyOf", 1
        ),
        *[
            schema_const_pair_at(
                failure_schema, "allOf", 1, "then", "anyOf", index
            )
            for index in range(3)
        ],
        *[
            schema_const_pair_at(
                failure_schema, "allOf", condition, "if", "anyOf", index
            )
            for condition, length in ((16, 6), (17, 4), (18, 4))
            for index in range(length)
        ],
    ]
    expected_schema_pair_sequence = [
        (expected_target, expected_harness),
        (expected_target, expected_harness),
        (expected_target, expected_harness),
        (HISTORICAL_PRE_269_TARGET_SHA, HISTORICAL_PRE_269_HARNESS_SHA256),
        (HISTORICAL_PRE_265_TARGET_SHA, HISTORICAL_PRE_265_HARNESS_SHA256),
        ("83d0c3720d342d0222e8dee9819e28d0c6739f84", "ba4daa656cc462264c00f830985ad3c346e7ca4db8df9a50e8ee0c7a7d499946"),
        (HISTORICAL_CLEANUP_TARGET_SHA, "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"),
        ("b8f5a505d318d06a64a5975cfaba9f1e5ba0041f", "918c992aad9c937fa2639cd345adc849784344574c44da3d7e3dfeb01bd770fa"),
        (expected_target, expected_harness),
        (HISTORICAL_PRE_269_TARGET_SHA, HISTORICAL_PRE_269_HARNESS_SHA256),
        (HISTORICAL_PRE_265_TARGET_SHA, HISTORICAL_PRE_265_HARNESS_SHA256),
        (HISTORICAL_CLEANUP_TARGET_SHA, "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"),
        (expected_target, expected_harness),
        (HISTORICAL_PRE_269_TARGET_SHA, HISTORICAL_PRE_269_HARNESS_SHA256),
        (HISTORICAL_PRE_265_TARGET_SHA, HISTORICAL_PRE_265_HARNESS_SHA256),
        (HISTORICAL_CLEANUP_TARGET_SHA, "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"),
        (expected_target, expected_harness),
        (HISTORICAL_PRE_269_TARGET_SHA, HISTORICAL_PRE_269_HARNESS_SHA256),
        (HISTORICAL_PRE_265_TARGET_SHA, HISTORICAL_PRE_265_HARNESS_SHA256),
    ]

    if (
        schema_const_pairs(failure_schema).count(
            (expected_target, expected_harness)
        )
        != 5
        or schema_const_pairs(failure_schema).count(
            (HISTORICAL_PRE_269_TARGET_SHA, HISTORICAL_PRE_269_HARNESS_SHA256)
        )
        != 4
        or schema_const_pairs(failure_schema).count(
            (HISTORICAL_PRE_265_TARGET_SHA, HISTORICAL_PRE_265_HARNESS_SHA256)
        )
        != 4
        or schema_pair_sequence != expected_schema_pair_sequence
    ):
        raise ArchitectureError("diagnostic schema target/harness binding disagrees")


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--collector", type=Path, default=DEFAULT_COLLECTOR)
    parser.add_argument("--preparation", type=Path, default=DEFAULT_PREPARATION)
    parser.add_argument(
        "--isolation-contract", type=Path, default=DEFAULT_ISOLATION_CONTRACT
    )
    parser.add_argument(
        "--qualification-schema", type=Path, default=DEFAULT_QUALIFICATION_SCHEMA
    )
    parser.add_argument(
        "--qualification-harness", type=Path, default=DEFAULT_QUALIFICATION_HARNESS
    )
    parser.add_argument(
        "--qualification-runner", type=Path, default=DEFAULT_QUALIFICATION_RUNNER
    )
    parser.add_argument("--rocky-control", type=Path, default=DEFAULT_ROCKY_CONTROL)
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument(
        "--target-failure-classifier",
        type=Path,
        default=DEFAULT_TARGET_FAILURE_CLASSIFIER,
    )
    parser.add_argument(
        "--target-replay-verifier",
        type=Path,
        default=DEFAULT_TARGET_REPLAY_VERIFIER,
    )
    parser.add_argument(
        "--target-failure-schema", type=Path, default=DEFAULT_TARGET_FAILURE_SCHEMA
    )
    parser.add_argument("--target-trace", type=Path, default=DEFAULT_TARGET_TRACE)
    parser.add_argument(
        "--reload-observer", type=Path, default=DEFAULT_RELOAD_OBSERVER
    )
    options = parser.parse_args(arguments)
    try:
        validate_pure_contract(options.contract)
        validate_collector(options.collector)
        validate_preparation(options.preparation)
        validate_component_complexity(options.contract, options.collector)
        validate_diagnostic_contract(options.contract, options.collector)
        validate_selinux_isolation_architecture(
            options.isolation_contract,
            options.qualification_schema,
            options.qualification_harness,
            options.qualification_runner,
            options.rocky_control,
        )
        validate_target_qualification_binding(
            options.workflow,
            options.qualification_harness,
            options.qualification_runner,
            options.target_failure_classifier,
            options.target_replay_verifier,
            options.target_failure_schema,
            options.target_trace,
            options.reload_observer,
        )
    except ArchitectureError as error:
        print(f"ERROR: Rocky evidence architecture rejected: {error}", file=sys.stderr)
        return 1
    print("Rocky evidence architecture validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
