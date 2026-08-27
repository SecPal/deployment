#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static architecture gate for Rocky preparation evidence."""

from __future__ import annotations

import argparse
import ast
import json
import symtable
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "scripts/ci-cloud/rocky_preparation_contract.py"
DEFAULT_COLLECTOR = ROOT / "scripts/ci-cloud/collect-rocky-preparation.py"
DEFAULT_PREPARATION = ROOT / "scripts/ci-cloud/prepare-rocky-host.sh"
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
    if '"rocky-package-signing-key": "rocky_preparation_contract.admit_rocky_signing_key"' not in source:
        raise ArchitectureError("authoritative package-signing invariant owner is absent")
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    for required in (
        "normalize_observations",
        "admit_facts",
        "assemble_preparation_evidence",
        "normalize_and_admit",
    ):
        if required not in functions:
            raise ArchitectureError("explicit layered responsibility surface is absent")
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


def responsibility_set(tree: ast.Module) -> set[str]:
    value = assignment_string(tree, "RESPONSIBILITY")
    return set(value.split(",")) if value else set()


def validate_component_complexity(contract_path: Path, collector_path: Path) -> None:
    for path in (contract_path, collector_path):
        responsibilities = responsibility_set(parse(path))
        if {"observation", "normalization", "admission", "assembly"} <= responsibilities:
            raise ArchitectureError("evidence component collapses all semantic responsibilities")
    collector = collector_path.read_text(encoding="utf-8")
    if "INVARIANT_OWNERS" in collector or '"fixture-arm64-child"' in collector:
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
    for sequence in ast.walk(tree):
        if not isinstance(sequence, (ast.List, ast.Tuple)):
            continue
        arguments = {
            value.value
            for value in ast.walk(sequence)
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        }
        if {"dnf4", "download"} <= arguments:
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
            and node.func.attr != "normalize_and_admit"
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


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--collector", type=Path, default=DEFAULT_COLLECTOR)
    parser.add_argument("--preparation", type=Path, default=DEFAULT_PREPARATION)
    options = parser.parse_args(arguments)
    try:
        validate_pure_contract(options.contract)
        validate_collector(options.collector)
        validate_preparation(options.preparation)
        validate_component_complexity(options.contract, options.collector)
        validate_diagnostic_contract(options.contract, options.collector)
    except ArchitectureError as error:
        print(f"ERROR: Rocky evidence architecture rejected: {error}", file=sys.stderr)
        return 1
    print("Rocky evidence architecture validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
