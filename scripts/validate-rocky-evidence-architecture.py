#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static architecture gate for Rocky preparation evidence."""

from __future__ import annotations

import argparse
import ast
import json
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
    required_reasons = {
        "command-failed", "observation-failed", "observation-limit-exceeded",
        "representation-invalid", "subject-invalid", "wrong-type",
        "duplicate-observation", "cardinality-invalid", "invariant-failed",
        "internal-error", "postcondition-failed",
    }
    if not required_reasons <= schema_reasons:
        raise ArchitectureError("diagnostic reasons are incomplete")


def enclosing_class(tree: ast.Module, target: ast.AST) -> str | None:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(child is target for child in ast.walk(node)):
            return node.name
    return None


def enclosing_function(tree: ast.Module, target: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            child is target for child in ast.walk(node)
        ):
            return node.name
    return None


def validate_collector(path: Path) -> None:
    tree = parse(path)
    source = path.read_text(encoding="utf-8")
    if not {"observation", "orchestration"} <= responsibility_set(tree):
        raise ArchitectureError("collector responsibility declaration is invalid")
    if "COHERENT_EXTERNAL_CONTRACT = \"rocky-preparation-evidence-v1\"" not in source:
        raise ArchitectureError("collector external domains lack a coherent contract")
    if "{{json .RepoDigests}}" not in source or "{{.Digest}}" in source:
        raise ArchitectureError("fixture observation must use complete RepoDigests membership")
    if "ObservationOperation" not in source:
        raise ArchitectureError("closed observation operation set is absent")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id == "subprocess":
                if enclosing_class(tree, node) != "Observer" or enclosing_function(tree, node) != "run":
                    raise ArchitectureError("opaque observation lacks a closed semantic operation")
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
