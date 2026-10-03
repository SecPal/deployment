#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Closed purity contract for the current workload normalization and admission.

This checks reviewed source before loading it. It prevents ordinary capability
drift; it is not a sandbox for code that can edit both this checker and its input.
"""

from __future__ import annotations

import ast
import contextvars
import importlib.util
import symtable
import sys
from pathlib import Path


COLLECTOR = "collect-workload-evidence.py"
ADMISSION = "workload-admission.py"
NORMALIZERS = frozenset({
    "parsed_manager_environment", "normalized_mounts", "parsed_tmpfs_size",
    "normalized_tmpfs", "normalized_command", "parse_id_map",
    "configured_id_maps", "configured_userns_options",
    "normalized_network_address", "normalized_network_endpoints",
    "service_environment_assignments", "normalized_service_environment",
    "normalized_aardvark_addresses",
})
CONTRACT_FUNCTIONS = frozenset({
    "allowed_service_process_groups", "compose_id_maps", "id_map_is_bounded",
    "container_pid_matches_state", "expected_gateway_port",
    "expected_generated_source", "expected_image_identity",
    "expected_role_mounts", "expected_role_tmpfs", "expected_unit_names",
    "service_state_matches_role", "tmpfs_contract_matches",
})
CONTRACT_VALUES = frozenset({
    "API_DIGEST", "BASELINE_OBSERVATION_FIELDS", "CI_GID", "CI_UID",
    "CLEANUP_OBSERVATION_FIELDS", "CONTROL_NETWORK", "CONTROL_VOLUME",
    "FRONTEND_DIGEST", "GENERATED_LOGICAL_NAMES", "GENERATOR_ROOT",
    "HEALTHY_ROLES", "HEALTH_INTERVAL_USEC", "LIVE_OBSERVATION_FIELDS",
    "NETWORK_KINDS", "OPAQUE_PROCESS_EXECUTABLE",
    "PODMAN_54_HEALTH_TIMER_SUFFIX", "PODMAN_NETWORK_ONLINE_UNIT",
    "QUADLET_ROOT", "READY_ROLES", "ROLES", "ROLE_CONTRACTS",
    "SYSTEMD_ROOT", "TRUSTED_CONTAINER_SERVICE_ENVIRONMENT_NAMES",
    "TRUSTED_SERVICE_CONFIG_ENVIRONMENT", "VOLUME_KINDS",
})
CONTRACT = CONTRACT_FUNCTIONS | CONTRACT_VALUES
PURE_BUILTINS = frozenset({
    "all", "any", "bool", "dict", "enumerate", "frozenset", "int",
    "isinstance", "iter", "len", "list", "min", "next", "ord", "set",
    "sorted", "str", "sum", "tuple", "type", "zip",
})
EXCEPTIONS = frozenset({"ValueError", "UnicodeDecodeError", "UnicodeEncodeError"})
COLLECTOR_IMPORTS = frozenset({
    "argparse", "hashlib", "ipaddress", "json", "os", "re", "selectors",
    "shlex", "signal", "stat", "subprocess", "sys", "time",
})
COLLECTOR_FROM = {
    "__future__": frozenset({"annotations"}),
    "pathlib": frozenset({"Path"}),
    "types": frozenset({"MappingProxyType"}),
    "typing": frozenset({"NamedTuple"}),
}
ADMISSION_IMPORTS = frozenset({"importlib.util", "re"})
ADMISSION_FROM = {
    "__future__": frozenset({"annotations"}),
    "collections.abc": frozenset({"Mapping"}),
    "pathlib": frozenset({"Path"}),
    "typing": frozenset({"Any"}),
}
MODULE_ATTRIBUTES = frozenset({
    "re.fullmatch", "re.match", "re.escape", "ipaddress.ip_address",
    "shlex.split",
})
LOAD_CONTRACT_SOURCE = """def load_contract() -> Mapping[str, object]:
    spec = importlib.util.spec_from_file_location('ci_cloud_workload_contract', COLLECTOR_PATH)
    if spec is None or spec.loader is None:
        raise ValueError('workload contract is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ADMISSION_CONTRACT"""
DATA_ATTRIBUTES = frozenset({
    "add", "append", "binds", "capabilities", "casefold", "command",
    "decode", "encode", "endswith", "entrypoint", "extend", "fromkeys",
    "get", "group", "healthcheck", "identity", "isdigit", "issubset",
    "items", "join", "lower", "networks", "removesuffix", "replace",
    "sort", "split", "splitlines", "startswith", "strip", "tmpfs",
    "values", "version", "volumes",
})
COLLECTOR_DATA = frozenset({
    "API_DIGEST", "CI_GID", "CI_UID", "FRONTEND_DIGEST",
    "GENERATED_LOGICAL_NAMES", "NETWORK_KINDS", "POSTGRES_DIGEST",
    "QUADLET_ROOT", "READY_ROLES", "ROLES", "ROLE_CONTRACTS",
    "VOLUME_KINDS", "NetworkAddress", "NetworkEndpoint", "Path",
})


class PurityViolation(ValueError):
    """A bounded named failure of the declared purity contract."""

    def __init__(self, identity: str):
        super().__init__(identity)
        self.identity = identity


def reject(identity: str) -> None:
    raise PurityViolation(identity)


def _imports(tree: ast.Module, collector: bool) -> None:
    modules = COLLECTOR_IMPORTS if collector else ADMISSION_IMPORTS
    members = COLLECTOR_FROM if collector else ADMISSION_FROM
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name not in modules or item.asname:
                    reject("PURITY_UNDECLARED_IMPORT")
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in members:
                reject("PURITY_UNDECLARED_IMPORT")
            for item in node.names:
                if item.name not in members[node.module] or item.asname:
                    reject("PURITY_UNDECLARED_IMPORTED_MEMBER")


def _declared_mapping(tree: ast.Module, name: str) -> dict[str, str]:
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == name
                           for target in node.targets)]
    if len(assignments) != 1 or len(assignments[0].targets) != 1:
        reject("PURITY_CONTRACT_REBIND")
    value = assignments[0].value
    if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
            and value.func.id == "MappingProxyType" and len(value.args) == 1
            and not value.keywords and isinstance(value.args[0], ast.Dict)):
        reject("PURITY_CONTRACT_REBIND")
    result = {}
    for key, item in zip(value.args[0].keys, value.args[0].values):
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)
                and isinstance(item, ast.Name) and key.value == item.id
                and key.value not in result):
            reject("PURITY_CONTRACT_REBIND")
        result[key.value] = item.id
    return result


def _scope_globals(table: symtable.SymbolTable) -> set[str]:
    names = {symbol.get_name() for symbol in table.get_symbols()
             if symbol.is_global() and symbol.is_referenced()}
    for child in table.get_children():
        names.update(_scope_globals(child))
    return names


def _reject_shadowing(table: symtable.SymbolTable, authority: set[str]) -> None:
    for symbol in table.get_symbols():
        if symbol.get_name() in authority and symbol.is_local():
            reject("PURITY_DYNAMIC_CAPABILITY")
    for child in table.get_children():
        _reject_shadowing(child, authority)


def _function_table(module: symtable.SymbolTable, node: ast.FunctionDef):
    matches = [child for child in module.get_children()
               if child.get_name() == node.name and child.get_lineno() == node.lineno]
    if len(matches) != 1:
        reject("PURITY_DYNAMIC_CAPABILITY")
    return matches[0]


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _module_path(node: ast.Attribute) -> str | None:
    pieces = [node.attr]
    value = node.value
    while isinstance(value, ast.Attribute):
        pieces.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        pieces.append(value.id)
        return ".".join(reversed(pieces))
    return None


def _pure_body(node: ast.FunctionDef, globals_used: set[str],
               functions: dict[str, ast.FunctionDef], collector: bool) -> set[str]:
    modules = {"re", "ipaddress", "shlex"} if collector else {"re"}
    data = COLLECTOR_DATA if collector else CONTRACT
    allowed = PURE_BUILTINS | EXCEPTIONS | data | modules | functions.keys()
    if globals_used & {"getattr", "setattr", "delattr", "globals", "locals",
                       "vars", "eval", "exec", "__import__", "compile"}:
        reject("PURITY_DYNAMIC_CAPABILITY")
    if globals_used - allowed:
        reject("PURITY_UNDECLARED_CONTRACT_GLOBAL" if not collector
               else "PURITY_UNDECLARED_NORMALIZATION_GLOBAL")
    if any(isinstance(child, (ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom,
                              ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.YieldFrom))
           for child in ast.walk(node)):
        reject("PURITY_DYNAMIC_CAPABILITY")
    calls = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            path = _module_path(child)
            if path and path.split(".")[0] in modules:
                if path not in MODULE_ATTRIBUTES:
                    reject("PURITY_UNDECLARED_MODULE_ATTRIBUTE")
            elif child.attr not in DATA_ATTRIBUTES:
                reject("PURITY_DYNAMIC_CAPABILITY")
        elif isinstance(child, ast.Call):
            target = child.func
            if isinstance(target, ast.Name):
                if target.id in {"type", "iter"} and (len(child.args) != 1
                                                         or child.keywords):
                    reject("PURITY_DYNAMIC_CAPABILITY")
                if target.id in functions:
                    calls.add(target.id)
                elif target.id not in (PURE_BUILTINS | EXCEPTIONS
                                        | ({"Path", "NetworkAddress", "NetworkEndpoint"}
                                           if collector else CONTRACT_FUNCTIONS)):
                    reject("PURITY_DYNAMIC_CAPABILITY")
            elif not isinstance(target, ast.Attribute):
                reject("PURITY_DYNAMIC_CAPABILITY")
            elif _root_name(target) in modules and _module_path(target) not in MODULE_ATTRIBUTES:
                reject("PURITY_UNDECLARED_MODULE_ATTRIBUTE")
        elif isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            for target in targets:
                if _root_name(target) in globals_used:
                    reject("PURITY_CONTRACT_REBIND")
        elif isinstance(child, ast.NamedExpr) and _root_name(child.target) in globals_used:
            reject("PURITY_CONTRACT_REBIND")
    return calls


def _analyze_reachable(source: str, tree: ast.Module, roots: frozenset[str],
                       collector: bool) -> None:
    table = symtable.symtable(source, COLLECTOR if collector else ADMISSION, "exec")
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    if roots - functions.keys():
        reject("PURITY_REACHABLE_IMPURE_CALLEE")
    visited = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        node = functions[name]
        scope = _function_table(table, node)
        globals_used = _scope_globals(scope)
        _reject_shadowing(scope, set(functions) | set(PURE_BUILTINS)
                          | set(CONTRACT) | {"re", "ipaddress", "shlex", "Path"})
        try:
            calls = _pure_body(node, globals_used, functions, collector)
        except PurityViolation as error:
            if (name not in roots and error.identity in {
                    "PURITY_UNDECLARED_NORMALIZATION_GLOBAL",
                    "PURITY_UNDECLARED_CONTRACT_GLOBAL"}):
                reject("PURITY_REACHABLE_IMPURE_CALLEE")
            raise
        pending.extend(calls - visited)
        # References to local helpers are also authority, even when routed
        # through a comprehension or an alias. Review the callee transitively.
        pending.extend((globals_used & functions.keys()) - visited)


def _module_initialization(tree: ast.Module, collector: bool) -> None:
    """Reject new executable module-level routes before candidate code runs."""
    allowed_calls = {"MappingProxyType", "Path", "RoleContract", "frozenset",
                     "set", "tuple"} if collector else {"Path", "load_contract"}
    allowed_attrs = {"items"} if collector else {"with_name"}
    imported_names = set()
    defined_names = {node.name for node in tree.body
                     if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported_names.update(item.name.split(".")[0] for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported_names.update(item.name for item in node.names)
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef)):
            exprs = node.decorator_list + node.args.defaults if isinstance(node, ast.FunctionDef) else []
        elif isinstance(node, ast.ClassDef):
            if not (len(node.bases) == 1 and isinstance(node.bases[0], ast.Name)
                    and node.bases[0].id == "NamedTuple" and not node.decorator_list
                    and not node.keywords
                    and all((isinstance(member, ast.AnnAssign)
                             and (member.value is None or not any(
                                 isinstance(child, (ast.Call, ast.Attribute))
                                 for child in ast.walk(member.value))))
                            or (isinstance(member, ast.FunctionDef)
                                and not member.decorator_list and not member.args.defaults)
                            for member in node.body)):
                reject("PURITY_IMPORT_SIDE_EFFECT")
            exprs = []
        elif isinstance(node, ast.If):
            if not (isinstance(node.test, ast.Compare)
                    and ast.unparse(node.test) == "__name__ == '__main__'"
                    and not node.orelse):
                reject("PURITY_IMPORT_SIDE_EFFECT")
            continue
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if not isinstance(target, ast.Name) or target.id in (
                            imported_names | defined_names | {"__builtins__", "__loader__",
                                                              "__spec__", "__package__"}):
                        reject("PURITY_IMPORT_SIDE_EFFECT")
            exprs = [node]
        else:
            reject("PURITY_IMPORT_SIDE_EFFECT")
        for expr in exprs:
            for child in ast.walk(expr):
                if isinstance(child, ast.Call):
                    target = child.func
                    if isinstance(target, ast.Name):
                        if target.id not in allowed_calls:
                            reject("PURITY_IMPORT_SIDE_EFFECT")
                    elif not (isinstance(target, ast.Attribute)
                              and target.attr in allowed_attrs):
                        reject("PURITY_IMPORT_SIDE_EFFECT")


def check_sources(collector_source: str, admission_source: str) -> None:
    try:
        collector = ast.parse(collector_source)
        admission = ast.parse(admission_source)
    except SyntaxError:
        reject("PURITY_SOURCE_INVALID")
    _imports(collector, True)
    _imports(admission, False)
    exports = _declared_mapping(collector, "ADMISSION_CONTRACT")
    normalizers = _declared_mapping(collector, "NORMALIZATION_SURFACE")
    if set(exports) != CONTRACT or set(normalizers) != NORMALIZERS:
        reject("PURITY_CONTRACT_REBIND")
    loader = [node for node in admission.body if isinstance(node, ast.FunctionDef)
              and node.name == "load_contract"]
    if len(loader) != 1 or ast.unparse(loader[0]) != LOAD_CONTRACT_SOURCE:
        reject("PURITY_IMPORT_SIDE_EFFECT")
    collector_paths = [node for node in admission.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "COLLECTOR_PATH"
                               for target in node.targets)]
    if (len(collector_paths) != 1 or ast.unparse(collector_paths[0])
            != "COLLECTOR_PATH = Path(__file__).with_name('collect-workload-evidence.py')"):
        reject("PURITY_IMPORT_SIDE_EFFECT")
    contract_loads = [node for node in admission.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "_CONTRACT"
                              for target in node.targets)]
    if (len(contract_loads) != 1 or ast.unparse(contract_loads[0])
            != "_CONTRACT = load_contract()"):
        reject("PURITY_CONTRACT_REBIND")
    _module_initialization(collector, True)
    _module_initialization(admission, False)
    _analyze_reachable(collector_source, collector,
                       NORMALIZERS | CONTRACT_FUNCTIONS, True)
    _analyze_reachable(admission_source, admission,
                       frozenset({"workload_admission_failures"}), False)
    # The admitted contract is a single closed binding block. Later writes,
    # indirect access to a collector module, and fallback lookups are rejected.
    bindings = {}
    for node in admission.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (isinstance(target, ast.Name)
                    and isinstance(node.value, ast.Subscript)
                    and isinstance(node.value.value, ast.Name)
                    and node.value.value.id == "_CONTRACT"
                    and isinstance(node.value.slice, ast.Constant)):
                bindings[target.id] = node.value.slice.value
    if bindings != {name: name for name in CONTRACT}:
        reject("PURITY_UNDECLARED_CONTRACT_GLOBAL")
    for tree, protected in ((collector, CONTRACT_VALUES
                             | {"ADMISSION_CONTRACT", "NORMALIZATION_SURFACE"}),
                            (admission, CONTRACT | {"_CONTRACT", "COLLECTOR_PATH"})):
        counts = {name: 0 for name in protected}
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in counts:
                        counts[target.id] += 1
                    elif _root_name(target) in counts:
                        reject("PURITY_CONTRACT_REBIND")
        if any(count != 1 for count in counts.values()):
            reject("PURITY_CONTRACT_REBIND")
    contract_reads = [node for node in ast.walk(admission) if isinstance(node, ast.Name)
                      and node.id == "_CONTRACT" and isinstance(node.ctx, ast.Load)]
    if len(contract_reads) != len(CONTRACT):
        reject("PURITY_UNDECLARED_CONTRACT_GLOBAL")
    for node in ast.walk(admission):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {"getattr", "setattr", "delattr", "globals", "locals", "vars", "eval", "exec"}):
            reject("PURITY_DYNAMIC_CAPABILITY")


def check_files(directory: Path) -> None:
    try:
        check_sources((directory / COLLECTOR).read_text(encoding="utf-8"),
                      (directory / ADMISSION).read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        reject("PURITY_SOURCE_INVALID")


_active = contextvars.ContextVar("workload_admission_guard", default=False)
_hook_installed = False


def _audit(event: str, _args: tuple[object, ...]) -> None:
    if not _active.get():
        return
    if event.startswith(("subprocess.", "os.system", "os.spawn", "os.posix_spawn",
                         "os.exec", "os.fork", "os.kill")):
        reject("PURITY_RUNTIME_PROCESS")
    if event.startswith(("socket.", "ssl.")):
        reject("PURITY_RUNTIME_NETWORK")
    if event == "open" or event.startswith(("os.listdir", "os.scandir", "os.remove",
                                             "os.rename", "os.mkdir", "os.rmdir",
                                             "os.stat", "os.chmod", "os.chown",
                                             "os.chdir", "os.link", "os.symlink",
                                             "os.truncate", "os.utime", "os.chroot")):
        reject("PURITY_RUNTIME_FILESYSTEM")
    reject("PURITY_RUNTIME_CAPABILITY")


def guarded_decision(admission_module: object, evidence: object) -> list[str]:
    global _hook_installed
    if not _hook_installed:
        sys.addaudithook(_audit)
        _hook_installed = True
    token = _active.set(True)
    try:
        return admission_module.workload_admission_failures(evidence)
    except PurityViolation as error:
        return [error.identity]
    finally:
        _active.reset(token)


def load_checked_admission(directory: Path):
    check_files(directory)
    spec = importlib.util.spec_from_file_location(
        "ci_cloud_checked_workload_admission", directory / ADMISSION
    )
    if spec is None or spec.loader is None:
        reject("PURITY_SOURCE_INVALID")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    try:
        check_files(Path(__file__).resolve().parent)
    except PurityViolation as error:
        print(error.identity, file=sys.stderr)
        raise SystemExit(1) from None
    print("Workload purity contract passed.")
