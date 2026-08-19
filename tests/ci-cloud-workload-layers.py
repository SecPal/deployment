#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Cross-layer contract tests for the D.1a workload evidence boundary.

Each layer of the workload subsystem has its own focused tests: the collector
tests drive collection and representation normalization, and the evidence
tests drive the schema and the independent validator. Those alone cannot prove
that a representation the collector admits also crosses the declared evidence
boundary, which is how a canonical systemd unit name once passed collection
while the schema rejected it.

The tests here close that gap. They take representations produced by the
collection layer itself, carry them through assembly, the JSON Schema, the
independent validator, and admission, and assert the same result at every
layer. They also pin the layer boundary: the collector and the admission
module must share exactly one contract surface, the streamed collector must
stay self-contained, and admission must decide without touching the system.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "scripts" / "ci-cloud" / "collect-workload-evidence.py"
ADMISSION_PATH = ROOT / "scripts" / "ci-cloud" / "workload-admission.py"
ASSEMBLER_PATH = ROOT / "scripts" / "ci-cloud" / "assemble-evidence.py"
VALIDATOR_PATH = ROOT / "scripts" / "ci-cloud" / "validate-evidence.py"
SCHEMA_PATH = ROOT / "schemas" / "ci-cloud-evidence.schema.json"
WORKLOAD_TEST_PATH = ROOT / "tests" / "ci-cloud-workload-evidence.py"
EVIDENCE_TEST_PATH = ROOT / "tests" / "ci-cloud-evidence.py"
STATIC_VALIDATOR_PATH = ROOT / "scripts" / "validate-ci-cloud.py"

INSTANCE = "aaaaaaaaaaaa"
TARGET_SHA = "a" * 40
PHASES = ("baseline", "live", "post_cleanup")
CLEAN_PHASE_STATUSES = {
    "host": 0,
    "workload_prepare_start": 0,
    "workload_cleanup": 0,
    "trusted_quadlet_normalize_live": 0,
    "trusted_quadlet_normalize_cleanup": 0,
}
CLEAN_COLLECTION_STATUSES = {"baseline": 0, "live": 0, "post_cleanup": 0}
# Fields the service binding layer adds to a container fact after inspection.
SERVICE_BOUND_FIELDS = ("container_cgroup", "lifecycle_service_invocation")


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


static_validator = load(STATIC_VALIDATOR_PATH, "ci_cloud_static_validator")
# The builtins that reach a process, a file, or the interpreter without an
# import, and the methods that reach the filesystem through a path object. The
# static trust-boundary validator owns both lists and applies them to the
# admission layer; binding them here keeps the executable proof over the
# normalization layer from drifting away from the rule the validator enforces.
IMPURE_BUILTINS = (
    static_validator.IMPURE_BUILTINS | static_validator.REFLECTIVE_BUILTINS
)
IMPURE_ATTRIBUTES = static_validator.IMPURE_ATTRIBUTES
AMBIGUOUS_PATH_METHODS = static_validator.AMBIGUOUS_PATH_METHODS
PURE_NORMALIZATION_MODULES = static_validator.PURE_NORMALIZATION_MODULES


def file_metadata(uid: int, gid: int, mode: int) -> types.SimpleNamespace:
    """Return the os.stat_result fields the collection layer reads."""
    return types.SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)


def collector_system_access(source: str | None = None) -> dict[str, set[str]]:
    """Map each collector function to the system access it can reach.

    The value is every command, filesystem, or clock primitive the function
    uses itself or through a callee defined in the same file. A primitive is
    reachable through any imported module the normalization layer is not
    allowed to touch, through a method name only a filesystem object carries,
    or through a builtin that needs no import at all, which is why
    IMPURE_BUILTINS is checked as well: a normalization function calling
    ``open`` directly would otherwise be invisible here. A
    method another type shares, such as ``replace``, is judged by arity so
    ``Path.replace(target)`` is caught while ``str.replace(old, new)`` stays
    legal.
    """
    methods = IMPURE_ATTRIBUTES
    tree = ast.parse(
        COLLECTOR_PATH.read_text(encoding="utf-8") if source is None else source
    )
    # Every module the file imports counts, minus the few a normalizer may
    # use. Listing the modules that reach the system instead would have to be
    # completed again for each new import, which is how socket slipped past.
    modules = (
        static_validator.imported_module_aliases(tree) - PURE_NORMALIZATION_MODULES
    )
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }

    def direct(node: ast.AST) -> set[str]:
        found: set[str] = set()
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in IMPURE_BUILTINS
            ):
                found.add(child.func.id)
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr in AMBIGUOUS_PATH_METHODS
                and len(child.args) + len(child.keywords) == 1
            ):
                found.add(f".{child.func.attr}")
            if not isinstance(child, ast.Attribute):
                continue
            if isinstance(child.value, ast.Name) and child.value.id in modules:
                found.add(f"{child.value.id}.{child.attr}")
            elif child.attr in methods:
                found.add(f".{child.attr}")
        return found

    # A module-level alias such as ``reader = bounded_regular_file`` is an
    # ordinary refactoring, and following it matters: an unresolved alias would
    # leave no edge in the graph and report an impure normalizer as clean.
    aliases: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Name)
        ):
            aliases[node.targets[0].id] = node.value.id
    for alias, target in list(aliases.items()):
        seen = {alias}
        while target in aliases and target not in seen:
            seen.add(target)
            target = aliases[target]
        aliases[alias] = target

    def resolved(name: str) -> str:
        return aliases.get(name, name)

    calls = {
        name: {
            resolved(child.func.id)
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and resolved(child.func.id) in functions
        }
        for name, node in functions.items()
    }
    immediate = {name: direct(node) for name, node in functions.items()}

    def reachable(name: str, seen: set[str]) -> set[str]:
        if name in seen:
            return set()
        seen.add(name)
        found = set(immediate[name])
        for callee in calls[name]:
            found |= reachable(callee, seen)
        return found

    return {name: reachable(name, set()) for name in functions}


def host_input() -> dict[str, object]:
    """Return the D.1 host document the assembler consumes."""
    document = evidence_tests.valid_document()
    test = document["test"]
    return {
        "schema_version": 1,
        "workflow": document["workflow"],
        "test": {
            name: test[name]
            for name in (
                "provider",
                "region",
                "profile",
                "machine_type",
                "provider_image",
                "started_at",
                "ended_at",
            )
        }
        | {"failed_admission_invariants": []},
        "platform": document["platform"],
        "apt": document["apt"],
        "host": document["host"],
        "runtime": document["runtime"],
    }


def assembled_document(observations: dict[str, object]) -> dict[str, object]:
    """Assemble evidence exactly as the orchestrator does after a clean run."""
    return assembler.assemble(
        host_input(),
        observations["baseline"],
        observations["live"],
        observations["post_cleanup"],
        workload_tests.valid_normalization_diagnostics(),
        dict(CLEAN_PHASE_STATUSES),
        dict(CLEAN_COLLECTION_STATUSES),
    )


def podman_inspect_representation(fact: dict[str, object]) -> dict[str, object]:
    """Rebuild the Podman 5.4 inspect representation behind a container fact.

    The reviewed fixture records what the collector emits. Rebuilding the
    inspect payload and replaying it through the collection layer proves the
    fixture is the representation Podman 5.4 actually produces rather than a
    hand-written shape that only the later layers ever see.
    """
    tmpfs = {
        str(entry["destination"]): ",".join(
            [
                *[str(flag) for flag in entry["flags"]],
                f"size={entry['size_bytes']}",
                f"mode={entry['mode']}",
                f"uid={entry['uid']}",
                f"gid={entry['gid']}",
            ]
        )
        for entry in fact["tmpfs"]
    }
    mounts = [
        {
            "Type": entry["type"],
            "Name" if entry["type"] == "volume" else "Source": entry["source"],
            "Destination": entry["destination"],
            "RW": entry["rw"],
        }
        for entry in fact["mounts"]
    ]
    networks: dict[str, object] = {}
    for index, network in enumerate(fact["networks"], start=1):
        networks[str(network)] = {
            "IPAddress": f"10.89.{index}.2",
            "IPPrefixLen": 24,
            "SecondaryIPAddresses": [],
            "Gateway": f"10.89.{index}.1",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "SecondaryIPv6Addresses": [],
            "IPv6Gateway": "",
            "NetworkID": f"{index:064x}",
            "Aliases": [fact["role"], str(fact["id"])[:12]],
        }
    ports: dict[str, object] = {}
    for published in fact["published_ports"]:
        host_ip, host_port, container_port = str(published).split(":", 2)
        ports.setdefault(container_port, []).append(
            {"HostIp": host_ip, "HostPort": host_port}
        )
    namespace = fact["user_namespace"]
    state: dict[str, object] = {
        "Status": fact["state"],
        "Pid": fact["pid"],
        "ExitCode": fact["exit_code"],
    }
    if fact["health"] != "none":
        state["Health"] = {"Status": fact["health"]}
    config: dict[str, object] = {
        "Labels": {"PODMAN_SYSTEMD_UNIT": fact["systemd_unit"]},
        "Env": [],
        "Image": fact["image"],
        "User": fact["configured_user"],
        "Entrypoint": list(fact["entrypoint"]),
        "Cmd": list(fact["command"]),
        "CreateCommand": ["/usr/bin/podman", "run"],
    }
    if fact["healthcheck_command"]:
        config["Healthcheck"] = {"Test": list(fact["healthcheck_command"])}
    return {
        "Id": fact["id"],
        "Name": f"/{fact['name']}",
        "State": state,
        "Config": config,
        "HostConfig": {
            "Privileged": fact["privileged"],
            "PidMode": fact["pid_mode"],
            "UsernsMode": namespace["compat_mode"],
            "IpcMode": fact["ipc_mode"],
            "UTSMode": fact["uts_mode"],
            "NetworkMode": fact["network_mode"],
            "SecurityOpt": list(fact["security_opt"]),
            "CapAdd": list(fact["cap_add"]),
            "GroupAdd": list(fact["group_add"]),
            "Devices": [],
            "Tmpfs": tmpfs,
            "ReadonlyRootfs": fact["read_only_rootfs"],
            "Dns": [],
            "IDMappings": {
                "UidMap": [
                    f"{entry['container_id']}:{entry['host_id']}:{entry['size']}"
                    for entry in namespace["configured_uid_map"]
                ],
                "GidMap": [
                    f"{entry['container_id']}:{entry['host_id']}:{entry['size']}"
                    for entry in namespace["configured_gid_map"]
                ],
            },
        },
        "NetworkSettings": {"Networks": networks, "Ports": ports},
        "Mounts": mounts,
        "OCIRuntime": fact["oci_runtime"],
        "EffectiveCaps": list(fact["effective_caps"]),
        "BoundingCaps": list(fact["bounding_caps"]),
        "ImageName": fact["image"],
    }


def collected_namespace(fact: dict[str, object]) -> dict[str, object]:
    """Return the identity facts the collector reads from the live kernel."""
    namespace = dict(fact["user_namespace"])
    for name in (
        "compat_mode",
        "create_options",
        "configured_uid_map",
        "configured_gid_map",
        "podman_uid_map",
        "podman_gid_map",
    ):
        namespace.pop(name)
    return namespace


workload_tests = load(WORKLOAD_TEST_PATH, "ci_cloud_workload_tests")
evidence_tests = load(EVIDENCE_TEST_PATH, "ci_cloud_evidence_tests")
collector = load(COLLECTOR_PATH, "ci_cloud_workload_collector")
admission = load(ADMISSION_PATH, "ci_cloud_workload_admission")
assembler = load(ASSEMBLER_PATH, "ci_cloud_evidence_assembler")
validator = load(VALIDATOR_PATH, "ci_cloud_evidence_validator")
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


class LayerBoundaryTests(unittest.TestCase):
    """Pin the module boundary between collection and admission."""

    def test_one_contract_surface_is_shared_by_collection_and_admission(
        self,
    ) -> None:
        self.assertEqual(
            collector.WORKLOAD_CONTRACT_EXPORTS, admission.CONTRACT_NAMES
        )
        # The loader keeps only the declared members, so an undeclared
        # collector name cannot become a hidden dependency of admission that
        # bypasses the surface these agreement checks cover.
        self.assertEqual(
            set(collector.WORKLOAD_CONTRACT_EXPORTS),
            set(admission.WORKLOAD_CONTRACT),
        )
        for name in ("CHECKOUT", "MAX_OUTPUT", "PODMAN_EXECUTABLE", "main"):
            with self.subTest(undeclared=name):
                self.assertTrue(hasattr(collector, name))
                self.assertNotIn(name, admission.WORKLOAD_CONTRACT)
        for name in collector.WORKLOAD_CONTRACT_EXPORTS:
            with self.subTest(name=name):
                # Admission binds the collector's definition rather than
                # restating the concept, so the two can never drift apart.
                self.assertIs(
                    admission.WORKLOAD_CONTRACT[name],
                    getattr(admission, name),
                )
                self.assertIn(name, dir(collector))

    def test_admission_refuses_a_drifted_contract_surface(self) -> None:
        collector_source = COLLECTOR_PATH.read_text(encoding="utf-8")
        drifts = {
            "renamed": collector_source.replace(
                '    "ROLE_CONTRACTS",\n', '    "ROLE_CONTRACT",\n', 1
            ),
            "dropped": collector_source.replace(
                '    "ROLE_CONTRACTS",\n', "", 1
            ),
            "reordered": collector_source.replace(
                '    "CI_UID",\n    "CI_GID",\n',
                '    "CI_GID",\n    "CI_UID",\n',
                1,
            ),
            "undeclared": collector_source.replace(
                "WORKLOAD_CONTRACT_EXPORTS = (", "UNDECLARED_EXPORTS = (", 1
            ),
        }
        for name, source in drifts.items():
            with self.subTest(drift=name), tempfile.TemporaryDirectory() as raw:
                directory = Path(raw)
                (directory / COLLECTOR_PATH.name).write_text(
                    source, encoding="utf-8"
                )
                (directory / ADMISSION_PATH.name).write_text(
                    ADMISSION_PATH.read_text(encoding="utf-8"), encoding="utf-8"
                )
                self.assertNotEqual(source, collector_source)
                with self.assertRaisesRegex(ValueError, "contract"):
                    load(directory / ADMISSION_PATH.name, f"drift_{name}")

    def test_admission_refuses_an_incomplete_contract(self) -> None:
        collector_source = COLLECTOR_PATH.read_text(encoding="utf-8")
        without_definition = collector_source.replace(
            "\nCI_GID = 20000\n", "\n", 1
        )
        self.assertNotEqual(without_definition, collector_source)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            (directory / COLLECTOR_PATH.name).write_text(
                without_definition, encoding="utf-8"
            )
            (directory / ADMISSION_PATH.name).write_text(
                ADMISSION_PATH.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "incomplete"):
                load(directory / ADMISSION_PATH.name, "incomplete_contract")

    def test_declared_normalization_layer_never_reaches_the_system(
        self,
    ) -> None:
        """Enforce the in-file boundary the streaming constraint forces.

        Normalization cannot become its own module because the collector must
        stay one streamed file, so the boundary is enforced here instead: a
        declared normalization function may not run a command, read the
        filesystem, or read the clock, directly or through any callee.
        """
        reachable = collector_system_access()
        declared = collector.REPRESENTATION_NORMALIZATION_EXPORTS
        self.assertEqual(len(set(declared)), len(declared))
        self.assertEqual(sorted(declared), list(declared))
        for name in declared:
            with self.subTest(name=name):
                self.assertTrue(
                    callable(getattr(collector, name, None)),
                    "declared normalization name is not a function",
                )
                self.assertEqual(
                    set(),
                    reachable[name],
                    "normalization function reaches the system",
                )
        # Negative control: the analysis must still see the collection layer
        # touching the system, otherwise the assertions above prove nothing.
        for name in ("container_facts", "user_work_facts", "installed_unit_facts"):
            with self.subTest(collection=name):
                self.assertTrue(reachable[name])

    def test_normalization_analysis_sees_every_route_to_the_system(self) -> None:
        """Prove the analysis behind the boundary above cannot be evaded.

        A route it cannot see is a boundary that is documented rather than
        enforced, so each way a function can reach the system is replayed
        against the analysis itself: a module attribute, a filesystem method,
        a builtin that needs no import, and any of them through a callee.
        """
        source = "\n".join(
            (
                "import os",
                "import socket",
                "import time",
                "def pure(value):",
                "    return value.strip()",
                "def module_attribute():",
                "    return os.getuid()",
                "def clock():",
                "    return time.monotonic()",
                "def filesystem_method(path):",
                "    return path.read_bytes()",
                "def builtin_open(path):",
                "    return open(path).close()",
                "def builtin_eval(text):",
                "    return eval(text)",
                "def path_replace(path, target):",
                "    return path.replace(target)",
                "def keyword_path_replace(path, destination):",
                "    return path.replace(target=destination)",
                "def reflective(path):",
                "    return getattr(path, 'read_text')()",
                "def string_replace(text):",
                "    return text.replace(':', ' ')",
                "def through_a_callee(path):",
                "    return builtin_open(path)",
                "def network(host):",
                "    return socket.socket()",
                "reader = filesystem_method",
                "def through_an_alias(path):",
                "    return reader(path)",
                "",
            )
        )
        reachable = collector_system_access(source)
        self.assertEqual(set(), reachable["pure"])
        self.assertEqual({"os.getuid"}, reachable["module_attribute"])
        self.assertEqual({"time.monotonic"}, reachable["clock"])
        self.assertEqual({".read_bytes"}, reachable["filesystem_method"])
        self.assertEqual({"socket.socket"}, reachable["network"])
        self.assertEqual({"open"}, reachable["builtin_open"])
        self.assertEqual({"eval"}, reachable["builtin_eval"])
        self.assertEqual({".replace"}, reachable["path_replace"])
        self.assertEqual({".replace"}, reachable["keyword_path_replace"])
        self.assertEqual({"getattr"}, reachable["reflective"])
        self.assertEqual(set(), reachable["string_replace"])
        self.assertEqual({"open"}, reachable["through_a_callee"])
        self.assertEqual({".read_bytes"}, reachable["through_an_alias"])

    def test_importing_the_contract_reaches_nothing(self) -> None:
        """Loading the contract must not run the collector's collection code.

        The controller imports the streamed collector to read its contract, so
        whatever that file runs at module level runs here, before any
        admission decision. Discarding the module afterwards does not undo it,
        so the audit hook is installed before the load rather than after, and
        the only file access it permits is reading the two trusted sources.
        """
        program = f"""
import importlib.util, sys

allowed_reads = {{{str(COLLECTOR_PATH)!r}, {str(ADMISSION_PATH)!r}}}
forbidden = (
    "subprocess.Popen", "os.system", "os.exec", "os.fork", "os.posix_spawn",
    "os.spawn", "os.remove", "os.rename", "os.mkdir", "os.rmdir",
    "socket.socket", "socket.connect", "urllib.Request", "shutil.",
)


def audit(event, arguments):
    if event.startswith(forbidden):
        raise AssertionError(f"loading the contract reached {{event}}")
    if event == "open":
        target = arguments[0]
        cached = "__pycache__" in str(target) and str(target).endswith(".pyc")
        if isinstance(target, str) and target not in allowed_reads and not cached:
            raise AssertionError(f"loading the contract opened {{target}}")


sys.addaudithook(audit)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


admission = load({str(ADMISSION_PATH)!r}, "workload_admission")
assert admission.WORKLOAD_CONTRACT
print("loaded", len(admission.WORKLOAD_CONTRACT))
"""
        result = subprocess.run(
            [sys.executable, "-I", "-"],
            input=program.encode(),
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            f"loaded {len(collector.WORKLOAD_CONTRACT_EXPORTS)}".encode(),
            result.stdout,
        )

    def test_contract_mapping_matches_the_declared_surface(self) -> None:
        contract = collector.workload_contract()
        self.assertEqual(
            list(collector.WORKLOAD_CONTRACT_EXPORTS), list(contract)
        )
        for name, value in contract.items():
            with self.subTest(name=name):
                self.assertIs(getattr(collector, name), value)

    def test_streamed_collector_runs_without_repository_modules(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = subprocess.run(
                [sys.executable, "-I", "-", "baseline", TARGET_SHA, INSTANCE],
                input=COLLECTOR_PATH.read_bytes(),
                capture_output=True,
                cwd=raw,
                timeout=120,
            )
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn(b"workload collection refused", result.stderr)
        self.assertEqual(b"", result.stdout)

    def test_admission_decides_without_touching_the_system(self) -> None:
        program = f"""
import importlib.util, json, sys
from pathlib import Path


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tests = load({str(WORKLOAD_TEST_PATH)!r}, "workload_tests")
admission = load({str(ADMISSION_PATH)!r}, "workload_admission")
observations = tests.valid_observations()
forbidden = (
    "subprocess.Popen", "os.system", "os.exec", "os.fork", "os.posix_spawn",
    "open", "socket.socket", "socket.connect", "urllib.Request",
)


def audit(event, _arguments):
    if event.startswith(forbidden):
        raise AssertionError(f"admission reached the system through {{event}}")


sys.addaudithook(audit)
json.dump(admission.workload_admission_failures(observations), sys.stdout)
"""
        result = subprocess.run(
            [sys.executable, "-I", "-"],
            input=program.encode(),
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], json.loads(result.stdout))

    def test_collection_holds_no_admission_decision(self) -> None:
        self.assertFalse(hasattr(collector, "workload_admission_failures"))
        self.assertNotIn(
            "D1A_", COLLECTOR_PATH.read_text(encoding="utf-8")
        )
        self.assertTrue(
            all(
                failure.startswith("D1A_")
                for failure in admission.workload_admission_failures(
                    {"protocol_version": 1}
                )
            )
        )


class CrossLayerEvidenceTests(unittest.TestCase):
    """Carry collector-produced representations across every later layer."""

    def assert_admitted(self, observations: dict[str, object]) -> None:
        document = assembled_document(observations)
        jsonschema.Draft202012Validator(SCHEMA).validate(document)
        self.assertEqual(document, validator.validate_document(document))
        self.assertEqual([], document["workload"]["failed_admission_invariants"])
        self.assertEqual("passed", document["workload"]["result"])

    def assert_refused(self, observations: dict[str, object]) -> None:
        """Assert the representation fails closed at its earliest boundary.

        A representation the closed schema cannot express is refused there and
        never reaches admission, so the independent validator rejects the whole
        document. A representation the schema can express but the contract
        forbids is refused by admission, and independent revalidation must
        recompute the same failed result rather than quietly passing it.
        """
        document = assembled_document(observations)
        schema_errors = list(
            jsonschema.Draft202012Validator(SCHEMA).iter_errors(document)
        )
        admission_failures = document["workload"]["failed_admission_invariants"]
        self.assertTrue(
            schema_errors or admission_failures,
            "neither the schema nor admission refused the representation",
        )
        if schema_errors:
            with self.assertRaises(ValueError):
                validator.validate_document(document)
            return
        self.assertEqual("failed", document["workload"]["result"])
        self.assertEqual(document, validator.validate_document(document))

    def test_reviewed_evidence_crosses_every_layer(self) -> None:
        self.assert_admitted(workload_tests.valid_observations())

    def test_canonical_systemd_names_have_one_agreed_definition(self) -> None:
        """The collector predicate and the schema definition must agree."""
        names = (
            "postgresql.service",
            "dev-disk-by\\x2ddiskseq-1.device",
            "secpal\\x2dmaintenance.service",
            "getty@tty1.service",
            "run-user-20000.mount",
            "machine.slice",
            "a:b_c.d-e@f.socket",
            "a" * 128,
            "a" * 129,
            "",
            "dev-disk-by\\xZZescape.device",
            "dev-disk-by\\x2Descape.device",
            "dev-disk-by\\escape.device",
            "dev-disk-by\\x2.device",
            "unit name.service",
            "unit/name.service",
            "unit\nname.service",
            "unit\tname.service",
            "unit\x7fname.service",
            "unit\u2028name.service",
            "unit\u2029name.service",
            "unit\x00name.service",
            "\\x2d",
            "unité.service",
        )
        definition = jsonschema.Draft202012Validator(
            SCHEMA["$defs"]["canonicalSystemdUnitName"]
        )
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(
                    collector.canonical_systemd_unit_name(name),
                    definition.is_valid(name),
                )
        self.assertTrue(
            collector.canonical_systemd_unit_name(
                "dev-disk-by\\x2ddiskseq-1.device"
            )
        )
        self.assertFalse(collector.canonical_systemd_unit_name(b"unit.service"))

    def test_collector_admitted_unit_names_cross_the_schema_boundary(
        self,
    ) -> None:
        escaped_unit = "dev-disk-by\\x2ddiskseq-1.device"
        escaped_job = "secpal\\x2dmaintenance.service"

        def command_result(arguments, **_kwargs):
            if "list-units" in arguments:
                return 0, f"{escaped_unit} loaded active plugged\n", True
            if "list-jobs" in arguments:
                return 0, f"1 {escaped_job} start running\n", True
            return 0, "", True

        with mock.patch.object(
            collector, "command_result", side_effect=command_result
        ):
            facts, complete = collector.user_work_facts()
        self.assertTrue(complete)
        self.assertEqual([escaped_unit], facts["active_units"])

        observations = workload_tests.valid_observations()
        for phase in PHASES:
            user_work = observations[phase]["user_work"]
            user_work["active_units"].extend(facts["active_units"])
            user_work["jobs"].extend(facts["jobs"])
        self.assert_admitted(observations)

    def test_reviewed_health_timer_representation_crosses_every_layer(
        self,
    ) -> None:
        """Replay the reviewed transient Podman 5.4 health units.

        The timers are transient systemd units Podman 5.4 creates for a
        healthchecked container. Replaying the systemd representation through
        the collection layer proves the reviewed evidence is what a target
        actually reports, and that admission still binds each timer to an
        observed healthy container rather than to its name.
        """
        observations = workload_tests.valid_observations()
        reviewed = observations["live"]["user_work"]
        timers = {
            str(timer["timer"]): timer
            for timer in reviewed["podman_health_timers"]
        }
        healthcheck_probes = []

        def command_result(arguments, **_kwargs):
            if "list-units" in arguments:
                return (
                    0,
                    "".join(
                        f"{unit} loaded active waiting\n"
                        for unit in reviewed["active_units"]
                    ),
                    True,
                )
            if "list-jobs" in arguments:
                return 0, "", True
            if arguments[:4] == [
                "systemctl",
                "--user",
                "show",
                collector.PODMAN_NETWORK_ONLINE_UNIT,
            ]:
                return (
                    0,
                    f"FragmentPath={collector.PODMAN_NETWORK_ONLINE_FRAGMENT}\n"
                    "DropInPaths=",
                    True,
                )
            if arguments[:3] == ["systemctl", "--user", "show"]:
                name = arguments[3]
                timer = timers.get(name) or timers[f"{name[:-8]}.timer"]
                seconds = int(timer["interval_usec"]) // 1_000_000
                if name.endswith(".timer"):
                    properties = {
                        "FragmentPath": (
                            f"/run/user/20000/systemd/transient/{name}"
                        ),
                        "DropInPaths": "",
                        "Transient": "yes",
                        "Triggers": str(timer["service"]),
                        "AccuracyUSec": "1s",
                        "TimersMonotonic": (
                            f"{{ OnUnitInactiveUSec={seconds}s ; "
                            f"next_elapse={seconds}s }}"
                        ),
                    }
                else:
                    properties = {
                        "FragmentPath": (
                            f"/run/user/20000/systemd/transient/{name}"
                        ),
                        "DropInPaths": "",
                        "Transient": "yes",
                        "Environment": next(
                            item
                            for item in collector.TRUSTED_MANAGER_ENVIRONMENT
                            if item.startswith("PATH=")
                        ),
                        "ExecCondition": "",
                        "ExecStartPre": "",
                        "ExecStart": (
                            "{ path=/usr/bin/podman ; "
                            "argv[]=/usr/bin/podman healthcheck run "
                            f"{timer['container_id']} ; ignore_errors=no ; "
                            "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
                            "code=(null) ; status=0/0 }"
                        ),
                        "ExecStartPost": "",
                        "ExecReload": "",
                        "ExecStop": "",
                        "ExecStopPost": "",
                    }
                return (
                    0,
                    "\n".join(
                        f"{name}={value}" for name, value in properties.items()
                    ),
                    True,
                )
            if arguments[:3] == ["/usr/bin/podman", "healthcheck", "run"]:
                healthcheck_probes.append(arguments[3])
                return 0, "", True
            raise AssertionError(f"unexpected command: {arguments}")

        with mock.patch.object(
            collector, "command_result", side_effect=command_result
        ):
            facts, complete = collector.user_work_facts()
        self.assertTrue(complete)
        self.assertEqual(reviewed, facts)
        self.assertEqual(
            sorted(str(timer["container_id"]) for timer in timers.values()),
            sorted(healthcheck_probes),
        )

        observations["live"]["user_work"] = facts
        self.assert_admitted(observations)

    def test_unit_names_the_collector_refuses_never_reach_evidence(
        self,
    ) -> None:
        malformed = (
            "dev-disk-by\\xZZescape.device",
            "dev-disk-by\\x2Descape.device",
            "dev-disk-by\\escape.device",
        )
        for name in malformed:
            with self.subTest(name=name):

                def command_result(arguments, **_kwargs):
                    if "list-units" in arguments:
                        return 0, f"{name} loaded active plugged\n", True
                    return 0, "", True

                with mock.patch.object(
                    collector, "command_result", side_effect=command_result
                ):
                    _, complete = collector.user_work_facts()
                self.assertFalse(complete)

                observations = workload_tests.valid_observations()
                for phase in PHASES:
                    observations[phase]["user_work"]["active_units"].append(name)
                self.assert_refused(observations)

    def test_quadlet_unit_file_names_have_one_agreed_definition(self) -> None:
        """Installed units and cleanup leftovers name the same concept.

        Both are file names the trusted installer writes under the root-owned
        Quadlet and systemd roots, so the schema states the rule once. A
        leftover the collector can report but the installer could never have
        written is refused at the schema boundary rather than described as a
        merely failed cleanup.
        """
        definition = jsonschema.Draft202012Validator(
            SCHEMA["$defs"]["quadletUnitFileName"]
        )
        reference = {"$ref": "#/$defs/quadletUnitFileName"}
        self.assertEqual(
            reference, SCHEMA["$defs"]["unitFact"]["properties"]["name"]
        )
        self.assertEqual(
            reference,
            SCHEMA["$defs"]["cleanupObservation"]["properties"]["owned_units"][
                "items"
            ],
        )
        collected = collector.expected_unit_names(INSTANCE)
        self.assertEqual(16, len(collected))
        for name in collected:
            with self.subTest(name=name):
                self.assertTrue(definition.is_valid(name))
        for name in (
            f"secpal-int-{INSTANCE}-evil.sh",
            f"secpal-int-{INSTANCE}-api.service",
            f"secpal-int-{INSTANCE}-API.container",
            f"secpal-int-{INSTANCE}.target.bak",
            "unrelated.container",
            "",
        ):
            with self.subTest(name=name):
                self.assertFalse(definition.is_valid(name))

        # A leftover the installer could never have written fails closed at
        # the schema, while a well-formed leftover still fails admission.
        for leftover, refused_by_schema in (
            (f"secpal-int-{INSTANCE}-evil.sh", True),
            (f"secpal-int-{INSTANCE}-api.container", False),
        ):
            with self.subTest(leftover=leftover):
                observations = workload_tests.valid_observations()
                observations["post_cleanup"]["owned_units"].append(leftover)
                document = assembled_document(copy.deepcopy(observations))
                errors = list(
                    jsonschema.Draft202012Validator(SCHEMA).iter_errors(document)
                )
                self.assertEqual(refused_by_schema, bool(errors))
                self.assert_refused(observations)

    def test_generated_service_names_have_one_agreed_definition(self) -> None:
        """The generated service name is one concept with one schema home.

        A Quadlet generator turns each reviewed unit into a systemd service,
        and both the generated service fact and the container fact that names
        its own service describe the same string. Stating the rule once keeps
        the two from drifting the way the canonical unit name once did.
        """
        definition = jsonschema.Draft202012Validator(
            SCHEMA["$defs"]["generatedServiceName"]
        )
        reference = {"$ref": "#/$defs/generatedServiceName"}
        self.assertEqual(
            reference,
            SCHEMA["$defs"]["generatedServiceFact"]["properties"]["unit"],
        )
        self.assertEqual(
            reference,
            SCHEMA["$defs"]["containerFact"]["properties"]["systemd_unit"],
        )
        observations = workload_tests.valid_observations()
        produced = [
            str(service["unit"])
            for service in observations["live"]["generated_services"]
        ] + [
            str(container["systemd_unit"])
            for container in observations["live"]["containers"]
        ]
        self.assertTrue(produced)
        for name in produced:
            with self.subTest(name=name):
                self.assertTrue(definition.is_valid(name))
        for name in (
            f"secpal-int-{INSTANCE}-api.container",
            f"secpal-int-{INSTANCE}.service",
            f"secpal-int-{INSTANCE}-API.service",
            "unrelated.service",
            "",
        ):
            with self.subTest(name=name):
                self.assertFalse(definition.is_valid(name))

    def test_reviewed_installed_unit_representation_crosses_every_layer(
        self,
    ) -> None:
        """Replay the root-owned Quadlet unit files behind the evidence."""
        observations = workload_tests.valid_observations()
        reviewed = observations["live"]["installed_units"]
        contents = {
            str(unit["path"]): f"# {unit['name']}\n".encode()
            for unit in reviewed
        }

        def bounded_regular_file(path):
            content = contents.get(str(path))
            if content is None:
                return None
            return content, file_metadata(0, 0, 0o100644)

        with mock.patch.object(
            collector, "bounded_regular_file", side_effect=bounded_regular_file
        ), mock.patch.object(
            collector.Path,
            "iterdir",
            autospec=True,
            side_effect=lambda root: [
                Path(path)
                for path in contents
                if Path(path).parent == root
            ],
        ):
            facts, complete = collector.installed_unit_facts(INSTANCE)
        self.assertTrue(complete)
        expected = [
            unit
            | {
                "sha256": hashlib.sha256(
                    contents[str(unit["path"])]
                ).hexdigest()
            }
            for unit in reviewed
        ]
        self.assertEqual(expected, facts)

        observations["live"]["installed_units"] = facts
        self.assert_admitted(observations)

    def test_reviewed_generated_service_representation_crosses_every_layer(
        self,
    ) -> None:
        """Replay the systemd generator representation behind the evidence.

        ``generated_file_fact`` reads fragment ownership and hashes it; that
        reader has its own coverage, so it is stubbed with the reviewed
        metadata here. The representation under test is the exact
        ``systemctl --user show`` output the collection layer parses.
        """
        observations = workload_tests.valid_observations()
        reviewed = {
            str(service["logical_name"]): service
            for service in observations["live"]["generated_services"]
        }
        metadata = {
            str(service["fragment_path"]): (
                service["fragment_uid"],
                service["fragment_gid"],
                service["fragment_mode"],
                service["fragment_sha256"],
            )
            for service in reviewed.values()
        }

        def command_result(arguments, **_kwargs):
            unit = arguments[3]
            logical_name = unit.removeprefix(
                f"secpal-int-{INSTANCE}-"
            ).removesuffix(".service")
            service = reviewed[logical_name]
            if logical_name in collector.ROLES:
                operation, stop = "run", "rm"
            elif logical_name.endswith("-network"):
                operation, stop = "network create", None
            else:
                operation, stop = "volume create", None
            properties = {
                "FragmentPath": service["fragment_path"],
                "DropInPaths": " ".join(service["drop_in_paths"]),
                "ActiveState": service["active_state"],
                "SubState": service["sub_state"],
                "Result": service["result"],
                "ExecMainStatus": str(service["exec_main_status"]),
                "MainPID": str(service["main_pid"]),
                "ControlGroup": service["control_group"],
                "InvocationID": service["invocation_id"],
                "SourcePath": service["source_path"],
                "Environment": workload_tests.trusted_service_environment(
                    logical_name
                ),
                "PassEnvironment": "",
                "UnsetEnvironment": "",
                "ExecStart": (
                    "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman "
                    f"{operation} ; }}"
                ),
            }
            if stop is not None:
                lifecycle = (
                    "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman "
                    f"{stop} ; }}"
                )
                properties["ExecStop"] = lifecycle
                properties["ExecStopPost"] = lifecycle
            return (
                0,
                "".join(f"{name}={value}\n" for name, value in properties.items()),
                True,
            )

        with mock.patch.object(
            collector, "command_result", side_effect=command_result
        ), mock.patch.object(
            collector,
            "generated_file_fact",
            side_effect=lambda path: metadata.get(str(path)),
        ), mock.patch.object(
            collector,
            "quadlet_source_execution_controls_are_trusted",
            return_value=True,
        ):
            facts, complete = collector.generated_service_facts(INSTANCE)
        self.assertTrue(complete)
        self.assertEqual(list(reviewed.values()), facts)

        observations["live"]["generated_services"] = facts
        self.assert_admitted(observations)

    def test_reviewed_process_census_representation_crosses_every_layer(
        self,
    ) -> None:
        """Replay the procfs representation behind the process census."""
        observations = workload_tests.valid_observations()
        reviewed = observations["live"]["processes"]
        own_group = "/user.slice/user-20000.slice/user@20000.service/collector"
        pids = {2_000 + index: fact for index, fact in enumerate(reviewed)}
        groups = {os.getpid(): own_group} | {
            pid: str(fact["control_group"]) for pid, fact in pids.items()
        }
        executables = {
            pid: str(fact["executable"]) for pid, fact in pids.items()
        }

        def readlink(path):
            return executables[int(Path(path).parent.name)]

        with mock.patch.object(
            collector.Path,
            "iterdir",
            autospec=True,
            side_effect=lambda root: [root / str(pid) for pid in pids],
        ), mock.patch.object(
            collector,
            "process_control_group",
            side_effect=lambda pid: (groups[pid], True),
        ), mock.patch.object(
            collector,
            "process_host_identity",
            side_effect=lambda pid: (
                int(pids[pid]["uid"]),
                int(pids[pid]["gid"]),
                True,
            ),
        ), mock.patch.object(
            collector.os, "readlink", side_effect=readlink
        ), mock.patch.object(
            collector, "podman_helper_process_is_bound", return_value=True
        ):
            facts, complete = collector.user_process_facts()
        self.assertTrue(complete)
        self.assertEqual(reviewed, facts)

        observations["live"]["processes"] = facts
        self.assert_admitted(observations)

    def test_reviewed_resource_inventory_crosses_every_layer(self) -> None:
        """Replay the Podman listing representation behind the inventory."""
        observations = workload_tests.valid_observations()
        live = observations["live"]
        listings = {
            ("podman", "ps"): live["all_containers"],
            ("podman", "network"): live["all_networks"],
            ("podman", "volume"): live["all_volumes"],
        }

        def json_array(arguments, **_kwargs):
            names = listings[(arguments[0], arguments[1])]
            return [{"Names": [name]} for name in names], True

        with mock.patch.object(
            collector, "json_array", side_effect=json_array
        ):
            inventory, complete = collector.resource_inventory()
        self.assertTrue(complete)
        self.assertEqual(
            {
                "containers": live["all_containers"],
                "networks": live["all_networks"],
                "volumes": live["all_volumes"],
            },
            inventory,
        )

        live["all_containers"] = inventory["containers"]
        live["all_networks"] = inventory["networks"]
        live["all_volumes"] = inventory["volumes"]
        self.assert_admitted(observations)

    def test_reviewed_podman_representations_cross_every_layer(self) -> None:
        observations = workload_tests.valid_observations()
        reviewed = observations["live"]["containers"]
        inspections = [
            podman_inspect_representation(fact) for fact in reviewed
        ]
        namespaces = {
            str(fact["id"]): collected_namespace(fact) for fact in reviewed
        }
        identities = {
            fact["pid"]: (
                namespaces[str(fact["id"])],
                fact["effective_uid"],
                fact["effective_gid"],
                fact["effective_supplementary_gids"],
                True,
            )
            for fact in reviewed
            if fact["state"] == "running"
        }
        exited = next(fact for fact in reviewed if fact["state"] != "running")
        events = {
            str(fact["id"]): (fact["lifecycle_events"], True)
            for fact in reviewed
        }
        first = reviewed[0]
        with mock.patch.object(
            collector,
            "names_from_listing",
            return_value=([str(fact["name"]) for fact in reviewed], True),
        ), mock.patch.object(
            collector, "json_array", return_value=(inspections, True)
        ), mock.patch.object(
            collector,
            "container_lifecycle_events",
            side_effect=lambda identifier: events[identifier],
        ), mock.patch.object(
            collector,
            "effective_user_namespace_facts",
            side_effect=lambda pid: identities[pid],
        ), mock.patch.object(
            collector,
            "collector_user_namespace_facts",
            return_value=(collected_namespace(exited), True),
        ):
            collected = collector.container_facts(
                INSTANCE,
                rootless=True,
                podman_uid_map=first["user_namespace"]["podman_uid_map"],
                podman_gid_map=first["user_namespace"]["podman_gid_map"],
            )
        self.assertTrue(collected.complete)
        expected = [
            {
                name: value
                for name, value in fact.items()
                if name not in SERVICE_BOUND_FIELDS
            }
            for fact in sorted(reviewed, key=lambda fact: str(fact["role"]))
        ]
        self.assertEqual(expected, collected.facts)

        produced = {str(fact["id"]): fact for fact in collected.facts}
        observations["live"]["containers"] = [
            produced[str(fact["id"])]
            | {name: fact[name] for name in SERVICE_BOUND_FIELDS}
            for fact in reviewed
        ]
        self.assert_admitted(observations)

    def test_transient_health_timers_are_not_admitted_from_names_alone(
        self,
    ) -> None:
        observations = workload_tests.valid_observations()
        timers = observations["live"]["user_work"]["podman_health_timers"]
        self.assertTrue(timers)
        reviewed = copy.deepcopy(timers[0])
        unknown = "b" * 64
        stolen = reviewed | {
            "container_id": unknown,
            "timer": f"{unknown}-{str(reviewed['timer']).split('-', 1)[1]}",
            "service": f"{unknown}-{str(reviewed['service']).split('-', 1)[1]}",
        }
        # The stolen timer is a well-formed transient unit name, so only
        # provenance against an observed healthy container can refuse it.
        jsonschema.Draft202012Validator(
            SCHEMA["$defs"]["podmanHealthTimerFact"]
        ).validate(stolen)
        timers[0] = stolen
        document = assembled_document(copy.deepcopy(observations))
        self.assertEqual(
            [], list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(document))
        )
        self.assert_refused(observations)

    def test_process_census_entries_are_not_admitted_from_names_alone(
        self,
    ) -> None:
        observations = workload_tests.valid_observations()
        reviewed = copy.deepcopy(observations["live"]["processes"][0])
        foreign = reviewed | {
            "control_group": (
                "/user.slice/user-20000.slice/user@20000.service/"
                "app.slice/unreviewed.service"
            ),
            "count": 1,
        }
        jsonschema.Draft202012Validator(SCHEMA["$defs"]["processFact"]).validate(
            foreign
        )
        observations["live"]["processes"].append(foreign)
        self.assert_refused(observations)

    def test_malformed_absent_duplicate_and_oversized_facts_fail_closed(
        self,
    ) -> None:
        mutations = {
            "duplicate-unit": lambda live: live["user_work"][
                "active_units"
            ].append(live["user_work"]["active_units"][0]),
            "over-limit-units": lambda live: live["user_work"][
                "active_units"
            ].extend(f"padding-{index}.service" for index in range(200)),
            "absent-container-field": lambda live: live["containers"][0].pop(
                "security_opt"
            ),
            "unexpected-container-field": lambda live: live["containers"][
                0
            ].__setitem__("target_claimed_ready", True),
            "malformed-process-group": lambda live: live["processes"][
                0
            ].__setitem__("control_group", "/system.slice/sshd.service"),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                observations = workload_tests.valid_observations()
                mutate(observations["live"])
                self.assert_refused(observations)

    def test_phase_comparisons_remain_exact(self) -> None:
        comparisons = {
            "baseline-control-resources": lambda observations: observations[
                "baseline"
            ]["control_resources"].__setitem__("network_id", "c" * 64),
            "cleanup-leaves-a-container": lambda observations: observations[
                "post_cleanup"
            ]["all_containers"].append(f"secpal-int-{INSTANCE}-api"),
            "cleanup-leaves-a-unit": lambda observations: observations[
                "post_cleanup"
            ]["user_work"]["active_units"].append(
                f"secpal-int-{INSTANCE}-api.service"
            ),
            "live-loses-a-container": lambda observations: observations["live"][
                "containers"
            ].pop(),
        }
        for name, mutate in comparisons.items():
            with self.subTest(comparison=name):
                observations = workload_tests.valid_observations()
                mutate(observations)
                self.assert_refused(observations)


if __name__ == "__main__":
    unittest.main()
