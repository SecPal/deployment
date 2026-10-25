#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Repository regressions only; never native host acceptance."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/ci-cloud"))


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def native_operations(source=None):
    """Executable inventory for the reviewed broader Python/Bash owner route."""
    import ast
    module = load("_native_host_coverage", "scripts/qualify-native-host.py")
    text = source if source is not None else (ROOT / "scripts/qualify-native-host.py").read_text()
    tree = ast.parse(text)
    operations = {"native-administrator-owned-source-required"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "diagnostic":
            assert isinstance(node.args[0], ast.Constant)
            operations.add("native-" + node.args[0].value)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            assert isinstance(node.args[0], ast.Constant)
            operations.add(node.args[0].value)
    operations.update(row[2] for row in module.classifier.LINE_RULES)
    operations.update(row[1] for row in module.classifier.EXPLICIT_RULES)
    collector_tree = ast.parse((ROOT / "scripts/ci-cloud/collect-rocky-preparation.py").read_text())
    collector = next(n for n in collector_tree.body if isinstance(n, ast.FunctionDef)
                     and n.name == "collect_native_package_admission")
    cls = next(n for n in collector_tree.body if isinstance(n, ast.ClassDef) and n.name == "Observer")
    methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
    pending = [collector]; seen = set()
    while pending:
        surface = pending.pop()
        for node in ast.walk(surface):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "ObservationOperation"):
                operations.add("rpm-" + getattr(module.phase.rpm_observer.ObservationOperation, node.attr).value)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in {"self", "observer"}
                    and node.func.attr in methods and node.func.attr not in seen):
                seen.add(node.func.attr); pending.append(methods[node.func.attr])
    return operations


class NativeHostTests(unittest.TestCase):
    def test_fixture_staging_reuses_the_complete_canonical_digest_membership(self):
        module = load("_native_host", "scripts/qualify-native-host.py")
        contract = load("_native_preparation", "scripts/ci-cloud/rocky_preparation_contract.py")
        expected = contract.AMD64_CHILD
        valid = json.dumps([contract.FIXTURE, contract.FIXTURE_REPOSITORY + "@" + expected])
        self.assertEqual(expected, module.admit_fixture(valid, "x86_64"))
        for raw in ("[]", '["docker.io/library/alpine:latest"]',
                    json.dumps([contract.FIXTURE]), valid[:-1],
                    json.dumps([contract.FIXTURE_REPOSITORY + "@" + expected] * 2)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                module.admit_fixture(raw, "x86_64")

    def test_operator_schema_cannot_change_the_historical_gcp_contract(self):
        control = load("_native_control", "scripts/ci-cloud/rocky-control.py")
        before = control.load_object(control.SCHEMAS["qualification"])
        target = "56e96e66edba1ad0b0de1682a5f231a7171ee8ae"
        scoped = control.operator_qualification_schema(target)
        self.assertEqual({"const": target}, scoped["properties"]["target_sha"])
        self.assertEqual({"const": target},
                         scoped["properties"]["native_observation"]["properties"]["target_sha"])
        self.assertEqual({"const": 4}, scoped["properties"]["schema_version"])
        self.assertEqual(before, control.load_object(control.SCHEMAS["qualification"]))
        self.assertNotIn(target, before["properties"]["target_sha"]["enum"])
        for value in ("", "main", "x" * 40, "a" * 39):
            with self.subTest(target=value), self.assertRaises(control.ControlError):
                control.operator_qualification_schema(value)

    def test_native_binding_rejects_changed_source_control_host_harness_and_boot(self):
        module = load("_native_host", "scripts/qualify-native-host.py")
        expected = {"source_sha": "a" * 40, "control_sha": "b" * 40,
                    "harness_sha256": module.HARNESS_SHA256,
                    "host_identity": "hetzner:163717938",
                    "architecture": "x86_64",
                    "boot_id": "00000000-0000-4000-8000-000000000001",
                    "execution_id": "1792944000000000"}
        self.assertIsNone(module.admit_binding(dict(expected), expected))
        for key in expected:
            altered = dict(expected); altered[key] = "changed"
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.admit_binding(altered, expected)
        for altered in ({}, {**expected, "accepted": True}):
            with self.assertRaises(ValueError):
                module.admit_binding(altered, expected)

    def envelope(self):
        module = load("_native_host", "scripts/qualify-native-host.py")
        import base64, hashlib
        binding = {"source_sha": "a" * 40, "control_sha": "b" * 40,
                   "harness_sha256": module.HARNESS_SHA256, "host_identity": "hetzner:163717938",
                   "architecture": "x86_64", "boot_id": "00000000-0000-4000-8000-000000000001",
                   "execution_id": "1792944000000000"}
        unit = "secpal-host-qualification-Ab12Cd"
        properties = "\n".join((
            f"FragmentPath=/run/user/20000/systemd/generator/{unit}.service",
            f"SourcePath=/etc/containers/systemd/users/20000/{unit}.container",
            "DropInPaths=", f"ExecStart={module.authority.expected_exec_start(unit)}")) + "\n"
        authority = module.authority.admit_quadlet_authority(properties,
            f"/run/user/20000/systemd/generator/{unit}.service",
            f"/etc/containers/systemd/users/20000/{unit}.container")
        facts = {"process_a": "system_u:system_r:container_t:s0:c0",
                 "process_b": "system_u:system_r:container_t:s0:c1023",
                 "storage_a": "system_u:object_r:container_file_t:s0:c0"}
        identity = "msg=audit(10/25/26 16:00:00.000:41) :"
        audit = "\n".join((
            f'type=AVC {identity} avc: denied {{ read }} pid=4242 name="marker" '
            f'scontext={facts["process_b"]} tcontext={facts["storage_a"]} tclass=file permissive=0',
            f"type=PROCTITLE {identity} proctitle=cat /foreign/marker",
            f'type=SYSCALL {identity} pid=4242 comm="cat"')) + "\n"
        isolation = module.isolation.admit_selinux_isolation(**facts, audit_text=audit)
        digest = hashlib.sha256(module.isolation.canonical_bytes(isolation)).hexdigest()
        encoded = base64.b64encode(module.authority.canonical_bytes(authority)).decode()
        stdout = "".join(f"{k}={v}\n" for k, v in facts.items()) + (
            f"seccomp_mode=2\ndenial_pid=4242\nselinux_isolation_sha256={digest}\n"
            f"quadlet_authority_base64={encoded}\n"
            "PASS: Rocky Linux 10.2 target workload contract\n")
        packages = []
        for name in module.preparation.PACKAGES:
            version = "5.8.2" if name == "podman" else "1.0"
            packages.append({"name": name, "epoch": "0", "version": version,
                "release": "1.el10_2", "architecture": "x86_64",
                "nevra": f"{name}-{version}-1.el10_2.x86_64", "resolved_repository": "appstream",
                "signature_verified": True, "signer_fingerprint": module.preparation.ROCKY_FINGERPRINT,
                "payload_digest": "c" * 64})
        observed = {"schema_version": 1, "target_sha": binding["source_sha"],
            "trusted_control_sha": binding["control_sha"], "qualification_run_id": binding["execution_id"],
            "qualification_run_attempt": "1", "host": {"id": "rocky", "version_id": "10.2",
            "architecture": "x86_64"}, "podman_version": "5.8.2", "packages": packages}
        native = {"schema_version": 4, "target_sha": binding["source_sha"],
            "native_observation": observed, "quadlet_authority": authority,
            "exit_status": 0, "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stdout_bytes": len(stdout.encode()), "selinux_isolation": isolation,
            "seccomp_enforced": True, "cleanup_complete": True, "classification": "PASS"}
        status = ("Uid: 65532 65532 65532 65532\nGid: 65532 65532 65532 65532\n"
                  "NoNewPrivs: 1\nSeccomp: 2\n" +
                  "".join(f"{k}: 0000000000000000\n" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")))
        envelope = {"binding": binding, "fixture": {"input": module.preparation.FIXTURE,
            "child": module.preparation.AMD64_CHILD}, "native": native, "packages": observed,
            "stdout": stdout, "audit": audit, "live": {"unit": unit, "properties": properties,
            "authority": authority, "workload_status": status},
            "cleanup_before": {"containers": [], "units": "", "paths": []},
            "cleanup_after": {"containers": [], "units": "", "paths": []}}
        return module, envelope, binding

    def test_real_canonical_owners_admit_only_the_exact_complete_test_representation(self):
        import tempfile
        module, envelope, expected = self.envelope()
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(module.admit_execution(envelope, expected, Path(temporary)))

    def test_real_owners_reject_missing_conflicting_and_incomplete_observations(self):
        import copy, tempfile
        module, envelope, expected = self.envelope()
        def reject(label, mutate):
            candidate = copy.deepcopy(envelope); mutate(candidate)
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises((ValueError, module.control.ControlError,
                        module.isolation.IsolationError, module.authority.AuthorityError,
                        module.phase.Error)):
                    module.admit_execution(candidate, expected, Path(temporary))
        reject("raw PASS", lambda d: d.clear())
        reject("source", lambda d: d["binding"].update(source_sha="c" * 40))
        reject("unsigned RPM", lambda d: d["packages"]["packages"][0].update(signature_verified=False))
        reject("wrong architecture", lambda d: d["packages"]["host"].update(architecture="aarch64"))
        reject("missing AVC", lambda d: d.update(audit=""))
        reject("permissive AVC", lambda d: d.update(audit=d["audit"].replace("permissive=0", "permissive=1")))
        reject("wrong tested process", lambda d: d.update(audit=d["audit"].replace("pid=4242", "pid=9999")))
        reject("mutable fixture", lambda d: d["fixture"].update(input="docker.io/library/alpine:latest"))
        reject("remaining container", lambda d: d["cleanup_after"].update(containers=["secpal-host-qualification-Ab12Cd"]))
        reject("pre-existing resource", lambda d: d["cleanup_before"].update(paths=["/var/tmp/secpal-host-qualification-Ab12Cd"]))
        reject("changed Quadlet command", lambda d: d["live"].update(properties=d["live"]["properties"].replace("--cap-drop all", "--privileged")))
        reject("capability", lambda d: d["live"].update(workload_status=d["live"]["workload_status"].replace("CapEff: 0000000000000000", "CapEff: 0000000000000001")))
        reject("NNP", lambda d: d["live"].update(workload_status=d["live"]["workload_status"].replace("NoNewPrivs: 1", "NoNewPrivs: 0")))
        reject("UID", lambda d: d["live"].update(workload_status=d["live"]["workload_status"].replace("65532", "0")))
        reject("seccomp", lambda d: d["live"].update(workload_status=d["live"]["workload_status"].replace("Seccomp: 2", "Seccomp: 0")))
        reject("unknown field", lambda d: d.update(accepted=True))
        reject("false cleanup", lambda d: d["cleanup_after"].update(containers=False))
        reject("missing cleanup", lambda d: d["cleanup_after"].pop("paths"))
        reject("missing live observation", lambda d: d.pop("live"))

    def test_staging_first_run_repeat_and_wrong_child_without_other_store_changes(self):
        import tempfile
        module = load("_native_host", "scripts/qualify-native-host.py")
        class Native:
            def __init__(self, exists, child):
                self.exists, self.child, self.calls = exists, child, []
            def run(self, operation, arguments, **options):
                self.calls.append((operation, arguments, options))
                if arguments[:3] == ["podman", "image", "exists"]:
                    return (0 if self.exists else 1), ""
                if arguments[:3] == ["podman", "image", "inspect"]:
                    return 0, json.dumps([module.preparation.FIXTURE_REPOSITORY + "@" + self.child])
                return 0, ""
        for exists in (False, True):
            native = Native(exists, module.preparation.AMD64_CHILD)
            with tempfile.TemporaryDirectory() as temporary:
                result = module.stage_fixture(native, {"name": "secpal-deploy"}, "x86_64", Path(temporary))
            self.assertEqual(not exists, result["changed"])
            pulls = [a for _, a, _ in native.calls if a[:2] == ["podman", "pull"]]
            self.assertEqual(0 if exists else 1, len(pulls))
            if pulls:
                self.assertEqual(module.preparation.FIXTURE, pulls[0][-1])
                self.assertIn("--tls-verify=true", pulls[0])
                self.assertIn("--authfile", pulls[0])
            self.assertTrue(all(o["user"] == "secpal-deploy" for _, _, o in native.calls))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(module.phase.Error):
            module.stage_fixture(Native(True, "sha256:" + "0" * 64),
                                 {"name": "secpal-deploy"}, "x86_64", Path(temporary))


    def test_dispatch_covers_real_native_calls_and_immutable_harness_mapping(self):
        document = json.loads((ROOT / ".secpal/evidence-architecture.json").read_text())
        entries = {r["id"]: r for r in document["external_operations"]}
        expected = native_operations()
        self.assertTrue(expected <= entries.keys())
        for name in expected:
            self.assertEqual({"id": name, "reachable": True, "fallible": True, "trusted": True,
                "diagnostic_identity": {"id": name, "kind": "semantic"}}, entries[name])
        module = load("_native_host", "scripts/qualify-native-host.py")
        import hashlib
        self.assertEqual(module.HARNESS_SHA256, hashlib.sha256(module.HARNESS.read_bytes()).hexdigest())
        self.assertEqual(module.HARNESS_SHA256, module.classifier.EXPECTED_HARNESS_SHA256)

    def test_dispatch_inventory_detects_new_source_operations(self):
        source = (ROOT / "scripts/qualify-native-host.py").read_text()
        self.assertNotIn("native-unlisted", native_operations(source))
        changed = source + '\ndef extra(native):\n    native.run("native-unlisted", ["true"])\n'
        self.assertIn("native-unlisted", native_operations(changed))


    def test_control_hook_observes_the_exact_service_unit_and_uses_existing_authority(self):
        import tempfile
        module, envelope, _ = self.envelope()
        class Native:
            def __init__(self):
                self.calls = []
            def run(self, operation, arguments, **options):
                self.calls.append((operation, arguments, options))
                if operation == "native-observe-quadlet-properties":
                    return 0, envelope["live"]["properties"]
                if operation == "native-observe-quadlet-pid":
                    return 0, "12345"
                if operation == "native-observe-workload-process":
                    return 0, envelope["live"]["workload_status"]
                return 0, ""
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "live.json"
            native = Native()
            module.unit_observation(native, envelope["live"]["unit"] + ".service", output)
            self.assertNotIn("workload_status", json.loads(output.read_text()))
            module.unit_observation(native, envelope["live"]["unit"] + ".service", output, runtime=True)
            self.assertEqual(envelope["live"], json.loads(output.read_text()))
            self.assertEqual(1, sum(op == "native-observe-quadlet-properties"
                                    for op, _, _ in native.calls))
            self.assertTrue(any(op == "native-admit-runtime-identity" for op, _, _ in native.calls))
            self.assertTrue(any(op == "native-admit-least-authority" for op, _, _ in native.calls))
        for bad in ("unrelated.service", "../secpal-host-qualification-Ab12Cd.service"):
            native = Native()
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
                module.unit_observation(native, bad, Path(temporary) / "live.json")
            self.assertEqual([], native.calls)

    def test_real_generated_hook_orders_observations_and_never_hides_failure(self):
        import os, subprocess, tempfile
        module = load("_native_host", "scripts/qualify-native-host.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); hook = root / "hook"; live = root / "live.json"
            module.write_control_hook(hook, live)
            subprocess.run(["bash", "-n", str(hook)], check=True)
            observer = root / "observer"; runtime = root / "runuser"
            observer.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$LOG"\n'
                                '[ "$1" != "$FAIL_PHASE" ]\n')
            runtime.write_text('#!/bin/sh\nprintf "runuser\\n" >> "$LOG"\nexit "$RUNTIME_STATUS"\n')
            observer.chmod(0o700); runtime.chmod(0o700)
            instrumented = hook.read_text().replace("/usr/sbin/runuser", str(runtime)).replace(
                "/usr/bin/python3 -I " + str(ROOT / "scripts/qualify-native-host.py"), str(observer))
            hook.write_text(instrumented)
            for failure, runtime_status, expected, success in (
                    ("none", "0", ["--observe-unit", "runuser", "--observe-runtime"], True),
                    ("--observe-unit", "0", ["--observe-unit"], False),
                    ("--observe-runtime", "0", ["--observe-unit", "runuser", "--observe-runtime"], False),
                    ("none", "1", ["--observe-unit", "runuser"], False)):
                log = root / "log"; log.write_text("")
                env = {"PATH": "/usr/bin:/bin", "LOG": str(log),
                       "FAIL_PHASE": failure, "RUNTIME_STATUS": runtime_status}
                args = ["--user", "secpal-deploy", "--", "env", "-u", "CONTAINER_HOST",
                        "-u", "CONTAINER_CONNECTION", "HOME=/var/lib/secpal",
                        "XDG_RUNTIME_DIR=/run/user/20000",
                        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
                        "systemctl", "--user", "start", "secpal-host-qualification-Ab12Cd.service"]
                c = subprocess.run(["bash", "-c", 'source "$1"; shift; runuser "$@"',
                                    "test-owner", str(hook), *args], env=env,
                                   capture_output=True, text=True)
                with self.subTest(failure=failure, runtime_status=runtime_status):
                    self.assertEqual(success, c.returncode == 0, c.stderr)
                    self.assertEqual(expected, log.read_text().splitlines())

    def test_real_path_owner_admits_only_trusted_working_directory_ancestry(self):
        import os, tempfile
        module = load("_native_host", "scripts/qualify-native-host.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "run").mkdir(); (root / "private").mkdir()
            (root / "var").mkdir(); (root / "var/tmp").mkdir(mode=0o1777)
            (root / "var/tmp").chmod(0o1777)
            native = module.phase.Native(root=root, owner=(os.geteuid(), os.getegid()))
            output = root / "private/evidence.json"
            with module.working_directory(native, output, staging=False) as actual:
                self.assertEqual(output.parent, Path(actual).parent)
                native.trusted(Path(actual), directory=True)
            with module.working_directory(native, output, staging=True) as actual:
                self.assertEqual(root / "run", Path(actual).parent)
                native.trusted(Path(actual), directory=True)
            with self.assertRaises(module.phase.Error):
                native.trusted(root / "var/tmp", directory=True)

    def test_every_existing_explicit_harness_rejection_has_its_semantic_owner(self):
        module = load("_native_host", "scripts/qualify-native-host.py")
        for prefix, operation, reason in module.classifier.EXPLICIT_RULES:
            with self.subTest(prefix=prefix):
                self.assertEqual((operation, reason), module.diagnose_harness(
                    (prefix + " private variable suffix\n").encode(), b"", 1))
        self.assertEqual(("qualification-harness", "timeout"),
                         module.diagnose_harness(b"", b"", 124))
        self.assertEqual(("qualification-harness", "unclassified-target-failure"),
                         module.diagnose_harness(b"private unknown message\n", b"", 1))

    def test_harness_timeout_is_term_first_with_real_cleanup_and_outer_grace(self):
        import subprocess, tempfile
        from unittest import mock
        module, envelope, binding = self.envelope()
        class Captured(Exception):
            pass
        class Native:
            def run(self, operation, arguments, **options):
                if operation == "native-observe-audit-checkpoint":
                    return 0, "10/25/26 16:00:00"
                if operation == "native-execute-harness":
                    self.command, self.options = arguments, options
                    raise Captured
                return 0, ""
        native = Native()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(module, "snapshot",
                    return_value={"containers": [], "units": "", "paths": []}), mock.patch.object(
                    module.phase.rpm_observer, "collect_native_package_admission",
                    return_value=envelope["packages"]):
                with self.assertRaises(Captured):
                    module.qualify(native, {"name": "secpal-deploy"}, binding, root)
            self.assertEqual(["timeout", "--signal=TERM", "--kill-after=180s", "45m"],
                             native.command[:4])
            self.assertGreater(native.options["timeout"], 2700 + 180)
            self.assertIn("2>&1", native.command[6])
            # Exercise the same TERM-first primitive on a harmless local fixture.
            marker = root / "cleaned"
            c = subprocess.run(["timeout", native.command[1], "--kill-after=2s", "0.2s",
                "bash", "-c", 'trap \'printf cleaned > "$1"; exit 0\' TERM; while :; do sleep 1; done',
                "test-owner", str(marker)], text=True, capture_output=True, timeout=5)
            self.assertEqual(124, c.returncode)
            self.assertEqual("cleaned", marker.read_text())

if __name__ == "__main__":
    unittest.main()
