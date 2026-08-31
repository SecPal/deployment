#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Architecture regressions for the layered Rocky host-evidence pipeline."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import itertools
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate-rocky-evidence-architecture.py"
CONTRACT = ROOT / "scripts/ci-cloud/rocky_preparation_contract.py"
COLLECTOR = ROOT / "scripts/ci-cloud/collect-rocky-preparation.py"
PREPARATION = ROOT / "scripts/ci-cloud/prepare-rocky-host.sh"
WORKFLOW = ROOT / ".github/workflows/rocky-cloud-qualification.yml"
CONTROL = ROOT / "scripts/ci-cloud/rocky-control.py"


def load_contract():
    specification = importlib.util.spec_from_file_location(
        "rocky_preparation_contract", CONTRACT
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load Rocky preparation contract")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RockyEvidenceArchitectureTests(unittest.TestCase):
    RUNTIME_ADMISSION_OPERATIONS = (
        "admit-runtime-rootless",
        "admit-runtime-oci-runtime",
        "admit-runtime-network-backend",
        "admit-runtime-seccomp",
        "admit-runtime-cgroup",
        "admit-runtime-systemd-user",
        "admit-runtime-socket-path-absence",
        "admit-runtime-socket-unit-disabled",
        "admit-runtime-container-host-absence",
        "admit-runtime-service-locality",
        "admit-runtime-podman-version",
    )

    @staticmethod
    def realistic_raw(contract):
        payload = "a" * 64
        header = "b" * 64
        key_packet = b"reviewed Rocky 10 signing key packet"
        contract.ROCKY_KEY_PACKET_SHA256 = hashlib.sha256(key_packet).hexdigest()
        packages = []
        for name in contract.PACKAGES:
            version = "5.8.2" if name == "podman" else "1.0"
            nevra = f"{name}-{version}-1.el10_2.aarch64"
            packages.append(
                {
                "name": name,
                "epoch": "0",
                "version": version,
                "release": "1.el10_2",
                "architecture": "aarch64",
                "nevra": nevra,
                "repositories": ["appstream"],
                "signed_header": "\n".join(
                    (
                        name,
                        "0",
                        version,
                        "1.el10_2",
                        "aarch64",
                        nevra,
                        payload,
                        "8",
                        header,
                        "RSA/SHA256, Wed May 21 13:19:52 2025, Key ID 5b106c736fedfc85",
                    )
                ),
                "verification": "\n".join(
                    (
                        "Header V4 RSA/SHA256 Signature, key ID 6fedfc85: OK",
                        "Header SHA256 digest: OK",
                        "Header SHA1 digest: OK",
                    )
                ),
                }
            )
        expected = f"{contract.FIXTURE_REPOSITORY}@{contract.ARM_CHILD}"
        return {
            "os_release": 'NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="10.2"',
            "architecture": "aarch64",
            "dnf_version": "4.22.0\nInstalled: dnf-0:4.22.0",
            "releasever": "10",
            "getenforce": "Enforcing",
            "selinux_enabled": True,
            "sestatus": "Loaded policy name: targeted",
            "repositories": "repo id repo name\nappstream AppStream\nbaseos BaseOS\nextras Extras",
            "account": {"name": "secpal-runtime", "uid": 991, "gid": 991, "home": "/home/secpal-runtime", "shell": "/usr/sbin/nologin"},
            "subuid": "secpal-runtime:1048576:65536",
            "subgid": "secpal-runtime:1048576:65536",
            "effective_ids": [0, 991],
            "supplementary_groups": [991],
            "podman_info": json.dumps({"host": {"security": {"rootless": True, "seccompEnabled": True}, "ociRuntime": {"name": "crun"}, "networkBackend": "netavark", "remoteSocket": {"path": "/run/user/991/podman/podman.sock", "exists": True}, "serviceIsRemote": False}, "store": {"graphRoot": "/home/secpal-runtime/.local/share/containers/storage"}}),
            "graphroot": "/home/secpal-runtime/.local/share/containers/storage",
            "account_home": "/home/secpal-runtime",
            "fixture_repo_digests": json.dumps([expected]),
            "automatic_unit_statuses": [1, 1, 1, 1],
            "boot_id": "22222222-2222-2222-2222-222222222222",
            "meminfo": "MemTotal:       16000000 kB",
            "root_filesystem_bytes": 120000000000,
            "cpu_count": 4,
            "packages": packages,
            "rocky_signing_key": "6fedfc85\n"
            + base64.b64encode(key_packet).decode("ascii"),
            "container_configs": ["[engine]\nlabel=true"],
            "cgroup_filesystem": "cgroup2fs",
            "systemd_user": "active",
            "socket_exists": False,
            "podman_socket_status": 1,
            "container_host_present": False,
            "sudo_observation": {"status": 1, "output": "not allowed to run sudo"},
            "quadlet_status": 1,
            "linger": True,
            "fixture_present": True,
            "cloud_identity_marker": True,
            "google_credentials_present": False,
        }

    @staticmethod
    def realistic_options():
        return {
            "target_sha": "b" * 40,
            "control_sha": "a" * 40,
            "run_id": "12345",
            "run_attempt": "1",
            "expires_at": 1800010800,
            "image": "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/global/images/rocky-linux-10-2-20260801-arm64",
            "first_boot_id": "11111111-1111-1111-1111-111111111111",
        }

    def test_repository_architecture_gate_passes(self) -> None:
        completed = subprocess.run(
            [VALIDATOR], check=False, capture_output=True, text=True
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        collector = COLLECTOR.read_text(encoding="utf-8")
        self.assertNotIn("contract.normalize_podman", collector)

    def test_package_identity_and_podman_range_are_one_authenticated_contract(self) -> None:
        contract = load_contract()

        preparation_schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )["properties"]["packages"]["items"]["properties"]
        qualification_schema = json.loads(
            (
                ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json"
            ).read_text(encoding="utf-8")
        )["$defs"]["package"]["properties"]
        for schema in (preparation_schema, qualification_schema):
            self.assertEqual(
                contract.RPM_VERSION_RELEASE_MAX_LENGTH,
                schema["version"]["maxLength"],
            )
            self.assertEqual(
                contract.RPM_VERSION_RELEASE_MAX_LENGTH,
                schema["release"]["maxLength"],
            )
            self.assertEqual(
                contract.RPM_NEVRA_MAX_LENGTH,
                schema["nevra"]["maxLength"],
            )

        def package(
            version: str = "5.8.2",
            architecture: str = "aarch64",
            epoch: str = "7",
        ):
            epoch_prefix = "" if epoch == "0" else f"{epoch}:"
            nevra = f"podman-{epoch_prefix}{version}-1.el10_2.{architecture}"
            return {
                "name": "podman",
                "epoch": epoch,
                "version": version,
                "release": "1.el10_2",
                "architecture": architecture,
                "nevra": nevra,
                "repositories": ["appstream"],
                "signed_header": "\n".join(
                    (
                        "podman",
                        epoch,
                        version,
                        "1.el10_2",
                        architecture,
                        nevra,
                        "a" * 64,
                        "8",
                        "b" * 64,
                        "RSA/SHA256, Wed May 21 13:19:52 2025, Key ID 5b106c736fedfc85",
                    )
                ),
                "verification": "\n".join(
                    (
                        "Header V4 RSA/SHA256 Signature, key ID 6fedfc85: OK",
                        "Header SHA256 digest: OK",
                        "Header SHA1 digest: OK",
                    )
                ),
            }

        for host_architecture, version in (
            ("aarch64", "5.8.2"),
            ("x86_64", "5.9.7"),
        ):
            with self.subTest(
                admitted_version=version, host_architecture=host_architecture
            ):
                fact = contract.normalize_package(
                    "podman",
                    package(version, host_architecture),
                    host_architecture,
                )
                admitted = contract.admit_package(
                    fact, contract.ROCKY_FINGERPRINT, host_architecture
                )
                facts = {"packages_admitted": [admitted]}
                contract.admit_runtime_podman_version(facts)
                self.assertEqual(version, facts["podman_version_admitted"])

        mutations = {
            "below-minimum": package("5.8.1"),
            "leading-zero": package("5.8.02"),
            "next-major": package("6.0.0"),
            "malformed-version": package("5.8"),
            "wrong-architecture": package(architecture="x86_64"),
            "inverse-wrong-architecture": package(architecture="aarch64"),
            "wrong-package": {**package(), "name": "conmon"},
            "malformed-nevra": {**package(), "nevra": "xxx"},
        }
        for name, raw in mutations.items():
            with self.subTest(rejected=name), self.assertRaises(
                contract.ContractError
            ):
                host_architecture = (
                    "x86_64" if name == "inverse-wrong-architecture" else "aarch64"
                )
                fact = contract.normalize_package(
                    "podman", raw, host_architecture
                )
                admitted = contract.admit_package(
                    fact, contract.ROCKY_FINGERPRINT, host_architecture
                )
                contract.admit_runtime_podman_version(
                    {"packages_admitted": [admitted]}
                )

        for field in ("version", "release"):
            with self.subTest(rejected=f"overlong-{field}"):
                with self.assertRaises(contract.ContractError) as raised:
                    raw = package()
                    raw[field] = "1" * 129
                    raw["nevra"] = contract.canonical_nevra(
                        raw["name"],
                        raw["epoch"],
                        raw["version"],
                        raw["release"],
                        raw["architecture"],
                    )
                    header = raw["signed_header"].splitlines()
                    header[2 if field == "version" else 3] = raw[field]
                    header[5] = raw["nevra"]
                    raw["signed_header"] = "\n".join(header)
                    contract.normalize_package("podman", raw, "aarch64")
                self.assertEqual(
                    "normalize-package-evidence", raised.exception.operation
                )

    def test_architecture_gate_rejects_collapsed_runtime_admission(self) -> None:
        source = CONTRACT.read_text(encoding="utf-8")
        for operation in self.RUNTIME_ADMISSION_OPERATIONS:
            source = source.replace(f'"{operation}"', '"admit-runtime"')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / CONTRACT.name
            path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--contract", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("runtime admission", completed.stderr)

    def test_architecture_gate_pins_authenticated_package_owner(self) -> None:
        source = CONTRACT.read_text(encoding="utf-8").replace(
            '"authenticated-native-packages": "rocky_preparation_contract.admit_package"',
            '"authenticated-native-packages": "collector.admit_package"',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / CONTRACT.name
            path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--contract", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("authenticated-package invariant owner", completed.stderr)

    def test_architecture_gate_rejects_disconnected_runtime_owner(self) -> None:
        source = CONTRACT.read_text(encoding="utf-8")
        owner_calls = (
            "admit_runtime_rootless(host)",
            "admit_runtime_socket_path_absence(facts)",
            "admit_runtime_socket_unit_disabled(facts)",
            "admit_runtime_container_host_absence(facts)",
            "admit_runtime_service_locality(host)",
        )
        for owner_call in owner_calls:
            with self.subTest(owner_call=owner_call):
                mutation = source.replace(
                    f"    {owner_call}\n",
                    "    # deliberately disconnected runtime owner\n",
                    1,
                )
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / CONTRACT.name
                    path.write_text(mutation, encoding="utf-8")
                    completed = subprocess.run(
                        [VALIDATOR, "--contract", path],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn("runtime admission", completed.stderr)

    def test_runtime_admission_matches_authoritative_direct_invariants(self) -> None:
        contract = load_contract()
        for states in itertools.product((False, True), repeat=11):
            (
                rootless,
                crun,
                netavark,
                seccomp,
                cgroup2,
                systemd_user,
                socket_absent,
                socket_unit_disabled,
                container_host_absent,
                service_local,
                podman_version_supported,
            ) = states
            for remote_socket_exists in (False, True):
                facts = {
                    "podman_normalized": {
                        "host": {
                            "security": {
                                "rootless": rootless,
                                "seccompEnabled": seccomp,
                            },
                            "ociRuntime": {"name": "crun" if crun else "runc"},
                            "networkBackend": "netavark" if netavark else "cni",
                            "remoteSocket": {
                                "path": "/run/user/991/podman/podman.sock",
                                "exists": remote_socket_exists,
                            },
                            "serviceIsRemote": not service_local,
                        },
                    },
                    "cgroup_filesystem": "cgroup2fs" if cgroup2 else "tmpfs",
                    "systemd_user": "active" if systemd_user else "inactive",
                    "socket_exists": not socket_absent,
                    "podman_socket_enabled": not socket_unit_disabled,
                    "container_host_present": not container_host_absent,
                    "packages_admitted": [
                        {
                            "name": "podman",
                            "epoch": "0",
                            "version": "5.8.2" if podman_version_supported else "6.0.0",
                        }
                    ],
                }
                intended_accepts = all(states)
                try:
                    contract.admit_runtime(facts)
                except contract.ContractError:
                    new_accepts = False
                else:
                    new_accepts = True
                self.assertEqual(
                    intended_accepts,
                    new_accepts,
                    (states, remote_socket_exists),
                )

    def test_runtime_admission_reports_each_exact_semantic_boundary(self) -> None:
        contract = load_contract()
        baseline = self.realistic_raw(contract)

        def mutate_podman(path, value):
            def mutation(raw):
                podman = json.loads(raw["podman_info"])
                target = podman
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                raw["podman_info"] = json.dumps(podman)

            return mutation

        mutations = (
            ("admit-runtime-rootless", mutate_podman(("host", "security", "rootless"), False)),
            ("admit-runtime-oci-runtime", mutate_podman(("host", "ociRuntime", "name"), "runc")),
            ("admit-runtime-network-backend", mutate_podman(("host", "networkBackend"), "cni")),
            ("admit-runtime-seccomp", mutate_podman(("host", "security", "seccompEnabled"), False)),
            ("admit-runtime-cgroup", lambda raw: raw.__setitem__("cgroup_filesystem", "tmpfs")),
            ("admit-runtime-systemd-user", lambda raw: raw.__setitem__("systemd_user", "inactive")),
            ("admit-runtime-socket-path-absence", lambda raw: raw.__setitem__("socket_exists", True)),
            ("admit-runtime-socket-unit-disabled", lambda raw: raw.__setitem__("podman_socket_status", 0)),
            ("admit-runtime-container-host-absence", lambda raw: raw.__setitem__("container_host_present", True)),
            ("admit-runtime-service-locality", mutate_podman(("host", "serviceIsRemote"), True)),
            (
                "admit-runtime-podman-version",
                lambda raw: raw["packages"][0].update(
                    {
                        "version": "5.8.1",
                        "nevra": "podman-5.8.1-1.el10_2.aarch64",
                        "signed_header": raw["packages"][0]["signed_header"].replace(
                            "5.8.2", "5.8.1"
                        ),
                    }
                ),
            ),
        )
        for operation, mutate in mutations:
            with self.subTest(operation=operation):
                candidate = copy.deepcopy(baseline)
                mutate(candidate)
                with self.assertRaises(contract.ContractError) as raised:
                    contract.normalize_and_admit(candidate, self.realistic_options())
                self.assertEqual("admission", raised.exception.layer)
                self.assertEqual(operation, raised.exception.operation)
                self.assertEqual("invariant-failed", raised.exception.reason)
                self.assertIsNone(raised.exception.subject)
                diagnostic = contract.assemble_collection_diagnostic(
                    raised.exception.layer,
                    raised.exception.operation,
                    raised.exception.reason,
                    raised.exception.subject,
                )
                failure = {
                    "schema_version": 1,
                    "target_sha": "b" * 40,
                    "trusted_control_sha": "a" * 40,
                    "run_id": "12345",
                    "run_attempt": "1",
                    "phase": "evidence-collection",
                    "exit_status": 1,
                    "guest": {
                        "id": "rocky",
                        "version_id": "10.2",
                        "uname_machine": "aarch64",
                    },
                    "collection_diagnostic": diagnostic,
                }
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8"
                ) as artifact:
                    json.dump(failure, artifact)
                    artifact.flush()
                    completed = subprocess.run(
                        [
                            CONTROL,
                            "validate-evidence",
                            "preparation-failure",
                            artifact.name,
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                self.assertEqual(0, completed.returncode, completed.stderr)

    def test_combined_runtime_failures_use_stable_semantic_order(self) -> None:
        contract = load_contract()
        raw = self.realistic_raw(contract)
        podman = json.loads(raw["podman_info"])
        podman["host"]["security"]["rootless"] = False
        podman["host"]["ociRuntime"]["name"] = "runc"
        raw["podman_info"] = json.dumps(podman)
        with self.assertRaises(contract.ContractError) as raised:
            contract.normalize_and_admit(raw, self.realistic_options())
        self.assertEqual("admit-runtime-rootless", raised.exception.operation)

    def test_remote_socket_info_is_not_authoritative_for_socket_absence(self) -> None:
        contract = load_contract()
        raw = self.realistic_raw(contract)
        document = contract.normalize_and_admit(raw, self.realistic_options())
        self.assertTrue(document["runtime"]["socket_absent"])
        self.assertTrue(document["runtime"]["api_dependency_absent"])
        without_remote_socket = copy.deepcopy(raw)
        podman = json.loads(without_remote_socket["podman_info"])
        del podman["host"]["remoteSocket"]
        without_remote_socket["podman_info"] = json.dumps(podman)
        self.assertEqual(
            document,
            contract.normalize_and_admit(
                without_remote_socket, self.realistic_options()
            ),
        )

        direct_failures = (
            ("socket_exists", True, "admit-runtime-socket-path-absence"),
            (
                "podman_socket_status",
                0,
                "admit-runtime-socket-unit-disabled",
            ),
            (
                "container_host_present",
                True,
                "admit-runtime-container-host-absence",
            ),
        )
        for key, value, operation in direct_failures:
            with self.subTest(operation=operation):
                candidate = copy.deepcopy(raw)
                candidate[key] = value
                with self.assertRaises(contract.ContractError) as raised:
                    contract.normalize_and_admit(
                        candidate, self.realistic_options()
                    )
                self.assertEqual(operation, raised.exception.operation)

        remote_client = copy.deepcopy(raw)
        podman = json.loads(remote_client["podman_info"])
        podman["host"]["serviceIsRemote"] = True
        remote_client["podman_info"] = json.dumps(podman)
        with self.assertRaises(contract.ContractError) as raised:
            contract.normalize_and_admit(
                remote_client, self.realistic_options()
            )
        self.assertEqual(
            "admit-runtime-service-locality", raised.exception.operation
        )

    def test_architecture_gate_rejects_remote_socket_info_as_admission(self) -> None:
        source = CONTRACT.read_text(encoding="utf-8")
        mutation = source.replace(
            "def admit_runtime_podman_version(facts: dict[str, Any]) -> None:\n",
            "def forbidden_remote_socket_present(host: dict[str, Any]) -> bool:\n"
            "    return bool(host.get('remoteSocket', {}).get('exists'))\n\n\n"
            "def admit_runtime_podman_version(facts: dict[str, Any]) -> None:\n"
            "    if forbidden_remote_socket_present(facts['podman_normalized']['host']):\n"
            "        reject('admission', 'admit-runtime-remote-socket-absence', "
            "'invariant-failed')\n",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / CONTRACT.name
            path.write_text(mutation, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--contract", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("remoteSocket", completed.stderr)

    def test_cloud_identity_marker_observation_requires_regular_file(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "rocky_preparation_collector", COLLECTOR
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("cannot load Rocky preparation collector")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        observer = module.Observer()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "cloud-identity-absent"
            marker.mkdir()
            self.assertFalse(
                observer.is_regular_file(
                    module.ObservationOperation.CLOUD_IDENTITY, marker
                )
            )
            marker.rmdir()
            marker.write_text("absent\n", encoding="utf-8")
            self.assertTrue(
                observer.is_regular_file(
                    module.ObservationOperation.CLOUD_IDENTITY, marker
                )
            )

    def test_architecture_gate_rejects_forbidden_pure_capabilities(self) -> None:
        source = CONTRACT.read_text(encoding="utf-8")
        mutation = source.replace(
            "def normalize_os_release(raw: str) -> dict[str, str]:",
            "def normalize_os_release(raw: str) -> dict[str, str]:\n    open('/etc/os-release').read()",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / CONTRACT.name
            path.write_text(mutation, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--contract", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("forbidden pure capability", completed.stderr)

    def test_architecture_gate_rejects_opaque_observation(self) -> None:
        source = COLLECTOR.read_text(encoding="utf-8")
        mutations = {
            "module": source.replace(
                "import subprocess\n", "import subprocess\nsubprocess.run(['uname', '-m'])\n", 1
            ),
            "another-observer-method": source.replace(
                "    def run(\n",
                "    def run_opaque(self):\n"
                "        return subprocess.run(['uname', '-m'])\n\n"
                "    def run(\n",
                1,
            ),
            "another-class": source.replace(
                "class Observer:\n",
                "class OpaqueObserver:\n"
                "    def run(self):\n"
                "        return subprocess.run(['uname', '-m'])\n\n"
                "class Observer:\n",
                1,
            ),
            "nested-function": source.replace(
                "        command = arguments\n",
                "        def hidden():\n"
                "            return subprocess.run(['uname', '-m'])\n"
                "        command = arguments\n",
                1,
            ),
            "nested-lambda": source.replace(
                "        command = arguments\n",
                "        hidden = lambda: subprocess.run(['uname', '-m'])\n"
                "        command = arguments\n",
                1,
            ),
            "nested-comprehension": source.replace(
                "        command = arguments\n",
                "        hidden = [subprocess.run(['uname', '-m']) for _ in range(1)]\n"
                "        command = arguments\n",
                1,
            ),
            "aliased-import": source.replace(
                "import subprocess\n",
                "import subprocess as sp\nsp.run(['uname', '-m'])\n",
                1,
            ),
            "from-import": source.replace(
                "import subprocess\n",
                "from subprocess import run\nrun(['uname', '-m'])\n",
                1,
            ),
            "nested-default": source.replace(
                "        command = arguments\n",
                "        def hidden(value=subprocess.run(['uname', '-m'])):\n"
                "            return value\n"
                "        command = arguments\n",
                1,
            ),
            "nested-decorator": source.replace(
                "        command = arguments\n",
                "        @subprocess.run(['uname', '-m'])\n"
                "        def hidden():\n"
                "            return None\n"
                "        command = arguments\n",
                1,
            ),
            "nested-annotation": source.replace(
                "        command = arguments\n",
                "        def hidden(value: subprocess.run(['uname', '-m'])):\n"
                "            return value\n"
                "        command = arguments\n",
                1,
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / COLLECTOR.name
                path.write_text(mutation, encoding="utf-8")
                completed = subprocess.run(
                    [VALIDATOR, "--collector", path],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn("opaque observation", completed.stderr)

    def test_architecture_gate_rejects_post_install_package_transfer(self) -> None:
        source = COLLECTOR.read_text(encoding="utf-8")
        mutations = (
            source.replace(
                "        _, repositories, _ = self.run(\n",
                "        self.run(ObservationOperation.PACKAGE_REPOSITORY, "
                "['dnf4', 'download', nevra], subject=name)\n"
                "        _, repositories, _ = self.run(\n",
                1,
            ),
            source.replace(
                "    @staticmethod\n    def package_repository_query",
                "    @staticmethod\n"
                "    def package_download_query(nevra: str) -> list[str]:\n"
                "        return ['dnf4', '--quiet', 'download', nevra]\n\n"
                "    @staticmethod\n    def package_repository_query",
                1,
            ),
            source.replace(
                "        _, repositories, _ = self.run(\n",
                "        action = 'download'\n"
                "        self.run(ObservationOperation.PACKAGE_REPOSITORY, "
                "['dnf4'] + [action, nevra], subject=name)\n"
                "        _, repositories, _ = self.run(\n",
                1,
            ),
        )
        for mutation in mutations:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / COLLECTOR.name
                path.write_text(mutation, encoding="utf-8")
                completed = subprocess.run(
                    [VALIDATOR, "--collector", path],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn(
                "post-install package payload transfer", completed.stderr
            )

    def test_architecture_gate_rejects_filesystem_observation_outside_owner(self) -> None:
        source = COLLECTOR.read_text(encoding="utf-8")
        mutation = source.replace(
            "def collect(observer: Observer, options: argparse.Namespace) -> dict[str, Any]:",
            "def collect(observer: Observer, options: argparse.Namespace) -> dict[str, Any]:\n"
            "    Path('/etc/os-release').read_text(encoding='utf-8')",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / COLLECTOR.name
            path.write_text(mutation, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--collector", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("outside the Observer owner", completed.stderr)

        nested = source.replace(
            "        command = arguments\n",
            "        def hidden():\n"
            "            return Path('/etc/os-release').read_text()\n"
            "        command = arguments\n",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / COLLECTOR.name
            path.write_text(nested, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--collector", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("outside the Observer owner", completed.stderr)

    def test_architecture_gate_rejects_semantic_layer_collapse(self) -> None:
        source = COLLECTOR.read_text(encoding="utf-8").replace(
            'RESPONSIBILITY = "observation,orchestration"',
            'RESPONSIBILITY = "observation,orchestration,normalization,admission,assembly"',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / COLLECTOR.name
            path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--collector", path], check=False, capture_output=True, text=True
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("collapses all semantic responsibilities", completed.stderr)

    def test_architecture_gate_rejects_duplicate_invariant_owner(self) -> None:
        source = COLLECTOR.read_text(encoding="utf-8").replace(
            'RESPONSIBILITY = "observation,orchestration"',
            'RESPONSIBILITY = "observation,orchestration"\n'
            'INVARIANT_OWNERS = {"fixture-arm64-child": "collector"}',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / COLLECTOR.name
            path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--collector", path], check=False, capture_output=True, text=True
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("duplicate declared invariant ownership", completed.stderr)

    def test_collection_diagnostic_is_closed_and_independently_validated(self) -> None:
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        accepted = {
            "layer": "observation",
            "operation": "inspect-installed-signed-header",
            "reason": "command-failed",
            "subject": "container-selinux",
        }
        rejected = (
            {**accepted, "operation": "run-command"},
            {**accepted, "operation": "download-official-package"},
            {**accepted, "reason": "arbitrary stderr"},
            {**accepted, "subject": "https://example.invalid/secret"},
            {**accepted, "stderr": "unbounded"},
            {"layer": "observation", "operation": "inspect-installed-signed-header", "reason": "command-failed"},
            {"layer": "observation", "operation": "query-architecture", "reason": "command-failed", "subject": "podman"},
            {**accepted, "layer": "assembly"},
            {
                "layer": "normalization",
                "operation": "normalize-os-release",
                "reason": "command-failed",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diagnostic.json"
            path.write_text(json.dumps(accepted), encoding="utf-8")
            self.assertEqual(
                0,
                subprocess.run(
                    [control, "validate-collection-diagnostic", path],
                    check=False,
                    capture_output=True,
                ).returncode,
            )
            for diagnostic in rejected:
                with self.subTest(diagnostic=diagnostic):
                    path.write_text(json.dumps(diagnostic), encoding="utf-8")
                    self.assertNotEqual(
                        0,
                        subprocess.run(
                            [control, "validate-collection-diagnostic", path],
                            check=False,
                            capture_output=True,
                        ).returncode,
                    )

            key_diagnostic = {
                "layer": "observation",
                "operation": "inspect-rocky-signing-key",
                "reason": "command-failed",
            }
            path.write_text(json.dumps(key_diagnostic), encoding="utf-8")
            self.assertEqual(
                0,
                subprocess.run(
                    [control, "validate-collection-diagnostic", path],
                    check=False,
                    capture_output=True,
                ).returncode,
            )
            key_diagnostic["subject"] = "podman"
            path.write_text(json.dumps(key_diagnostic), encoding="utf-8")
            self.assertNotEqual(
                0,
                subprocess.run(
                    [control, "validate-collection-diagnostic", path],
                    check=False,
                    capture_output=True,
                ).returncode,
            )

    def test_fixture_identity_has_one_owner_and_rejects_digest_regression(self) -> None:
        contract = load_contract()
        preparation = PREPARATION.read_text(encoding="utf-8")
        collector = COLLECTOR.read_text(encoding="utf-8")
        expected = f"{contract.FIXTURE_REPOSITORY}@{contract.ARM_CHILD}"
        parent = f"{contract.FIXTURE_REPOSITORY}@sha256:" + "1" * 64
        realistic = json.dumps([parent, expected], separators=(",", ":"))
        self.assertEqual(
            contract.ARM_CHILD,
            contract.admit_fixture_repo_digests(realistic),
        )
        self.assertIn("--admit-fixture-repo-digests", preparation)
        self.assertNotIn("jq -e", preparation[preparation.index('current_phase="fixture"'):])
        self.assertNotIn("{{.Digest}}", collector)
        self.assertNotIn("{{.Digest}}", preparation)

        mutation = collector.replace("{{json .RepoDigests}}", "{{.Digest}}", 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / COLLECTOR.name
            path.write_text(mutation, encoding="utf-8")
            completed = subprocess.run(
                [VALIDATOR, "--collector", path],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("RepoDigests", completed.stderr)

    def test_realistic_fixture_representations_cover_closed_path(self) -> None:
        contract = load_contract()
        repository = contract.FIXTURE_REPOSITORY
        expected = f"{repository}@{contract.ARM_CHILD}"
        parent = f"{repository}@sha256:" + "1" * 64
        accepted = ([expected], [parent, expected], [expected, parent])
        rejected = (
            None,
            {},
            [],
            [parent],
            [expected, expected],
            [f"docker.io/library/other@{contract.ARM_CHILD}"],
            [f"{repository}@sha256:" + "f" * 63],
            [f"{repository}@sha256:{index:064x}" for index in range(9)],
        )
        for representation in accepted:
            with self.subTest(accepted=representation):
                raw = json.dumps(representation, separators=(",", ":"))
                fact = contract.normalize_fixture_repo_digests(raw)
                decision = contract.admit_fixture_identity(fact)
                document = contract.assemble_fixture_evidence(decision)
                contract.validate_fixture_evidence(document)
        for representation in rejected:
            with self.subTest(rejected=representation):
                raw = json.dumps(representation, separators=(",", ":"))
                with self.assertRaises(contract.ContractError):
                    fact = contract.normalize_fixture_repo_digests(raw)
                    contract.admit_fixture_identity(fact)

    def test_realistic_host_representations_cross_normalization_schema_and_validator(self) -> None:
        contract = load_contract()
        raw = self.realistic_raw(contract)
        document = contract.normalize_and_admit(raw, self.realistic_options())
        uppercase = json.loads(json.dumps(raw))
        uppercase_header = uppercase["packages"][0]["signed_header"].splitlines()
        uppercase_header[6] = uppercase_header[6].upper()
        uppercase_header[8] = uppercase_header[8].upper()
        uppercase_header[9] = uppercase_header[9][:-16] + uppercase_header[9][-16:].upper()
        uppercase["packages"][0]["signed_header"] = "\n".join(uppercase_header)
        uppercase_document = contract.normalize_and_admit(
            uppercase, self.realistic_options()
        )
        self.assertEqual("a" * 64, uppercase_document["packages"][0]["payload_digest"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preparation.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                0,
                subprocess.run(
                    [CONTROL, "validate-evidence", "preparation", path],
                    check=False,
                    capture_output=True,
                ).returncode,
            )

        representation_mutations = (
            ("os_release", 'ID="rocky"'),
            ("os_release", 'ID="rocky"\nID="rocky"\nVERSION_ID="10.2"'),
            ("repositories", "repo id repo name\nbaseos BaseOS\nbaseos Duplicate\nextras Extras"),
            ("subuid", "secpal-runtime:1048576:65536\nsecpal-runtime:1048576:65536"),
            ("podman_info", ""),
            ("podman_info", "[]"),
            ("podman_info", json.dumps({"host": {}, "store": {}})),
            (
                "podman_info",
                json.dumps(
                    {
                        "host": {
                            "security": [],
                            "ociRuntime": {"name": "crun"},
                            "serviceIsRemote": False,
                        },
                        "store": {
                            "graphRoot": "/home/secpal-runtime/.local/share/containers/storage"
                        },
                    }
                ),
            ),
            ("automatic_unit_statuses", []),
        )
        for key, value in representation_mutations:
            with self.subTest(key=key):
                candidate = dict(raw)
                candidate[key] = value
                with self.assertRaises((contract.ContractError, KeyError)):
                    contract.normalize_and_admit(candidate, self.realistic_options())

        wrong_package = json.loads(json.dumps(raw))
        wrong_package["packages"][0]["repositories"] = ["external"]
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(wrong_package, self.realistic_options())
        ambiguous_package = json.loads(json.dumps(raw))
        ambiguous_package["packages"][0]["repositories"] = [
            "appstream",
            "appstream",
        ]
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(ambiguous_package, self.realistic_options())
        unavailable_package = json.loads(json.dumps(raw))
        unavailable_package["packages"][0]["repositories"] = []
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(
                unavailable_package, self.realistic_options()
            )

        package_failures = {
            "wrong-nevra": {"signed_header": raw["packages"][0]["signed_header"].replace("podman-5.8.2-1.el10_2.aarch64", "podman-5.8.3-1.el10_2.aarch64", 1)},
            "wrong-signer": {"signed_header": raw["packages"][0]["signed_header"].replace("6fedfc85", "deadbeef")},
            "missing-signature": {"verification": "Header SHA256 digest: OK\nHeader SHA1 digest: OK"},
            "unknown-signer": {"verification": raw["packages"][0]["verification"].replace("6fedfc85", "deadbeef")},
            "bad-signature": {"verification": raw["packages"][0]["verification"].replace(": OK", ": BAD", 1)},
            "missing-payload": {"signed_header": "\n".join(raw["packages"][0]["signed_header"].splitlines()[:1] + [""] + raw["packages"][0]["signed_header"].splitlines()[2:])},
            "wrong-payload-algorithm": {"signed_header": raw["packages"][0]["signed_header"].replace("\n8\n", "\n1\n", 1)},
        }
        for name, changes in package_failures.items():
            with self.subTest(package_failure=name):
                candidate = json.loads(json.dumps(raw))
                candidate["packages"][0].update(changes)
                with self.assertRaises(contract.ContractError):
                    contract.normalize_and_admit(candidate, self.realistic_options())

        wrong_key = dict(raw)
        wrong_key["rocky_signing_key"] = "6fedfc85\n" + base64.b64encode(
            b"untrusted key packet"
        ).decode("ascii")
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(wrong_key, self.realistic_options())

        missing_history = json.loads(json.dumps(raw))
        for package in missing_history["packages"]:
            self.assertNotIn("from_repo", package)
        document_without_history = contract.normalize_and_admit(
            missing_history, self.realistic_options()
        )
        self.assertEqual(contract.ROCKY_FINGERPRINT, document_without_history["packages"][0]["signer_fingerprint"])

        # Current mirror payload bytes are intentionally absent. A same-NEVRA
        # republish is a temporal mirror fact, not evidence about the artifact
        # whose immutable signed header is installed and admitted here.
        for package in raw["packages"]:
            self.assertNotIn("downloaded_payload", package)
            self.assertNotIn("official_payload", package)

        malformed_key = dict(raw)
        malformed_key["rocky_signing_key"] = "6fedfc85\nnot-base64!"
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(malformed_key, self.realistic_options())

        security_inequivalent = json.loads(json.dumps(raw))
        security_inequivalent["podman_info"] = json.dumps(
            {
                "host": {
                    "security": {"rootless": False, "seccompEnabled": True},
                    "ociRuntime": {"name": "crun"},
                    "networkBackend": "netavark",
                    "serviceIsRemote": False,
                },
                "store": {
                    "graphRoot": "/home/secpal-runtime/.local/share/containers/storage"
                },
            }
        )
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(
                security_inequivalent, self.realistic_options()
            )

        automatic = dict(raw)
        automatic["automatic_unit_statuses"] = [0, 1, 1, 1]
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(automatic, self.realistic_options())
        rejected_document = json.loads(json.dumps(document))
        rejected_document["updates"]["automatic"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preparation.json"
            path.write_text(json.dumps(rejected_document), encoding="utf-8")
            self.assertNotEqual(
                0,
                subprocess.run(
                    [CONTROL, "validate-evidence", "preparation", path],
                    check=False,
                    capture_output=True,
                ).returncode,
            )

    def test_workflow_architecture_gate_precedes_provider_authentication(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        validate = workflow.index("jobs:\n  validate:")
        discover = workflow.index("\n  discover:", validate)
        validation_job = workflow[validate:discover]
        checkout = validation_job.index("Checkout trusted architecture gate from main")
        setup = validation_job.index("Set up reviewed architecture-gate Python")
        architecture = validation_job.index("Validate Rocky evidence architecture")
        closed_inputs = validation_job.index("Validate immutable inputs")
        self.assertLess(checkout, setup)
        self.assertLess(setup, architecture)
        self.assertLess(architecture, closed_inputs)
        self.assertIn('python-version: "3.12.13"', validation_job)
        self.assertIn("validate-rocky-evidence-architecture.py", validation_job)
        self.assertNotIn("id-token: write", validation_job)
        self.assertNotIn("google-github-actions/auth", validation_job)
        self.assertIn("needs: validate", workflow[discover:])


if __name__ == "__main__":
    unittest.main()
