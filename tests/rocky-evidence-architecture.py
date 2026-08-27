#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Architecture regressions for the layered Rocky host-evidence pipeline."""

from __future__ import annotations

import importlib.util
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
    @staticmethod
    def realistic_raw(contract):
        payload = "a" * 64
        packages = [
            {
                "name": name,
                "nevra": f"{name}-1-1.aarch64",
                "repositories": ["appstream"],
                "installed_payload": payload,
                "payload_count": 1,
                "signature": "digests signatures OK key ID 6fedfc85",
                "rocky_keys": contract.ROCKY_FINGERPRINT,
                "official_nevra": f"{name}-1-1.aarch64",
                "official_payload": payload,
            }
            for name in contract.PACKAGES
        ]
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
            "podman_info": json.dumps({"host": {"security": {"rootless": True, "seccompEnabled": True}, "ociRuntime": {"name": "crun"}, "networkBackend": "netavark", "remoteSocket": {"exists": False}}, "store": {"graphRoot": "/home/secpal-runtime/.local/share/containers/storage"}}),
            "graphroot": "/home/secpal-runtime/.local/share/containers/storage",
            "account_home": "/home/secpal-runtime",
            "fixture_repo_digests": json.dumps([expected]),
            "automatic_unit_statuses": [1, 1, 1, 1],
            "boot_id": "22222222-2222-2222-2222-222222222222",
            "meminfo": "MemTotal:       16000000 kB",
            "root_filesystem_bytes": 120000000000,
            "cpu_count": 4,
            "packages": packages,
            "container_configs": ["[engine]\nlabel=true"],
            "podman_version": "podman version 5.8.2",
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
            "operation": "verify-package-signature",
            "reason": "command-failed",
            "subject": "container-selinux",
        }
        rejected = (
            {**accepted, "operation": "run-command"},
            {**accepted, "reason": "arbitrary stderr"},
            {**accepted, "subject": "https://example.invalid/secret"},
            {**accepted, "stderr": "unbounded"},
            {"layer": "observation", "operation": "verify-package-signature", "reason": "command-failed"},
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
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preparation.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                0,
                subprocess.run(
                    [control, "validate-evidence", "preparation", path],
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
                            "remoteSocket": {"exists": False},
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

        wrong_package_type = json.loads(json.dumps(raw))
        wrong_package_type["packages"][0]["payload_count"] = "1"
        with self.assertRaises(contract.ContractError):
            contract.normalize_and_admit(
                wrong_package_type, self.realistic_options()
            )

        security_inequivalent = json.loads(json.dumps(raw))
        security_inequivalent["podman_info"] = json.dumps(
            {
                "host": {
                    "security": {"rootless": False, "seccompEnabled": True},
                    "ociRuntime": {"name": "crun"},
                    "networkBackend": "netavark",
                    "remoteSocket": {"exists": False},
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
                    [control, "validate-evidence", "preparation", path],
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
