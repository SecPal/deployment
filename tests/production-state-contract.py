#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for production persistence and secret handling."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "production" / "state-contract.yaml"
INVENTORY_PATH = ROOT / "config" / "production" / "inventory.example.yaml"
RENDERER_PATH = ROOT / "scripts" / "render-production-quadlets.py"
STATE_TOOL_PATH = ROOT / "scripts" / "production-state.py"
BOOTSTRAP_PATH = ROOT / "scripts" / "production-secret-bootstrap.php"
POSTGRES_LAUNCHER_PATH = ROOT / "scripts" / "production-postgres-entrypoint.sh"
VALKEY_LAUNCHER_PATH = ROOT / "scripts" / "production-valkey-entrypoint.sh"
CHECKED_QUADLETS = ROOT / "config" / "production" / "quadlet"
CHECKED_SYSTEMD = ROOT / "config" / "production" / "systemd"
POSTGRES_IMAGE = "docker.io/library/postgres@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74"
VALKEY_IMAGE = "docker.io/valkey/valkey@sha256:3acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd"

EXPECTED_OBJECTS = {
    "postgresql_data",
    "private_application_storage",
    "public_application_storage",
    "app_key",
    "app_previous_keys",
    "tenant_kek",
    "postgresql_credentials",
    "valkey_credentials",
    "external_service_credentials",
    "valkey_state",
    "acme_state",
    "crowdsec_state",
    "logs",
    "configuration",
    "deployment_state",
    "backup_encryption_credentials",
    "tls_private_keys",
    "operator_ssh_credentials",
    "github_credentials",
    "registry_credentials",
}
API_ROLES = {"api", "migrate", "scheduler", "worker-general", "worker-hash-chain"}
SECRET_SENTINELS = {
    "app-key": "base64:U0VDUEFMX0ZBS0VfQVBQX0tFWV8wMDAwMDAwMDA=",
    "app-previous-keys": "base64:U0VDUEFMX0ZBS0VfT0xEX0tFWV8wMDAwMDAwMDA=",
    "postgres-password": "SECPAL_FAKE_POSTGRES_PASSWORD_4ec96de8",
    "valkey-password": "SECPAL_FAKE_VALKEY_PASSWORD_f7967389",
}


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ProductionStateContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.state = load_module(STATE_TOOL_PATH, "production_state")
        cls.renderer = load_module(RENDERER_PATH, "render_production_quadlets")
        cls.contract = cls.state.load_contract(CONTRACT_PATH)

    def test_canonical_matrix_is_closed_and_complete(self) -> None:
        self.assertEqual(set(self.contract["objects"]), EXPECTED_OBJECTS)
        required = {
            "authority",
            "durability",
            "reconstructable",
            "loss_acceptable",
            "restore_required",
            "backup",
            "confidentiality",
            "integrity",
            "location",
            "consumers",
            "container_identity",
            "host_ownership",
            "type",
            "owner",
            "group",
            "mode",
            "acl",
            "initialization_authority",
            "rotation_migration_authority",
            "destruction_authority",
        }
        for name, row in self.contract["objects"].items():
            with self.subTest(name=name):
                self.assertEqual(set(row), required)

    def test_business_critical_recovery_boundary_and_public_decision(self) -> None:
        for name in (
            "postgresql_data",
            "private_application_storage",
            "public_application_storage",
        ):
            row = self.contract["objects"][name]
            with self.subTest(name=name):
                self.assertEqual(row["durability"], "durable")
                self.assertFalse(row["reconstructable"])
                self.assertFalse(row["loss_acceptable"])
                self.assertTrue(row["restore_required"])
                self.assertEqual(row["backup"], "required-d7")

    def test_rootless_mapping_is_deterministic_and_not_host_identity_equality(self) -> None:
        identity = self.contract["rootless_mapping"]
        expected_uids = {0: 20000, 101: 100100, 999: 100998, 10001: 110000, 10002: 110001}
        expected_gids = {0: 20000, 101: 200100, 999: 200998, 10001: 210000, 10002: 210001}
        for container_id, host_id in expected_uids.items():
            with self.subTest(kind="uid", container_id=container_id):
                self.assertEqual(self.state.map_rootless_id(container_id, identity, "uid"), host_id)
        for container_id, host_id in expected_gids.items():
            with self.subTest(kind="gid", container_id=container_id):
                self.assertEqual(self.state.map_rootless_id(container_id, identity, "gid"), host_id)
        self.assertEqual(self.state.map_rootless_id(65536, identity, "uid"), 165535)
        for invalid in (-1, 65537, True, "10001"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.state.ContractError):
                    self.state.map_rootless_id(invalid, identity, "uid")

    def test_inventory_is_mechanically_tied_to_the_canonical_state_contract(self) -> None:
        inventory = yaml.safe_load(INVENTORY_PATH.read_text(encoding="utf-8"))
        mapping = self.contract["rootless_mapping"]
        account = inventory["service_account"]
        self.assertEqual(mapping["service_uid"], account["uid"])
        self.assertEqual(mapping["service_gid"], account["gid"])
        self.assertEqual(mapping["uid_start"], account["subordinate_ids"]["uid"]["start"])
        self.assertEqual(mapping["gid_start"], account["subordinate_ids"]["gid"]["start"])
        self.assertEqual(mapping["count"], account["subordinate_ids"]["uid"]["count"])
        self.assertEqual(mapping["count"], account["subordinate_ids"]["gid"]["count"])
        rows = {
            "postgresql_data": "postgresql_data",
            "private_application_storage": "private_application_storage",
            "public_application_storage": "public_application_storage",
            "valkey_state": "valkey_data",
            "logs": "logs",
            "configuration": "configuration",
            "deployment_state": "deployment_state",
        }
        for object_name, inventory_name in rows.items():
            with self.subTest(object_name=object_name):
                row = self.contract["objects"][object_name]
                path = inventory["paths"][inventory_name]
                self.assertEqual(path["path"], row["location"])
                self.assertEqual(path["mode"], row["mode"])
        for inventory_name, container_id in {
            "postgresql_data": 999,
            "private_application_storage": 10001,
            "public_application_storage": 10001,
            "valkey_data": 10002,
        }.items():
            with self.subTest(inventory_name=inventory_name):
                path = inventory["paths"][inventory_name]
                self.assertEqual(path["container_uid"], container_id)
                self.assertEqual(path["container_gid"], container_id)
                self.assertEqual(
                    path["uid"], self.state.map_rootless_id(container_id, mapping, "uid")
                )
                self.assertEqual(
                    path["gid"], self.state.map_rootless_id(container_id, mapping, "gid")
                )

    def test_secret_contract_is_file_scoped_and_least_authority(self) -> None:
        objects = self.contract["objects"]
        self.assertEqual(objects["tenant_kek"]["type"], "raw-32-byte-file")
        self.assertEqual(objects["tenant_kek"]["mode"], "0600")
        self.assertEqual(set(objects["tenant_kek"]["consumers"]), API_ROLES)
        self.assertEqual(objects["app_previous_keys"]["type"], "bounded-key-list-file")
        self.assertEqual(self.contract["secret_policy"]["max_previous_keys"], 3)
        self.assertEqual(objects["postgresql_credentials"]["consumers"], ["api-roles", "postgres"])
        self.assertEqual(objects["valkey_credentials"]["consumers"], ["api-roles", "valkey"])
        for name in (
            "backup_encryption_credentials",
            "tls_private_keys",
            "operator_ssh_credentials",
            "github_credentials",
            "registry_credentials",
        ):
            with self.subTest(name=name):
                self.assertEqual(objects[name]["consumers"], [])
                self.assertTrue(objects[name]["location"].startswith("external-authority://"))

    def test_checked_quadlets_equal_renderer_and_have_exact_mounts(self) -> None:
        rendered = self.renderer.build_units(self.contract)
        checked = {}
        for directory in (CHECKED_QUADLETS, CHECKED_SYSTEMD):
            checked.update(
                {
                    path.name: path.read_text(encoding="utf-8")
                    for path in directory.iterdir()
                    if path.is_file()
                }
            )
        self.assertEqual(checked, rendered)
        self.assertFalse(any(path.suffix in {".service", ".target"} for path in CHECKED_QUADLETS.iterdir()))
        self.assertTrue(all(path.suffix in {".service", ".target"} for path in CHECKED_SYSTEMD.iterdir()))
        combined = "\n".join(rendered.values())
        self.assertNotRegex(combined, r"(?i)docker(?:-compose| compose)|podman(?:-compose| compose)")
        self.assertNotIn("Network=host", combined)
        self.assertNotRegex(combined, r"(?i)(podman|docker)\.sock|tcp://")
        self.assertNotIn("AutoUpdate=", combined)
        self.assertNotIn("latest", combined)
        self.assertNotIn("EnvironmentFile=", combined)
        self.assertIn("Pull=never", combined)
        self.assertIn("source=/srv/secpal/postgresql,target=/var/lib/postgresql/data,rw=true", combined)
        self.assertIn("source=/srv/secpal/valkey,target=/data,rw=true", combined)
        for role in API_ROLES:
            unit = rendered[f"secpal-{role}.container"]
            self.assertIn("source=/srv/secpal/private-storage,target=/app/storage/app/private,rw=true", unit)
            self.assertIn("source=/srv/secpal/public-storage,target=/app/storage/app/public,rw=true", unit)
            self.assertIn("/run/secpal/secrets/api/app-key", unit)
            self.assertIn("/run/secpal/secrets/api/tenant-kek", unit)
        self.assertNotIn("/run/secpal/secrets/postgres/", rendered["secpal-valkey.container"])
        self.assertNotIn("/run/secpal/secrets/valkey/", rendered["secpal-postgres.container"])
        self.assertNotIn("/run/secpal/secrets", rendered["secpal-frontend.container"])
        logs = self.contract["log_policy"]
        container_units = {
            name: text
            for name, text in rendered.items()
            if name.endswith(".container")
        }
        for unit_name, text in container_units.items():
            container_name = unit_name.removesuffix(".container")
            filename = logs["file_name"].format(container_name=container_name)
            with self.subTest(container_name=container_name):
                self.assertIn(f"LogDriver={logs['driver']}", text)
                self.assertIn(f"LogOpt=path={logs['directory']}/{filename}", text)
                self.assertIn(f"LogOpt=max-size={logs['maximum_file_size']}", text)
                self.assertNotIn(f"source={logs['directory']}", text)

    def test_secret_values_never_enter_rendered_or_runtime_metadata(self) -> None:
        rendered = "\n".join(self.renderer.build_units(self.contract).values())
        simulated_surfaces = "\n".join(
            (
                rendered,
                "ExecStart=/usr/bin/podman run --name secpal-api --pull=never",
                "Environment=APP_ENV=production DB_HOST=postgres REDIS_HOST=valkey",
                "secpal state contract validated\nsecpal-api started",
            )
        )
        for name, sentinel in SECRET_SENTINELS.items():
            with self.subTest(name=name, digest=hashlib.sha256(sentinel.encode()).hexdigest()[:12]):
                self.assertNotIn(sentinel, simulated_surfaces)
        bootstrap = BOOTSTRAP_PATH.read_text(encoding="utf-8")
        self.assertNotIn("putenv", bootstrap)
        self.assertNotIn("getenv", bootstrap)

    def test_postgres_secret_is_confined_to_the_explicit_initializer(self) -> None:
        rendered = self.renderer.build_units(self.contract)
        initializer = rendered["secpal-postgres-init.container"]
        server = rendered["secpal-postgres.container"]
        self.assertIn("Exec=initialize", initializer)
        self.assertIn("/run/secpal/secrets/postgres/password", initializer)
        self.assertIn("production-postgres-entrypoint.sh", initializer)
        self.assertIn("Exec=run", server)
        self.assertIn("production-postgres-entrypoint.sh", server)
        self.assertNotIn("POSTGRES_PASSWORD", server)
        self.assertNotIn("/run/secpal/secrets/postgres", server)
        if subprocess.run(["podman", "image", "exists", POSTGRES_IMAGE], check=False).returncode != 0:
            self.skipTest("the reviewed PostgreSQL image is not locally staged")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.mkdir(mode=0o700)
            password = root / "password"
            password.write_text("SecPalFakePostgresCredential1234\n", encoding="utf-8")
            password.chmod(0o400)
            subprocess.run(
                [
                    "podman",
                    "unshare",
                    "chown",
                    "-R",
                    "999:999",
                    os.fspath(data),
                    os.fspath(password),
                ],
                check=True,
            )
            container_name = f"secpal-postgres-contract-{os.getpid()}"
            mounts = [
                "--mount",
                f"type=bind,source={POSTGRES_LAUNCHER_PATH},destination=/run/secpal/bootstrap/production-postgres-entrypoint.sh,ro=true",
                "--mount",
                f"type=bind,source={data},destination=/var/lib/postgresql/data,rw=true",
                "--mount",
                "type=tmpfs,destination=/tmp,tmpfs-mode=0700,U=true",
                "--mount",
                "type=tmpfs,destination=/run/postgresql,tmpfs-mode=0750,U=true",
            ]
            initializer_mounts = [
                *mounts,
                "--mount",
                f"type=bind,source={password},destination=/run/secpal-secret/password,ro=true",
            ]
            base = [
                "podman",
                "run",
                "--network",
                "none",
                "--user",
                "999:999",
                "--read-only",
                "--entrypoint",
                "/bin/sh",
            ]
            try:
                for _attempt in range(2):
                    result = subprocess.run(
                        [
                            *base,
                            "--rm",
                            *initializer_mounts,
                            POSTGRES_IMAGE,
                            "/run/secpal/bootstrap/production-postgres-entrypoint.sh",
                            "initialize",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                subprocess.run(
                    [
                        *base,
                        "--detach",
                        "--name",
                        container_name,
                        *mounts,
                        POSTGRES_IMAGE,
                        "/run/secpal/bootstrap/production-postgres-entrypoint.sh",
                        "run",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    ready = subprocess.run(
                        [
                            "podman",
                            "exec",
                            container_name,
                            "pg_isready",
                            "-h",
                            "/run/postgresql",
                            "-U",
                            "secpal",
                            "-d",
                            "secpal",
                        ],
                        capture_output=True,
                        check=False,
                    )
                    if ready.returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("the pinned PostgreSQL image did not become ready")
                database = subprocess.run(
                    [
                        "podman",
                        "exec",
                        container_name,
                        "psql",
                        "-h",
                        "/run/postgresql",
                        "-U",
                        "secpal",
                        "-d",
                        "secpal",
                        "-Atqc",
                        "SELECT current_database()",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(database.stdout.strip(), "secpal")
                environment = subprocess.run(
                    [
                        "podman",
                        "exec",
                        container_name,
                        "/bin/sh",
                        "-c",
                        "tr '\\000' '\\n' </proc/1/environ | "
                        "grep -Eq '^(POSTGRES_PASSWORD|POSTGRES_PASSWORD_FILE|PGPASSWORD)='",
                    ],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(environment.returncode, 1)
            finally:
                subprocess.run(
                    ["podman", "rm", "--force", container_name],
                    capture_output=True,
                    check=False,
                )
                subprocess.run(
                    [
                        "podman",
                        "unshare",
                        "chown",
                        "-R",
                        "0:0",
                        os.fspath(data),
                        os.fspath(password),
                    ],
                    check=True,
                )

    def test_pinned_valkey_launcher_accepts_the_canonical_password_grammar(self) -> None:
        if subprocess.run(["podman", "image", "exists", VALKEY_IMAGE], check=False).returncode != 0:
            self.skipTest("the reviewed Valkey image is not locally staged")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password = root / "password"
            password.write_text("SecPalFake$And&Star*Credential1234\n", encoding="utf-8")
            password.chmod(0o400)
            fake_server = root / "valkey-server"
            fake_server.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "test \"$#\" -eq 1\n"
                "test \"$(stat -c %a \"$1\")\" = 600\n"
                "test \"$(wc -l <\"$1\")\" -eq 5\n"
                "grep -Eq '^requirepass .{24,128}$' \"$1\"\n"
                "grep -Fx 'dir /data' \"$1\" >/dev/null\n"
                "grep -Fx 'appendonly yes' \"$1\" >/dev/null\n"
                "grep -Fx 'appendfsync everysec' \"$1\" >/dev/null\n"
                "grep -Fx 'save \"\"' \"$1\" >/dev/null\n",
                encoding="utf-8",
            )
            fake_server.chmod(0o755)
            subprocess.run(
                ["podman", "unshare", "chown", "10002:10002", os.fspath(password)],
                check=True,
            )
            try:
                result = subprocess.run(
                    [
                        "podman",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--user",
                        "10002:10002",
                        "--read-only",
                        "--mount",
                        "type=tmpfs,destination=/tmp,tmpfs-mode=0700,U=true",
                        "--volume",
                        f"{VALKEY_LAUNCHER_PATH}:/run/secpal/bootstrap/production-valkey-entrypoint.sh:ro",
                        "--volume",
                        f"{password}:/run/secpal-secret/password:ro",
                        "--volume",
                        f"{fake_server}:/usr/local/bin/valkey-server:ro",
                        "--entrypoint",
                        "/bin/sh",
                        VALKEY_IMAGE,
                        "/run/secpal/bootstrap/production-valkey-entrypoint.sh",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                subprocess.run(
                    ["podman", "unshare", "chown", "0:0", os.fspath(password)],
                    check=True,
                )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_state_initializer_is_idempotent_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.state.initialize_fixture(self.contract, root)
            marker = root / "srv/secpal/private-storage/proof"
            marker.write_text("preserve", encoding="utf-8")
            before = marker.stat()
            self.state.initialize_fixture(self.contract, root)
            after = marker.stat()
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")
            self.assertEqual(before.st_ino, after.st_ino)

            target = root / "srv/secpal/target"
            target.mkdir()
            private = root / "srv/secpal/private-storage"
            private.rename(root / "srv/secpal/private-storage-real")
            private.symlink_to(target, target_is_directory=True)
            with self.assertRaises(self.state.ContractError):
                self.state.validate_fixture(self.contract, root)

    def test_modes_acls_types_links_and_owners_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.state.initialize_fixture(self.contract, root)
            private = root / "srv/secpal/private-storage"
            private.chmod(0o770)
            with self.assertRaises(self.state.ContractError):
                self.state.validate_fixture(self.contract, root)
            private.chmod(0o750)

            if subprocess.run(["setfacl", "-m", "u:12345:rwx", private], check=False).returncode == 0:
                with self.assertRaises(self.state.ContractError):
                    self.state.validate_fixture(self.contract, root)
                subprocess.run(["setfacl", "-b", private], check=True)

            ordinary = root / "owner-proof"
            ordinary.write_text("metadata", encoding="utf-8")
            with self.assertRaises(self.state.ContractError):
                self.state._assert_owner(ordinary, os.getuid() + 1, os.getgid())
            with self.assertRaises(self.state.ContractError):
                self.state._assert_owner(ordinary, os.getuid(), os.getgid() + 1)

            secret = root / "secret"
            secret.write_text("s" * 32, encoding="utf-8")
            secret.chmod(0o400)
            hardlink = root / "secret-link"
            os.link(secret, hardlink)
            with self.assertRaises(self.state.ContractError):
                self.state._assert_safe_component(secret, False, 0o400)

            with mock.patch.object(
                self.state.Path,
                "resolve",
                side_effect=self.state.ContractError("canonical path mismatch"),
            ):
                with self.assertRaises(self.state.ContractError):
                    self.state.validate_fixture(self.contract, root)

    def test_secret_validation_rejects_partial_and_malformed_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.state.initialize_fixture(self.contract, root)
            secret_root = root / "run/secpal/secrets"
            (secret_root / "api/app-key").write_text("invalid\n", encoding="utf-8")
            with self.assertRaises(self.state.ContractError):
                self.state.validate_fixture(self.contract, root, require_secrets=True)

            (secret_root / "api/app-key").unlink()
            with self.assertRaises(self.state.ContractError):
                self.state.validate_fixture(self.contract, root, require_secrets=True)

    def test_atomic_secret_publication_cleans_interruption_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination_parent = root / "run/secpal"
            destination = destination_parent / "secrets"
            destination_parent.mkdir(parents=True)
            values = {
                "api/app-key": b"base64:" + b"A" * 43 + b"=\n",
                "api/app-previous-keys": b"",
                "api/tenant-kek": b"K" * 32,
                "api/postgres-password": b"p" * 64 + b"\n",
                "api/valkey-password": b"v" * 64 + b"\n",
                "postgres/password": b"p" * 64 + b"\n",
                "valkey/password": b"v" * 64 + b"\n",
            }
            modes = {
                "api/tenant-kek": 0o600,
                **{name: 0o400 for name in values if name != "api/tenant-kek"},
            }
            for name, value in values.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
                path.chmod(modes[name])
            with self.assertRaises(self.state.ContractError):
                self.state.publish_initial_secret_tree(
                    self.contract,
                    source,
                    destination,
                    fixture=True,
                    interrupt_after=2,
                )
            self.assertFalse(destination.exists())
            self.assertEqual(list(destination_parent.glob(".secpal-secrets.*")), [])

            self.state.publish_initial_secret_tree(
                self.contract, source, destination, fixture=True
            )
            before = (destination / "api/app-key").read_bytes()
            with self.assertRaises(self.state.ContractError):
                self.state.publish_initial_secret_tree(
                    self.contract, source, destination, fixture=True
                )
            self.assertEqual((destination / "api/app-key").read_bytes(), before)

    def test_lifecycle_model_preserves_state_across_native_recreation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.state.initialize_fixture(self.contract, root)
            evidence = self.state.prove_fixture_lifecycle(self.contract, root)
            self.assertEqual(
                evidence,
                [
                    "initialize",
                    "quadlet-generate",
                    "systemd-user-start",
                    "roles-start",
                    "systemd-user-stop",
                    "systemd-user-restart",
                    "container-recreate",
                    "state-preserved",
                    "metadata-preserved",
                    "fixture-cleanup-bounded",
                ],
            )

    def test_php_bootstrap_keeps_values_out_of_os_environment(self) -> None:
        if subprocess.run(["php", "-v"], capture_output=True, check=False).returncode != 0:
            self.skipTest("php is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app_key = "base64:" + "A" * 43 + "="
            previous_key = "base64:" + "B" * 43 + "="
            values = {
                "app-key": app_key + "\n",
                "app-previous-keys": previous_key + "\n",
                "postgres-password": "a" * 64 + "\n",
                "valkey-password": "b" * 64 + "\n",
            }
            for name, value in values.items():
                path = root / name
                path.write_text(value, encoding="utf-8")
                path.chmod(0o400)
            kek = root / "tenant-kek"
            kek.write_bytes(b"K" * 32)
            kek.chmod(0o600)
            probe = root / "probe.php"
            probe.write_text(
                "<?php require $argv[1]; "
                "$ok = isset($_ENV['APP_KEY'], $_SERVER['DB_PASSWORD']) "
                "&& getenv('APP_KEY') === false && getenv('DB_PASSWORD') === false; "
                "exit($ok ? 0 : 1);\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["SECPAL_SECRET_ROOT"] = str(root)
            result = subprocess.run(
                ["php", os.fspath(probe), os.fspath(BOOTSTRAP_PATH)],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_live_php_process_arguments_environment_and_logs_do_not_leak(self) -> None:
        if subprocess.run(["php", "-v"], capture_output=True, check=False).returncode != 0:
            self.skipTest("php is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinels = {
                "app-key": "base64:" + "C" * 43 + "=",
                "app-previous-keys": "base64:" + "D" * 43 + "=",
                "postgres-password": "SECPAL_FAKE_POSTGRES_PASSWORD_4ec96de8",
                "valkey-password": "SECPAL_FAKE_VALKEY_PASSWORD_f7967389",
            }
            for name, value in sentinels.items():
                path = root / name
                path.write_text(value + "\n", encoding="utf-8")
                path.chmod(0o400)
            kek = root / "tenant-kek"
            kek.write_bytes(b"Z" * 32)
            kek.chmod(0o600)
            ready = root / "ready"
            probe = root / "sleeping-probe.php"
            probe.write_text(
                "<?php require $argv[1]; file_put_contents($argv[2], 'ready'); usleep(750000);\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["SECPAL_SECRET_ROOT"] = str(root)
            process = subprocess.Popen(
                ["php", os.fspath(probe), os.fspath(BOOTSTRAP_PATH), os.fspath(ready)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 2
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "PHP secret probe did not become ready")
                environment_surface = Path(f"/proc/{process.pid}/environ").read_bytes()
                argument_surface = Path(f"/proc/{process.pid}/cmdline").read_bytes()
                stdout, stderr = process.communicate(timeout=3)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)
            surfaces = (environment_surface, argument_surface, stdout, stderr)
            for name, sentinel in sentinels.items():
                with self.subTest(name=name):
                    encoded = sentinel.encode()
                    self.assertTrue(all(encoded not in surface for surface in surfaces))


if __name__ == "__main__":
    unittest.main()
