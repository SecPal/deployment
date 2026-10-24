#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Source-level installation contracts; never native host acceptance."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("standard_installation", ROOT / "scripts/standard-installation.py")
phase = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phase)


class FixtureNative(phase.Native):
    """In-memory OS commands + real isolated filesystem; not native acceptance."""

    def __init__(self, root, desired):
        super().__init__(root, owner=(os.getuid(), os.getgid()))
        self.desired = desired
        self.installed = False
        self.has_account = False
        self.has_subids = False
        self.manager = False
        self.firewall = False
        self.label_rule = False
        self.storage_labeled = False
        self.nft_enabled = False
        self.nft_active = False
        self.masks = set()
        self.commands = []

    def platform(self, desired):
        phase.admit_platform("ID=rocky\nVERSION_ID=10.2\n", "x86_64", "Enforcing", desired["inventory"])
        self.no_authority(desired)

    def directory(self, name, uid=0, gid=0, mode=0o755, *, create=True):
        if uid:
            uid = self.owner[0]
        if gid:
            gid = self.owner[1]
        return super().directory(name, uid, gid, mode, create=create)

    def account(self, desired, *, install=False):
        if not self.has_account:
            if not install:
                raise phase.Error("missing-runtime-account")
            self.has_account = True
            self.changes += 1

    def subids(self, desired, *, install=False):
        if not self.has_subids:
            if not install:
                raise phase.Error("missing-subids")
            self.has_subids = True
            self.changes += 1

    def packages(self, desired):
        return [{"name": "podman", "version": "5.8.2"}]

    def run(self, operation, arguments, *, user=None, accepted=(0,), timeout=60):
        self.commands.append(tuple(arguments))
        executable = arguments[0]
        if executable == "rpm":
            if "--qf" in arguments:
                name = arguments[-1]
                expected = next(item for item in self.desired["packages"]
                                if phase.re.fullmatch(phase.re.escape(name) + r"-[0-9].*", item))
                return 0, expected
            return (0, "installed") if self.installed else (1, "not installed")
        if executable == "dnf4":
            self.installed = True
            return 0, ""
        if executable == "loginctl":
            path = self.path("/var/lib/systemd/linger/" + arguments[-1])
            self.directory("/var/lib/systemd/linger")
            path.touch()
            return 0, ""
        if executable == "systemctl":
            key = (user, arguments[-1])
            if "mask" in arguments:
                self.masks.add(key)
                return 0, ""
            if "is-enabled" in arguments:
                if arguments[-1] == "nftables.service":
                    return (0, "enabled") if self.nft_enabled else (1, "disabled")
                return (0, "masked") if key in self.masks else ((0, "static") if arguments[-1] == "podman.service" else (1, "disabled"))
            if "is-active" in arguments:
                active = self.manager if arguments[-1].startswith("user@") else (
                    self.nft_active if arguments[-1] == "nftables.service" else False)
                return (0, "active") if active else (3, "inactive")
            if "enable" in arguments:
                self.nft_enabled = True
            if "start" in arguments:
                if arguments[-1] == "nftables.service":
                    self.nft_active = True
                else:
                    self.manager = True
            return 0, ""
        if executable == "python3":
            if arguments[-1] == "--apply":
                self.firewall = True
                return 0, ""
            return (0, "") if self.firewall else (1, "no accepted policy")
        if executable == "podman":
            if arguments[1] == "ps":
                return 0, ""
            return 0, phase.json.dumps({
                "host": {"security": {"rootless": True, "seccompEnabled": True},
                         "ociRuntime": {"name": "crun"}, "networkBackend": "netavark",
                         "serviceIsRemote": False},
                "store": {"graphRoot": self.desired["inventory"]["paths"]["podman_graph_root"]["path"]}})
        if executable == "semanage":
            if arguments[1] == "export":
                return 0, "boolean -D\nfcontext -D\n" + (
                    "fcontext -a -e /var/lib/containers/storage "
                    + self.desired["inventory"]["paths"]["podman_graph_root"]["path"]
                    if self.label_rule else "")
            self.label_rule = True
            return 0, ""
        if executable == "matchpathcon":
            return (0, "verified") if self.storage_labeled else (1, "incorrect label")
        if executable == "restorecon":
            self.storage_labeled = True
            return 0, ""
        if executable == "haproxy":
            return 0, ""
        raise AssertionError(("unexpected fixture operation", operation, arguments))


class InstallationContract(unittest.TestCase):
    def setUp(self):
        self.inventory = phase.inventory_owner.read_document(
            ROOT / "config/production/inventory.example.yaml", "inventory")
        self.firewall = {"edge_mode": "DIRECT", "management_ipv4": ["192.0.2.0/24"],
                         "management_ipv6": [], "dhcp_interfaces": ["eth0"]}

    def plan(self):
        # Only canonical documentation fixtures may use synthetic inventory admission.
        return phase.plan(self.inventory, self.firewall, synthetic=True)

    def test_public_plan_reuses_postgresql_renderer_and_has_no_state_authority(self):
        plan = self.plan()
        pg = phase.postgresql.render_configuration(phase.postgresql.DECLARATION, 20000)
        self.assertEqual(plan["files"]["/etc/secpal/host-base/postgresql.conf"], pg["postgresql.conf"])
        self.assertEqual(plan["files"]["/etc/secpal/host-base/pg_hba.conf"], pg["pg_hba.conf"])
        self.assertEqual(plan["files"]["/etc/secpal/host-base/loopback.nft"], pg["loopback.nft"])
        self.assertFalse(any("roles.sql" in name for name in plan["files"]))
        self.assertFalse(any("CREATE ROLE" in text or "CREATE DATABASE" in text
                             for text in plan["files"].values()))
        storage = tomllib.loads(plan["files"]["/var/lib/secpal/.config/containers/storage.conf"])
        self.assertEqual(storage["storage"]["graphroot"],
                         self.inventory["paths"]["podman_graph_root"]["path"])
        self.assertNotIn("image", plan)
        self.assertFalse(any("ghcr.io/" in text for text in plan["files"].values()))
        self.assertIn("postgresql18-server-18.6-1.el10_2.x86_64", plan["packages"])
        self.assertIn("/etc/containers/systemd/users/20000", plan["directories"])
        self.assertFalse(any(name.endswith(".container") for name in plan["files"]))

    def test_direct_configuration_is_preview_only_and_loopback_only(self):
        plan = self.plan()
        text = plan["files"]["/etc/secpal/host-base/haproxy.cfg"]
        self.assertIn("127.0.0.1:18085", text)
        self.assertNotIn("0.0.0.0", text)
        self.assertNotIn("crt ", text)
        self.assertFalse(any(name.startswith("/etc/haproxy/") for name in plan["files"]))

    def test_existing_firewall_policy_and_persistence_are_used_exactly(self):
        plan = self.plan()
        self.assertEqual(plan["files"]["/etc/systemd/system/nftables.service.d/secpal-host.conf"],
                         (ROOT / "config/production/host-systemd/nftables.service.d/secpal-host.conf").read_text())
        self.assertEqual(plan["files"]["/usr/local/libexec/secpal/host-firewall"],
                         (ROOT / "scripts/host-firewall.py").read_text())

    def test_both_architectures_use_canonical_package_pins(self):
        self.inventory["host"]["architecture"] = "arm64"
        plan = self.plan()
        self.assertIn("postgresql18-server-18.6-1.el10_2.aarch64", plan["packages"])
        self.assertIn("haproxy-3.0.5-6.el10_2.2.aarch64", plan["packages"])

    def test_conflicting_configuration_and_secret_inputs_are_rejected(self):
        for change in ("uid", "edge", "secret", "unknown"):
            with self.subTest(change=change):
                inv, fw = copy.deepcopy(self.inventory), copy.deepcopy(self.firewall)
                if change == "uid":
                    inv["service_account"]["subordinate_ids"]["uid"]["start"] = 20000
                elif change == "edge":
                    fw["edge_mode"] = "PROTECTED"
                elif change == "secret":
                    inv["DB_PASSWORD"] = "fixture-only-value"
                else:
                    fw["allow_all"] = True
                with self.assertRaises((phase.Error, ValueError, phase.inventory_owner.ContractViolation)):
                    phase.plan(inv, fw, synthetic=True)

    def test_wrong_host_and_disabled_selinux_fail_canonical_host_boundary(self):
        for release, architecture, enforcing in (
                ("ID=debian\nVERSION_ID=13", "x86_64", "Enforcing"),
                ("ID=rocky\nVERSION_ID=10.1", "x86_64", "Enforcing"),
                ("ID=rocky\nVERSION_ID=10.2", "s390x", "Enforcing"),
                ("ID=rocky\nVERSION_ID=10.2", "x86_64", "Permissive")):
            with self.subTest(release=release, architecture=architecture, enforcing=enforcing):
                with self.assertRaises(phase.Error):
                    phase.admit_platform(release, architecture, enforcing, self.inventory)

    def test_public_file_first_install_repeat_and_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            system = phase.Native(Path(directory), owner=(os.getuid(), os.getgid()))
            self.assertTrue(system.publish("/etc/secpal/base.conf", "public\n"))
            target = Path(directory) / "etc/secpal/base.conf"
            original = target.stat()
            self.assertFalse(system.publish("/etc/secpal/base.conf", "public\n"))
            self.assertEqual(target.stat().st_mtime_ns, original.st_mtime_ns)
            self.assertEqual(target.stat().st_ino, original.st_ino)
            with self.assertRaisesRegex(phase.Error, "public-file-conflict"):
                system.publish("/etc/secpal/base.conf", "different\n")
            self.assertEqual(target.read_text(), "public\n")

    def test_public_file_symlink_and_writable_ancestry_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            system = phase.Native(Path(directory), owner=(os.getuid(), os.getgid()))
            root = Path(directory)
            (root / "outside").mkdir()
            (root / "etc").symlink_to(root / "outside", target_is_directory=True)
            with self.assertRaises(phase.Error):
                system.publish("/etc/base.conf", "public\n")
            (root / "etc").unlink()
            (root / "etc").mkdir(mode=0o777)
            (root / "etc").chmod(0o777)
            with self.assertRaises(phase.Error):
                system.publish("/etc/base.conf", "public\n")

    def test_secret_or_enrollment_state_is_rejected_without_reading_contents(self):
        plan = self.plan()
        for name in ("/run/secpal/secrets", "/srv/secpal/deployment-state",
                     "/var/lib/pgsql/data", "/etc/secpal/enrollment"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                system = phase.Native(Path(directory), owner=(os.getuid(), os.getgid()))
                target = Path(directory) / name.lstrip("/")
                target.mkdir(parents=True)
                (target / "existing-authority").write_text("must-not-be-read")
                with self.assertRaisesRegex(phase.Error, "premature-authority"):
                    system.no_authority(plan)
        with patch.dict(os.environ, {"APP_KEY": "fixture-only-value"}):
            with self.assertRaisesRegex(phase.Error, "secret-environment"):
                phase.admit_environment()

    def test_missing_raw_unknown_review_or_expired_admission_never_grants_readiness(self):
        system = unittest.mock.Mock()
        plan = self.plan()
        # Raw policy JSON is not authenticated authority, even with plausible fields.
        values = [None, True, {}, {"gate_state": "CLEAN"},
                  {"gate_state": "REVIEW_REQUIRED"},
                  {"admission": "ADMITTED", "expires_at": "2000-01-01T00:00:00Z"}]
        with patch.object(phase, "verify_public_base"):
            for value in values:
                with self.subTest(value=value):
                    with self.assertRaises(phase.Error):
                        phase.admit_for_enrollment(system, plan, conformance=lambda: None,
                                                   artifacts=value)
            for value in values:
                if value is None:
                    continue
                with self.assertRaises(phase.Error):
                    phase.admit_for_enrollment(system, plan, conformance=lambda: None,
                                               artifacts=lambda: value)
            with self.assertRaises(phase.Error):
                phase.admit_for_enrollment(system, plan, conformance=None, artifacts=lambda: None)

    def test_root_path_authority_agrees_with_existing_firewall_owner(self):
        helper = phase.owner("_phase_one_firewall_agreement", "scripts/host-firewall.py")
        # Identical bounded metadata goes through both independent enforcers.
        for mode, uid, links in ((0o100644, 0, 1), (0o100666, 0, 1),
                                 (0o120777, 0, 1), (0o100644, 123, 1),
                                 (0o100644, 0, 2)):
            with self.subTest(mode=mode, uid=uid, links=links):
                info = os.stat_result((mode, 1, 1, links, uid, 0, 1, 0, 0, 0))
                accepted = []
                with patch.object(Path, "lstat", return_value=info):
                    for admit in (helper.trusted, phase.Native().trusted):
                        try:
                            admit(Path("/etc/secpal/example.conf"))
                            accepted.append(True)
                        except (phase.Error, ValueError):
                            accepted.append(False)
                self.assertEqual(accepted[0], accepted[1])

    def test_native_command_failure_never_exposes_untrusted_output(self):
        native = phase.Native()
        with self.assertRaisesRegex(phase.Error, "^fixture-command-failed$"):
            native.run("fixture", ["python3", "-c",
                       "import sys; print('FIXTURE_PRIVATE_VALUE'); sys.exit(1)"])

    def test_trusted_admission_failures_are_not_replaced_by_installer_success(self):
        with patch.object(phase, "verify_public_base"):
            def reject():
                raise ValueError("fixture rejection")
            with self.assertRaises(phase.Error):
                phase.admit_for_enrollment(unittest.mock.Mock(), self.plan(),
                                           conformance=lambda: None, artifacts=reject)

    def test_complete_public_install_first_run_and_unchanged_repeat(self):
        desired = self.plan()
        with tempfile.TemporaryDirectory() as directory:
            native = FixtureNative(Path(directory), desired)
            phase.install_public_base(native, desired)
            self.assertTrue(native.installed and native.manager and native.firewall and native.nft_active)
            self.assertTrue(native.label_rule and native.storage_labeled)
            self.assertGreater(native.changes, 0)
            snapshot = {name: (native.path(name).stat().st_ino, native.path(name).stat().st_mtime_ns,
                               native.path(name).read_bytes()) for name in desired["files"]}
            native.commands.clear()
            native.changes = 0
            phase.install_public_base(native, desired)
            self.assertEqual(native.changes, 0)
            self.assertFalse(any(command[0] in {"dnf4", "loginctl", "usermod", "useradd"}
                                 for command in native.commands))
            self.assertFalse(any("daemon-reload" in command or "--apply" in command
                                 for command in native.commands))
            self.assertEqual(snapshot, {name: (native.path(name).stat().st_ino,
                                               native.path(name).stat().st_mtime_ns,
                                               native.path(name).read_bytes())
                                        for name in desired["files"]})
            self.assertFalse(any(command[0] in {"psql", "initdb", "openssl"}
                                 or "qualify-native-postgresql.py" in " ".join(command)
                                 for command in native.commands))

    def test_authority_or_config_conflict_fails_before_any_install_mutation(self):
        for kind in ("authority", "configuration"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                desired = self.plan()
                native = FixtureNative(Path(directory), desired)
                if kind == "authority":
                    path = native.path("/var/lib/pgsql/data")
                    path.mkdir(parents=True)
                    (path / "PG_VERSION").write_text("18")
                else:
                    native.publish("/etc/secpal/host-base/postgresql.conf", "foreign configuration\n")
                native.changes = 0
                with self.assertRaises(phase.Error):
                    phase.install_public_base(native, desired)
                self.assertEqual(native.changes, 0)
                self.assertFalse(native.installed)

    def test_storage_policy_conflicts_never_relabel_existing_state(self):
        for case in ("foreign-policy", "populated-store", "label-drift"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                desired = self.plan()
                native = FixtureNative(Path(directory), desired)
                graphroot = desired["inventory"]["paths"]["podman_graph_root"]["path"]
                native.directory(graphroot)
                if case == "populated-store":
                    (native.path(graphroot) / "existing-state").touch()
                if case == "label-drift":
                    native.label_rule = True
                original = native.run
                def observe(operation, arguments, **kwargs):
                    if case == "foreign-policy" and arguments == ["semanage", "export"]:
                        return 0, "fcontext -a -t user_home_t /srv/foreign"
                    return original(operation, arguments, **kwargs)
                native.run = observe
                native.changes = 0
                with self.assertRaises(phase.Error):
                    native.storage_labels(desired, install=True)
                self.assertEqual(native.changes, 0)

    def test_masked_but_active_user_socket_is_rejected(self):
        desired = self.plan()
        with tempfile.TemporaryDirectory() as directory:
            native = FixtureNative(Path(directory), desired)
            user = desired["account"]["name"]
            native.masks.add((user, "podman.socket"))
            original = native.run
            def active(operation, arguments, **kwargs):
                if "is-active" in arguments and kwargs.get("user") == user:
                    return 0, "active"
                return original(operation, arguments, **kwargs)
            native.run = active
            with self.assertRaises(phase.Error):
                native.unit("podman.socket", user=user, install=True)
            self.assertEqual(native.changes, 0)

    def test_canonical_runtime_rejection_is_not_bypassed_after_install(self):
        desired = self.plan()
        with tempfile.TemporaryDirectory() as directory:
            native = FixtureNative(Path(directory), desired)
            phase.install_public_base(native, desired)
            original = native.run
            def conflicting(operation, arguments, **kwargs):
                status, output = original(operation, arguments, **kwargs)
                if operation == "observe-runtime":
                    data = phase.json.loads(output)
                    data["host"]["security"]["rootless"] = False
                    output = phase.json.dumps(data)
                return status, output
            native.run = conflicting
            with self.assertRaises(phase.rocky.ContractError):
                phase.verify_public_base(native, desired)


if __name__ == "__main__":
    unittest.main(verbosity=2)
