#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""FCOS preparation is secret-free and cannot execute installation."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import ast
import inspect
import symtable
import textwrap

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fcos_prepare", ROOT / "scripts/fcos_prepare.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PreparationTests(unittest.TestCase):
    def test_pure_preparation_has_closed_standard_library_dependencies(self):
        allowed = {
            "check",
            "Invalid",
            "ValueError",
            "TypeError",
            "KeyError",
            "AttributeError",
            "type",
            "dict",
            "set",
            "str",
            "list",
            "len",
            "re",
            "base64",
            "ipaddress",
            "admit",
        }
        attributes = {
            "re": {"fullmatch"},
            "base64": {"b64decode"},
            "ipaddress": {"ip_interface", "ip_address"},
        }

        def check_source(source):
            pending = list(
                symtable.symtable(source, "fcos-pure", "exec").get_children()
            )
            while pending:
                scope = pending.pop()
                self.assertLessEqual(
                    {
                        s.get_name()
                        for s in scope.get_symbols()
                        if s.is_global() and s.is_referenced()
                    },
                    allowed,
                )
                pending.extend(scope.get_children())
            for node in ast.walk(ast.parse(source)):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in attributes
                ):
                    self.assertIn(node.attr, attributes[node.value.id])

        for function in (
            module.check,
            module.admit,
            module.render,
            module.qualification,
        ):
            check_source(textwrap.dedent(inspect.getsource(function)))
        for source in (
            "def render(x):\n return open(x)\n",
            "def render(x):\n return re.compile(x)\n",
        ):
            with self.assertRaises(AssertionError):
                check_source(source)

    def rendered_fixture(self):
        return module.render(
            module.fixture("x86_64"),
            json.loads((ROOT / "config/fcos/artifacts.json").read_text()),
            json.loads((ROOT / "config/production/state-contract.json").read_text()),
        )

    def test_runtime_can_traverse_prepared_state_ancestors(self):
        result = self.rendered_fixture()
        contents = next(
            f["contents"]["inline"]
            for f in result["storage"]["files"]
            if f["path"] == "/etc/tmpfiles.d/secpal-foundation.conf"
        )
        for line in contents.splitlines():
            kind, path, mode, owner, group, _ = line.split()
            if kind == "d" and path in {"/srv/secpal", "/srv/secpal/runtime"}:
                shift = (
                    6
                    if owner == "secpal-runtime"
                    else 3 if group == "secpal-runtime" else 0
                )
                self.assertTrue((int(mode, 8) >> shift) & 1, path)

    def test_disposable_quadlet_fixture_preserves_qualified_isolation_and_native_pin(
        self,
    ):
        lock = json.loads((ROOT / "config/fcos/artifacts.json").read_text())
        for arch in ("x86_64", "aarch64"):
            settings = module.fixture(arch)
            fixture = module.qualification(settings, lock)
            unit = fixture["quadlet"]
            self.assertIn(
                "Image=quay.io/coreos/coreos-installer@"
                + lock["installer"][arch + "_manifest"],
                unit,
            )
            for setting in (
                "Pull=never",
                "Network=none",
                "ReadOnly=true",
                "NoNewPrivileges=true",
                "DropCapability=ALL",
                "Volume=/srv/secpal/runtime/qualification:/state:Z",
            ):
                self.assertIn(setting + "\n", unit)
            self.assertNotIn("Network=host", unit)
            self.assertIn(settings["installation_id"], fixture["script"])
            self.assertNotIn("private-key", json.dumps(fixture))

    def test_reinstallation_identity_preserves_first_boot_semantics(self):
        settings = module.fixture("x86_64")
        result = self.rendered_fixture()
        machine_id = next(
            f for f in result["storage"]["files"] if f["path"] == "/etc/machine-id"
        )
        self.assertEqual(machine_id["contents"]["inline"], "uninitialized\n")
        self.assertIn(
            "systemd.machine_id=" + settings["installation_id"],
            result["kernel_arguments"]["should_exist"],
        )

    def test_base_does_not_add_another_vpn_or_enrollment_authority(self):
        result = self.rendered_fixture()
        self.assertNotIn("netbird", json.dumps(result).lower())
        self.assertNotIn("management_url", module.fixture("x86_64"))

    def test_rootless_quadlet_can_observe_system_network_online_after_boot(self):
        result = self.rendered_fixture()
        self.assertIn(
            {
                "path": "/etc/systemd/system/multi-user.target.wants/network-online.target",
                "target": "/usr/lib/systemd/system/network-online.target",
            },
            result["storage"].get("links", []),
        )

    def test_fixture_renders_both_architectures_and_uses_canonical_mapping(self):
        lock = json.loads((ROOT / "config/fcos/artifacts.json").read_text())
        state = json.loads((ROOT / "config/production/state-contract.json").read_text())
        for arch in ["x86_64", "aarch64"]:
            settings = module.fixture(arch)
            result = module.render(settings, lock, state)
            text = json.dumps(result)
            self.assertIn("enabled = false", text)
            self.assertIn("systemd.machine_id=", text)
            self.assertNotIn("NB_SETUP_KEY=", text)
            self.assertNotIn("BEGIN PRIVATE KEY", text)
            self.assertNotIn("api.netbird.io", text)
            self.assertEqual(
                result["passwd"]["users"][0]["uid"],
                state["rootless_mapping"]["service_uid"],
            )
            self.assertNotIn("netbird", text.lower())

    def test_secret_and_command_fields_rejected(self):
        settings = module.fixture("x86_64")
        for name in ["setup_key", "private_key", "command", "installer_args"]:
            with self.subTest(name=name), self.assertRaises(module.Invalid):
                module.admit({**settings, name: "forbidden"})

    def test_untrusted_network_and_endpoint_rejected(self):
        for name, value in [
            ("management_url", "http://example.invalid"),
            ("management_url", "https://" + "user:secret@" + "example.invalid"),
            ("management_url", "https://example.invalid\n"),
            ("ipv6_gateway", "fe80::1%eth0\ninject=value"),
            ("mac", "xx; command"),
            ("ipv4", "0.0.0.0/0"),
            ("architecture", "amd64"),
            ("installation_id", "../replacement"),
            ("installation_id", "0" * 32),
        ]:
            with self.subTest(name=name), self.assertRaises(module.Invalid):
                module.admit({**module.fixture("x86_64"), name: value})


if __name__ == "__main__":
    unittest.main()
