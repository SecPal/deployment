#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Negative dispatch and provider-representation contract evidence."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import copy
import io
import json
import os
import socket
import struct
import tempfile
import threading
import inspect
import symtable
import textwrap
import ast

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "hetzner_broker", ROOT / "scripts/hetzner_broker.py"
)
broker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = broker
spec.loader.exec_module(broker)


class FoundationTests(unittest.TestCase):
    def test_denied_read_does_not_claim_protected_file_existence(self):
        specification = importlib.util.spec_from_file_location(
            "hetzner_boundary_check", ROOT / "scripts/hetzner_boundary_check.py"
        )
        boundary = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(boundary)
        output = io.StringIO()
        with patch.object(boundary.os, "geteuid", return_value=1001), patch.object(
            boundary.os, "open", side_effect=PermissionError
        ), patch.object(boundary.os, "access", return_value=False), patch.object(
            boundary.Path, "exists", return_value=True
        ), patch(
            "sys.stdout", output
        ):
            self.assertEqual(boundary.main(), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["code"], "boundary.access-checks-complete")
        self.assertEqual(
            result["protected_file_existence"], "administrator-verification-required"
        )
        self.assertEqual(result["credential_transition"], "not-evaluated")

    def test_closed_read_only_dispatch(self):
        policy = broker.Policy.from_dict(
            {
                "version": 2,
                "service_uid": 2001,
                "caller_uid": 2002,
                "expires_at": 4102444800,
                "allowed_mutations": [],
                "servers": {
                    "101": {"architecture": "x86", "server_type": "cx23"},
                    "102": {"architecture": "x86", "server_type": "cx33"},
                    "103": {"architecture": "arm", "server_type": "cax21"},
                },
                "excluded_server_ids": [104],
                "rescue_ssh_key_ids": [105],
            }
        )
        for sid in [101, 102, 103]:
            self.assertEqual(
                broker.admit_request(
                    {"operation": "server inspect", "server_id": sid}, policy
                )["server_id"],
                sid,
            )
        for request in [
            {"operation": "server inspect", "server_id": 104},
            {"operation": "server inspect", "server_id": 999},
            {"operation": "server delete", "server_id": 101},
            {"operation": "server change-protection", "server_id": 101},
            {"operation": "server inspect", "server_id": 101, "path": "/servers/101"},
            {"operation": "server inspect", "server_id": 101, "command": "id"},
            {"operation": "server inspect", "server_id": True},
            {"operation": "server inspect", "server_id": "101"},
            {"operation": "server reboot", "server_id": 101},
        ]:
            with self.subTest(request=request), self.assertRaises(broker.Rejected):
                broker.admit_request(request, policy)


class BrokerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "version": 2,
            "service_uid": 2001,
            "caller_uid": os.getuid(),
            "expires_at": 4102444800,
            "allowed_mutations": [],
            "servers": {
                "101": {"architecture": "x86", "server_type": "cx23"},
                "102": {"architecture": "x86", "server_type": "cx33"},
                "103": {"architecture": "arm", "server_type": "cax21"},
            },
            "excluded_server_ids": [104],
            "rescue_ssh_key_ids": [105],
        }
        self.policy = broker.Policy.from_dict(self.data)
        self.calls = []
        self.raw = {
            "server": {
                "id": 101,
                "server_type": {"name": "cx23", "architecture": "x86"},
                "protection": {"delete": True, "rebuild": True},
                "status": "running",
                "rescue_enabled": False,
                "locked": False,
                "name": "DO-NOT-LOG",
                "primary_disk_size": 40,
                "public_net": {
                    "ipv4": {
                        "id": 301,
                        "ip": "192.0.2.101",
                        "blocked": False,
                        "dns_ptr": "x86.example.test",
                    },
                    "ipv6": {
                        "id": 401,
                        "ip": "2001:db8:101::/64",
                        "blocked": False,
                        "dns_ptr": [],
                    },
                    "firewalls": [{"id": 501, "status": "applied"}],
                    "floating_ips": [1001],
                },
                "volumes": [],
                "private_net": [],
            }
        }

    def transport(self, method, path, body=None):
        self.calls.append((method, path, body))
        if "/actions/" in path:
            return {
                "root_password": "DO-NOT-LOG",
                "action": {
                    "id": 200,
                    "command": "reboot_server",
                    "status": "success",
                    "resources": [{"id": 101, "type": "server"}],
                },
            }
        result = copy.deepcopy(self.raw)
        sid = int(path.rsplit("/", 1)[1])
        result["server"]["id"] = sid
        result["server"]["server_type"] = self.policy.servers[str(sid)].copy()
        result["server"]["server_type"]["name"] = result["server"]["server_type"].pop(
            "server_type"
        )
        public = result["server"]["public_net"]
        public["ipv4"].update(id=200 + sid, ip=f"192.0.2.{sid}")
        public["ipv6"].update(id=300 + sid, ip=f"2001:db8:{sid}::/64")
        if sid != 101:
            result["server"]["primary_disk_size"] = 80
        if sid == 103:
            public["ipv6"]["dns_ptr"] = [
                {"ip": "2001:db8:103::10/64", "dns_ptr": "arm.example.test"},
                {"ip": "2001:db8:103::11", "dns_ptr": "other.example.test"},
            ]
            public["firewalls"].append({"id": 502, "status": "pending"})
            result["server"]["volumes"] = [601]
            result["server"]["private_net"] = [
                {
                    "network": 701,
                    "ip": "10.0.0.2",
                    "alias_ips": ["10.0.0.3"],
                    "mac_address": "DO-NOT-LOG",
                }
            ]
        return result

    def test_list_is_exact_id_reads_and_normalizes_provider_shape(self):
        transport = type(
            "Transport", (), {"request": lambda _, *a: self.transport(*a)}
        )()
        result = broker.execute({"operation": "servers list"}, self.policy, transport)
        self.assertEqual([s["id"] for s in result["servers"]], [101, 102, 103])
        self.assertEqual(
            self.calls,
            [
                ("GET", "/servers/101", None),
                ("GET", "/servers/102", None),
                ("GET", "/servers/103", None),
            ],
        )
        self.assertNotIn("DO-NOT-LOG", json.dumps(result))

    def test_inventory_preserves_legacy_target_checks(self):
        transport = type(
            "Transport", (), {"request": lambda _, *a: self.transport(*a)}
        )()
        for sid, server_type, architecture, disk in (
            (101, "cx23", "x86", 40),
            (103, "cax21", "arm", 80),
        ):
            with self.subTest(sid=sid):
                facts = broker.execute(
                    {"operation": "server status", "server_id": sid},
                    self.policy,
                    transport,
                )["server"]
                expected = self.transport("GET", f"/servers/{sid}")["server"]
                self.assertEqual(
                    set(facts),
                    {
                        "id", "server_type", "architecture", "status",
                        "delete_protection", "rebuild_protection", "rescue_enabled",
                        "locked", "primary_disk_size", "public_net", "volumes",
                        "private_net",
                    },
                )
                self.assertEqual(
                    (facts["id"], facts["server_type"], facts["architecture"],
                     facts["primary_disk_size"]),
                    (sid, server_type, architecture, disk),
                )
                self.assertTrue(facts["delete_protection"] and facts["rebuild_protection"])
                self.assertEqual(
                    facts["public_net"],
                    {key: expected["public_net"][key] for key in ("ipv4", "ipv6", "firewalls")},
                )
                self.assertEqual(facts["volumes"], expected["volumes"])
                self.assertEqual(
                    facts["private_net"],
                    [{key: item[key] for key in ("network", "ip", "alias_ips")}
                     for item in expected["private_net"]],
                )
                self.assertNotIn("DO-NOT-LOG", json.dumps(facts))

    def test_inventory_rejects_conflicting_exclusive_attachments(self):
        for key, value in (
            ("id", 301),
            ("ip", "192.0.2.101"),
        ):

            def observe(_, method, path):
                raw = self.transport(method, path)
                if path == "/servers/102":
                    raw["server"]["public_net"]["ipv4"][key] = value
                return raw

            transport = type("Transport", (), {"request": observe})()
            with self.subTest(key=key), self.assertRaisesRegex(
                broker.Rejected, "provider.shape"
            ) as caught:
                broker.execute({"operation": "servers list"}, self.policy, transport)
            self.assertEqual(caught.exception.stage, "server.inspect")

    def test_inventory_detects_private_ip_and_alias_conflicts_within_one_network(self):
        for network in (701, 702):

            def observe(_, method, path):
                raw = self.transport(method, path)
                if path == "/servers/101":
                    raw["server"]["private_net"] = [
                        {"network": network, "ip": "10.0.0.3", "alias_ips": []}
                    ]
                if path == "/servers/103":
                    raw["server"]["public_net"]["ipv6"]["dns_ptr"] = []
                return raw

            transport = type("Transport", (), {"request": observe})()
            request = {"operation": "servers list"}
            with self.subTest(network=network):
                if network == 701:
                    with self.assertRaisesRegex(broker.Rejected, "provider.shape") as caught:
                        broker.execute(request, self.policy, transport)
                    self.assertEqual(caught.exception.stage, "server.inspect")
                else:
                    self.assertEqual(
                        broker.execute(request, self.policy, transport)["code"],
                        "observed",
                    )

    def test_missing_malformed_or_conflicting_inventory_is_rejected(self):
        missing = object()
        for path, value in (
            (("primary_disk_size",), missing),
            (("primary_disk_size",), True),
            (("primary_disk_size",), 0),
            (("public_net",), missing),
            (("public_net", "ipv4"), None),
            (("public_net", "ipv4", "id"), "301"),
            (("public_net", "ipv4", "ip"), "2001:db8::1"),
            (("public_net", "ipv4", "ip"), "0.0.0.0"),
            (("public_net", "ipv4", "blocked"), 0),
            (("public_net", "ipv4", "dns_ptr"), "bad\nname"),
            (("public_net", "ipv6"), missing),
            (("public_net", "ipv6", "id"), 301),
            (("public_net", "ipv6", "ip"), "2001:db8:101::1/64"),
            (("public_net", "ipv6", "ip"), "2001:db8:101::/48"),
            (("public_net", "ipv6", "ip"), "::/64"),
            (("public_net", "ipv6", "dns_ptr"), None),
            (("public_net", "ipv6", "dns_ptr"),
             [{"ip": "2001:db8:102::1", "dns_ptr": "outside.example.test"}]),
            (
                ("public_net", "ipv6", "dns_ptr"),
                [{"ip": "2001:db8:101::1/48", "dns_ptr": "wrong-prefix.example.test"}],
            ),
            (
                ("public_net", "ipv6", "dns_ptr"),
                [
                    {"ip": "2001:db8:101::1", "dns_ptr": "first.example.test"},
                    {"ip": "2001:db8:101::1/64", "dns_ptr": "duplicate.example.test"},
                ],
            ),
            (("public_net", "firewalls"), missing),
            (("public_net", "firewalls"), [{"id": 0, "status": "applied"}]),
            (("public_net", "firewalls"), [{"id": 501, "status": "unknown"}]),
            (("public_net", "firewalls"),
             [{"id": 501, "status": "applied"}, {"id": 501, "status": "pending"}]),
            (("volumes",), missing),
            (("volumes",), [601, 601]),
            (("volumes",), [False]),
            (("private_net",), missing),
            (("private_net",), [{"network": 701, "ip": "10.0.0.2"}]),
            (("private_net",), [{"network": 701, "ip": "192.0.2.2", "alias_ips": []}]),
            (("private_net",),
             [{"network": 701, "ip": "10.0.0.2", "alias_ips": ["10.0.0.2"]}]),
            (("private_net",),
             [{"network": 701, "ip": "10.0.0.2", "alias_ips": []},
              {"network": 701, "ip": "10.0.0.3", "alias_ips": []}]),
        ):
            with self.subTest(path=path, missing=value is missing):
                raw = copy.deepcopy(self.raw)
                parent = raw["server"]
                for key in path[:-1]:
                    parent = parent[key]
                if value is missing:
                    del parent[path[-1]]
                else:
                    parent[path[-1]] = value
                transport = type("Transport", (), {"request": lambda *_: raw})()
                with self.assertRaisesRegex(broker.Rejected, "provider.shape") as caught:
                    broker.execute(
                        {"operation": "server inspect", "server_id": 101},
                        self.policy,
                        transport,
                    )
                self.assertEqual(caught.exception.stage, "server.inspect")

    def test_inventory_reply_obeys_existing_wire_bound(self):
        transport = type(
            "Transport", (), {"request": lambda _, *a: self.transport(*a)}
        )()
        with patch.object(broker, "MAX_RESPONSE", 512), self.assertRaisesRegex(
            broker.Rejected, "provider.shape"
        ) as caught:
            broker.execute({"operation": "servers list"}, self.policy, transport)
        self.assertEqual(caught.exception.stage, "socket.reply")

    def test_large_inventory_does_not_change_action_replies_or_ledger(self):
        policy = broker.Policy.from_dict(
            {**self.data, "allowed_mutations": ["server reboot"]}
        )
        request = {
            "operation": "server reboot",
            "server_id": 101,
            "request_id": "d" * 32,
        }

        def observe(_, method, path, body=None):
            raw = self.transport(method, path, body)
            if "server" in raw:
                raw["server"]["volumes"] = list(range(601, 1001))
            return raw

        transport = type("Transport", (), {"request": observe})()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            broker, "MAX_RESPONSE", 512
        ):
            ledger = broker.Ledger(Path(directory) / "ledger.sqlite")
            try:
                result = broker.execute(request, policy, transport, ledger)
                replay = broker.execute(request, policy, transport, ledger)
                action = broker.execute(
                    {"operation": "server action-status", "server_id": 101, "action_id": 200},
                    policy,
                    transport,
                )
            finally:
                ledger.db.close()
        self.assertEqual(result["code"], "applied")
        self.assertEqual(result, replay)
        self.assertEqual(action["server"], result["server"])
        self.assertNotIn("volumes", result["server"])
        self.assertNotIn("public_net", result["server"])
        self.assertEqual([call[0] for call in self.calls].count("POST"), 1)

    def test_wrong_identity_architecture_type_and_protection_fail_closed(self):
        edits = [
            ("id", 102),
            ("id", True),
            ("server_type", {"name": "cx33", "architecture": "x86"}),
            ("server_type", {"name": "cx23", "architecture": "arm"}),
            ("protection", {"delete": False, "rebuild": True}),
            ("protection", {"delete": True, "rebuild": False}),
        ]
        for field, value in edits:
            raw = copy.deepcopy(self.raw)
            raw["server"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                broker.Rejected
            ):
                broker.admit_server(broker.normalize_server(raw), 101, self.policy)

    def test_duplicate_json_and_non_finite_values_rejected(self):
        for value in [
            b'{"operation":"servers list","operation":"delete"}',
            b'{"server_id":NaN}',
            b"[]",
            b"null",
        ]:
            with self.subTest(value=value), self.assertRaises(broker.Rejected):
                broker.admit_request(broker.decode(value), self.policy)

    def test_policy_expiry_and_overlapping_targets(self):
        transport = type(
            "Transport", (), {"request": lambda *_: self.fail("provider called")}
        )()
        with self.assertRaisesRegex(broker.Rejected, "policy.expired"):
            broker.execute(
                {"operation": "servers list"}, self.policy, transport, now=4102444801
            )
        self.data["excluded_server_ids"] = [101]
        with self.assertRaises(broker.Rejected):
            broker.Policy.from_dict(self.data)

    def test_same_uid_and_root_cannot_be_final_service_identity(self):
        for uid in [self.policy.caller_uid, 0, 999]:
            with self.subTest(uid=uid), self.assertRaises(broker.Rejected):
                broker.admit_custody(self.policy, uid)
        broker.admit_custody(self.policy, self.policy.service_uid)

    def test_rescue_only_authority_does_not_enable_other_mutations(self):
        data = copy.deepcopy(self.data)
        data["version"] = 2
        data["allowed_mutations"] = ["server rescue enable"]
        policy = broker.Policy.from_dict(data)
        for operations in (True, ["server delete"], ["server rescue enable"] * 2):
            with self.subTest(operations=operations), self.assertRaises(
                broker.Rejected
            ):
                broker.Policy.from_dict({**data, "allowed_mutations": operations})
        with self.assertRaises(broker.Rejected):
            broker.Policy.from_dict({**data, "version": 1})
        broker.admit_request(
            {
                "operation": "server rescue enable",
                "server_id": 101,
                "request_id": "d" * 32,
            },
            policy,
        )
        for operation in set(broker.ACTIONS) - {"server rescue enable"}:
            with self.subTest(operation=operation), self.assertRaisesRegex(
                broker.Rejected, "mutation.disabled"
            ):
                broker.admit_request(
                    {"operation": operation, "server_id": 101, "request_id": "e" * 32},
                    policy,
                )
        transport = broker.HetznerTransport("x" * 64, policy)
        with patch.object(
            broker.http.client,
            "HTTPSConnection",
            side_effect=AssertionError("network called"),
        ):
            for suffix, _ in (
                broker.ACTIONS[op]
                for op in set(broker.ACTIONS) - {"server rescue enable"}
            ):
                with self.subTest(suffix=suffix), self.assertRaisesRegex(
                    broker.Rejected, "mutation.disabled"
                ):
                    transport.request("POST", "/servers/101/actions/" + suffix, {})

    def test_source_custody_receives_unresolved_entrypoint(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "actual.py"
            real.write_text("# synthetic source")
            link = Path(directory) / "entrypoint.py"
            link.symlink_to(real)
            observed = []

            def reject(path, *_args, **_kwargs):
                observed.append(path)
                raise broker.Rejected("custody.invalid")

            with patch.object(broker, "__file__", str(link)), patch.object(
                broker, "trusted_file", reject
            ), self.assertRaises(broker.Rejected):
                broker.serve("/unused", "/unused", "/unused")
            self.assertEqual(observed, [link])

    def test_checkout_and_user_owned_credentials_cannot_pass_root_custody(self):
        with self.assertRaises(broker.Rejected):
            broker.trusted_file(ROOT / "scripts/hetzner_broker.py", {0}, limit=65536)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("synthetic secret")
            with self.assertRaises(broker.Rejected):
                broker.trusted_file(path, {0}, secret=True)

    def test_existing_ledger_accepts_root_ancestors_but_only_service_owned_leaf(self):
        import stat
        from types import SimpleNamespace

        ledger = Path("/var/lib/secpal-hetzner/requests.sqlite")
        service_uid = self.policy.service_uid
        for leaf_uid in (service_uid, 0, self.policy.caller_uid):
            parent_info = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=service_uid
            )
            root_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            leaf_info = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=leaf_uid, st_nlink=1, st_size=0
            )

            def metadata(path):
                return parent_info if path == ledger.parent else root_info

            with self.subTest(leaf_uid=leaf_uid), patch.object(
                broker.Path, "lstat", metadata
            ), patch.object(
                broker.Path, "is_symlink", return_value=False
            ), patch.object(
                broker.Path, "exists", return_value=True
            ), patch.object(
                broker.os, "open", return_value=100
            ), patch.object(
                broker.os, "fstat", return_value=leaf_info
            ), patch.object(
                broker.os, "close"
            ):
                if leaf_uid == service_uid:
                    broker.inspect_ledger_custody(self.policy, ledger)
                else:
                    with self.assertRaises(broker.Rejected):
                        broker.inspect_ledger_custody(self.policy, ledger)

    def test_new_ledger_rejects_symlink_ancestor_before_creation(self):
        import stat
        from types import SimpleNamespace

        ledger = Path("/var/lib/secpal-hetzner/requests.sqlite")

        def metadata(path):
            if path == ledger.parent:
                return SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700, st_uid=self.policy.service_uid
                )
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)

        with patch.object(broker.Path, "lstat", metadata), patch.object(
            broker.Path, "is_symlink", return_value=False
        ), patch.object(broker.Path, "exists", return_value=False), patch.object(
            broker.os, "open", side_effect=AssertionError("must reject before create")
        ), self.assertRaises(
            broker.Rejected
        ):
            broker.inspect_ledger_custody(self.policy, ledger)

    def test_readonly_policy_accepts_empty_optional_lists_without_rescue_fallback(self):
        data = {**self.data, "excluded_server_ids": [], "rescue_ssh_key_ids": []}
        broker.Policy.from_dict(data)
        with self.assertRaises(broker.Rejected):
            broker.Policy.from_dict(
                {**data, "allowed_mutations": ["server rescue enable"]}
            )

    def test_ipc_does_not_log_or_return_attacker_or_provider_secrets(self):
        transport = type(
            "Transport", (), {"request": lambda _, *a: self.transport(*a)}
        )()
        for request in [
            {"operation": "servers list"},
            {
                "operation": "server inspect",
                "server_id": 101,
                "token": "SYNTHETIC-SECRET",
            },
        ]:
            logs = []
            left, right = socket.socketpair()
            worker = threading.Thread(
                target=broker.handle,
                args=(left, self.policy, transport, None, logs.append),
            )
            worker.start()
            right.sendall(json.dumps(request).encode() + b"\n")
            response = right.recv(131072)
            worker.join()
            left.close()
            right.close()
            output = json.dumps(logs) + response.decode()
            self.assertNotIn("SYNTHETIC-SECRET", output)
            self.assertNotIn("DO-NOT-LOG", output)
            self.assertNotIn("192.0.2.101", json.dumps(logs))
        denied = copy.deepcopy(self.data)
        denied["caller_uid"] = 3001
        denied = broker.Policy.from_dict(denied)
        left, right = socket.socketpair()
        try:
            with self.assertRaisesRegex(broker.Rejected, "caller.denied"):
                broker.authorize_peer(left, denied)
            self.assertEqual(broker.authorize_peer(left, self.policy), os.getuid())
        finally:
            left.close()
            right.close()

    def test_transport_denies_arbitrary_http_before_network(self):
        transport = broker.HetznerTransport("x" * 64, self.policy)
        for args in [
            ("DELETE", "/servers/101"),
            ("POST", "/servers/101/actions/change_protection", {}),
            ("POST", "/servers", {}),
            ("GET", "https://evil.invalid/servers/101"),
            ("GET", "/servers/104"),
            ("GET", "/servers/101/../104"),
            ("GET", "/servers/101?path=/servers/104"),
            ("GET", "/primary_ips/301"),
            ("GET", "/volumes/601"),
            ("GET", "/networks/701"),
            ("GET", "/firewalls/501"),
        ]:
            with self.subTest(args=args), patch.object(
                broker.http.client,
                "HTTPSConnection",
                side_effect=AssertionError("network called"),
            ), self.assertRaises(broker.Rejected):
                transport.request(*args)

    def test_typed_actions_durable_replay_and_response_redaction(self):
        data = copy.deepcopy(self.data)
        data["allowed_mutations"] = list(broker.ACTIONS)
        policy = broker.Policy.from_dict(data)
        transport = type(
            "Transport", (), {"request": lambda _, *a: self.transport(*a)}
        )()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite"
            ledger = broker.Ledger(path)
            request = {
                "operation": "server reboot",
                "server_id": 101,
                "request_id": "a" * 32,
            }
            result = broker.execute(request, policy, transport, ledger)
            self.assertEqual(result["code"], "applied")
            self.assertNotIn("DO-NOT-LOG", json.dumps(result))
            self.assertEqual(sum(c[0] == "POST" for c in self.calls), 1)
            ledger.db.close()
            ledger = broker.Ledger(path)
            self.assertEqual(broker.execute(request, policy, transport, ledger), result)
            self.assertEqual(sum(c[0] == "POST" for c in self.calls), 1)
            conflicting = {**request, "operation": "server power-off"}
            with self.assertRaisesRegex(broker.Rejected, "replay.conflict"):
                broker.execute(conflicting, policy, transport, ledger)
            request["request_id"] = "b" * 32
            ledger.reserve(request)
            ledger.db.close()
            ledger = broker.Ledger(path)
            with self.assertRaisesRegex(broker.Rejected, "ledger.uncertain"):
                broker.execute(request, policy, transport, ledger)
            ledger.db.close()

    def test_action_must_belong_to_exact_server(self):
        raw = {
            "action": {
                "id": 200,
                "command": "reboot_server",
                "status": "success",
                "resources": [{"id": 104, "type": "server"}],
            }
        }
        with self.assertRaisesRegex(broker.Rejected, "action.mismatch"):
            broker.admit_action(broker.normalize_action(raw), 101, 200)

    def test_normalization_does_not_grant_target_or_protection_admission(self):
        raw = copy.deepcopy(self.raw)
        raw["server"]["protection"]["delete"] = False
        facts = broker.normalize_server(raw)
        self.assertIs(facts["delete_protection"], False)
        with self.assertRaisesRegex(broker.Rejected, "protection.invalid"):
            broker.admit_server(facts, 101, self.policy)
        raw = copy.deepcopy(self.raw)
        raw["server"]["id"] = 999
        facts = broker.normalize_server(raw)
        self.assertEqual(facts["id"], 999)
        with self.assertRaisesRegex(broker.Rejected, "identity.mismatch"):
            broker.admit_server(facts, 101, self.policy)

    def test_exact_identity_agrees_with_canonical_provider_contract(self):
        specification = importlib.util.spec_from_file_location(
            "broker_provider_agreement",
            ROOT / "scripts/provider-capability-contract.py",
        )
        contract = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = contract
        specification.loader.exec_module(contract)
        target = contract.ResourceTarget("hetzner", "example-project", "slot-a", "101")
        request = contract.CapabilityRequest(
            "inspection-1",
            "maintenance",
            "a" * 40,
            contract.Operation.INSPECT,
            target,
            "b" * 64,
        )
        for observed_id in (101, 999):
            raw = copy.deepcopy(self.raw)
            raw["server"]["id"] = observed_id
            result = contract.CapabilityResult(
                request.request_id,
                request.adapter_id,
                request.source_revision,
                request.operation,
                target,
                request.parameters_sha256,
                contract.Outcome.OBSERVED,
                contract.CleanupOutcome.NOT_APPLICABLE,
                provider_resource_id=str(observed_id),
            )
            with self.subTest(observed_id=observed_id):
                if observed_id == 101:
                    contract.admit_result(request, result)
                    broker.admit_server(broker.normalize_server(raw), 101, self.policy)
                else:
                    with self.assertRaises(contract.ContractError):
                        contract.admit_result(request, result)
                    with self.assertRaises(broker.Rejected):
                        broker.admit_server(
                            broker.normalize_server(raw), 101, self.policy
                        )

    def test_pure_contract_boundaries_have_closed_dependencies(self):
        # Repository-specific enforcement for these broader Python surfaces;
        # no claim that the canonical single-return evaluator admits this module.
        allowed = {
            "type",
            "set",
            "len",
            "int",
            "str",
            "bool",
            "tuple",
            "dict",
            "json",
            "re",
            "ipaddress",
            "require",
            "closed",
            "integer",
            "Rejected",
            "ACTIONS",
            "DIAGNOSTICS",
            "STAGES",
            "READS",
            "super",
            "__class__",
            "ValueError",
            "RecursionError",
            "UnicodeError",
            "map",
            "list",
            "all",
            "any",
            "parse_address",
            "validate_dns_ptr",
            "normalize_public_net",
            "normalize_private_net",
            "PRIVATE_IPV4_NETWORKS",
            "MAX_RESPONSE",
        }
        module_calls = {
            "json": {"loads", "dumps"},
            "re": {"fullmatch"},
            "ipaddress": {"IPv4Address", "IPv6Interface", "IPv6Network"},
            "ACTIONS": {"values"},
        }

        def check_source(source):
            table = symtable.symtable(source, "broker-pure-surface", "exec")
            pending = list(table.get_children())
            while pending:
                scope = pending.pop()
                dependencies = {
                    symbol.get_name()
                    for symbol in scope.get_symbols()
                    if symbol.is_global() and symbol.is_referenced()
                }
                self.assertLessEqual(dependencies, allowed)
                pending.extend(scope.get_children())
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Attribute):
                    root = node.value
                    if isinstance(root, ast.Name) and root.id in module_calls:
                        self.assertIn(node.attr, module_calls[root.id])

        for function in (
            broker.require,
            broker.integer,
            broker.closed,
            broker.decode,
            broker.Rejected.__init__,
            broker.Policy.from_dict,
            broker.admit_request,
            broker.parse_address,
            broker.validate_dns_ptr,
            broker.normalize_public_net,
            broker.normalize_private_net,
            broker.normalize_server,
            broker.admit_server,
            broker.admit_server_list,
            broker.normalize_action,
            broker.admit_action,
            broker.assemble_reply,
            broker.admit_custody,
        ):
            source = textwrap.dedent(inspect.getsource(function))
            with self.subTest(function=function.__name__):
                check_source(source)
        for mutation in (
            "def normalize(value):\n return open(value)\n",
            "def normalize(value):\n return time.time()\n",
            "def normalize(value):\n return socket.socket()\n",
            "def normalize(value):\n return json.dump(value)\n",
        ):
            with self.assertRaises(AssertionError):
                check_source(mutation)

    def test_assembly_projects_action_facts_without_observing(self):
        action = {
            "id": 200,
            "command": "reboot_server",
            "status": "success",
            "server_ids": (101,),
            "root_password": "DO-NOT-LOG",
        }
        with patch.object(
            broker.time, "time", side_effect=AssertionError
        ), patch.object(broker.os, "open", side_effect=AssertionError), patch.object(
            broker.socket, "socket", side_effect=AssertionError
        ):
            facts = broker.admit_server(
                broker.normalize_server(self.raw), 101, self.policy
            )
            result = broker.assemble_reply("observed", server=facts, action=action)
        self.assertNotIn("DO-NOT-LOG", json.dumps(result))
        self.assertEqual(set(result["action"]), {"id", "command", "status"})

    def test_client_has_no_shell_or_route_surface(self):
        for words in [
            ["shell", "id"],
            ["server", "delete", "101"],
            ["server", "inspect", "101;id"],
            ["server", "inspect", "101", "--path", "/servers"],
        ]:
            with self.subTest(words=words), self.assertRaises(broker.Rejected):
                broker.client_request(words)
        self.assertEqual(
            broker.client_request(
                ["server", "rescue", "enable", "101"], request_id="a" * 32
            )["operation"],
            "server rescue enable",
        )

    def test_cli_mutation_requires_and_preserves_an_explicit_retry_identity(self):
        with self.assertRaises(broker.Rejected):
            broker.client_request(["server", "reboot", "101"])
        first = broker.client_request(["server", "reboot", "101"], request_id="a" * 32)
        retry = broker.client_request(["server", "reboot", "101"], request_id="a" * 32)
        self.assertEqual(first, retry)
        self.assertEqual(first["request_id"], "a" * 32)
        for request_id in ("bad", "a" * 33, True):
            with self.subTest(request_id=request_id), self.assertRaises(
                broker.Rejected
            ):
                broker.client_request(
                    ["server", "reboot", "101"], request_id=request_id
                )
        with self.assertRaises(broker.Rejected):
            broker.client_request(["servers", "list"], request_id="a" * 32)

    def test_policy_rejects_expiry_outside_supported_timestamp_range(self):
        for expiry in (4102444801, 2**63 - 1):
            with self.subTest(expiry=expiry), self.assertRaises(broker.Rejected):
                broker.Policy.from_dict({**self.data, "expires_at": expiry})


class TransportBudgetTests(unittest.TestCase):
    setUp = BrokerSecurityTests.setUp

    def test_get_retries_twice_post_never_retried(self):
        transport = broker.HetznerTransport("x" * 64, self.policy)
        failed = type(
            "Failed",
            (),
            {
                "request": lambda *_a, **_k: (_ for _ in ()).throw(
                    OSError("SYNTHETIC-SECRET")
                ),
                "close": lambda *_: None,
            },
        )()
        with patch.object(
            broker.http.client, "HTTPSConnection", return_value=failed
        ) as factory:
            with self.assertRaisesRegex(broker.Rejected, "provider.transport"):
                transport.request("GET", "/servers/101")
            self.assertEqual(factory.call_count, 2)
        data = copy.deepcopy(self.data)
        data["allowed_mutations"] = list(broker.ACTIONS)
        transport = broker.HetznerTransport("x" * 64, broker.Policy.from_dict(data))
        with patch.object(
            broker.http.client, "HTTPSConnection", return_value=failed
        ) as factory:
            with self.assertRaisesRegex(broker.Rejected, "mutation.unknown"):
                transport.request("POST", "/servers/101/actions/reboot", {})
            self.assertEqual(factory.call_count, 1)

    def test_audit_failure_prevents_provider_dispatch(self):
        transport = type(
            "Transport", (), {"request": lambda *_: self.fail("provider called")}
        )()
        left, right = socket.socketpair()
        try:
            right.sendall(b'{"operation":"server inspect","server_id":101}\n')

            def failed(_):
                raise OSError("SYNTHETIC-SECRET")

            broker.handle(left, self.policy, transport, None, failed)
            result = json.loads(right.recv(65536))
            self.assertEqual(result, {"code": "audit.failed", "stage": "audit.result"})
        finally:
            left.close()
            right.close()

    def test_socket_receive_failure_is_locatable_and_secret_free(self):
        class FailedConnection:
            def settimeout(self, _timeout):
                pass

            def recv(self, _length):
                raise OSError("SYNTHETIC-SECRET")

            def sendall(self, data):
                self.response = json.loads(data)

        connection = FailedConnection()
        events = []
        calls = []
        transport = type("Transport", (), {"request": lambda *_: calls.append(True)})()
        with patch.object(broker, "authorize_peer", return_value=os.getuid()):
            broker.handle(connection, self.policy, transport, None, events.append)
        self.assertEqual(
            connection.response, {"code": "internal.failure", "stage": "socket.receive"}
        )
        self.assertNotIn("SYNTHETIC-SECRET", json.dumps(events))
        self.assertEqual(calls, [])

    def test_redirect_and_oversized_response_never_escape_origin(self):
        for status, data in [
            (302, b""),
            (200, b"x" * (broker.MAX_RESPONSE + 1)),
            (401, b"SYNTHETIC-SECRET"),
        ]:
            response = type(
                "Response", (), {"status": status, "read": lambda *_a: data}
            )()
            connection = type(
                "Connection",
                (),
                {
                    "request": lambda *_a, **_k: None,
                    "getresponse": lambda *_: response,
                    "close": lambda *_: None,
                },
            )()
            transport = broker.HetznerTransport("x" * 64, self.policy)
            with self.subTest(status=status), patch.object(
                broker.http.client, "HTTPSConnection", return_value=connection
            ) as factory:
                with self.assertRaises(broker.Rejected) as caught:
                    transport.request("GET", "/servers/101")
                self.assertNotIn("SECRET", str(caught.exception))
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(factory.call_args.args[0], "api.hetzner.cloud")


class SemanticDiagnosticsTests(unittest.TestCase):
    setUp = BrokerSecurityTests.setUp
    transport = BrokerSecurityTests.transport

    def test_broker_semantic_stages_have_manifest_ownership(self):
        manifest = json.loads((ROOT / ".secpal/evidence-architecture.json").read_text())
        declarations = {
            entry["id"]: entry
            for entry in manifest["external_operations"]
            if entry["id"].startswith("hetzner-broker.")
        }
        self.assertEqual(
            set(declarations), {"hetzner-broker." + stage for stage in broker.STAGES}
        )
        for name, declaration in declarations.items():
            self.assertEqual(
                declaration["diagnostic_identity"], {"id": name, "kind": "semantic"}
            )
            self.assertTrue(
                all(
                    declaration[field] for field in ("reachable", "fallible", "trusted")
                )
            )

    def test_each_provider_failure_names_its_semantic_operation(self):
        data = copy.deepcopy(self.data)
        data["allowed_mutations"] = list(broker.ACTIONS)
        policy = broker.Policy.from_dict(data)
        for index, stage in enumerate(
            ["server.inspect", "action.submit", "action.inspect", "server.readback"], 1
        ):
            calls = []

            def observed(method, path, body=None):
                calls.append(method)
                if len(calls) == index:
                    raise OSError("SYNTHETIC-SECRET")
                return self.transport(method, path, body)

            transport = type(
                "Transport", (), {"request": lambda _, *args: observed(*args)}
            )()
            with tempfile.TemporaryDirectory() as directory:
                ledger = broker.Ledger(Path(directory) / "ledger.sqlite")
                with self.subTest(stage=stage), self.assertRaises(
                    broker.Rejected
                ) as caught:
                    broker.execute(
                        {
                            "operation": "server reboot",
                            "server_id": 101,
                            "request_id": "c" * 32,
                        },
                        policy,
                        transport,
                        ledger,
                    )
                self.assertEqual(caught.exception.stage, stage)
                self.assertNotIn("SECRET", str(caught.exception))
                ledger.db.close()


if __name__ == "__main__":
    unittest.main()
