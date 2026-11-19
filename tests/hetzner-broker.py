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
                "version": 1,
                "service_uid": 2001,
                "caller_uid": 2002,
                "expires_at": 4102444800,
                "allow_mutations": False,
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
            "version": 1,
            "service_uid": 2001,
            "caller_uid": os.getuid(),
            "expires_at": 4102444800,
            "allow_mutations": False,
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

    def test_checkout_and_user_owned_credentials_cannot_pass_root_custody(self):
        with self.assertRaises(broker.Rejected):
            broker.trusted_file(ROOT / "scripts/hetzner_broker.py", {0}, limit=65536)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("synthetic secret")
            with self.assertRaises(broker.Rejected):
                broker.trusted_file(path, {0}, secret=True)

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
        ]:
            with self.subTest(args=args), patch.object(
                broker.http.client,
                "HTTPSConnection",
                side_effect=AssertionError("network called"),
            ), self.assertRaises(broker.Rejected):
                transport.request(*args)

    def test_typed_actions_durable_replay_and_response_redaction(self):
        data = copy.deepcopy(self.data)
        data["allow_mutations"] = True
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
        }
        module_calls = {"json": {"loads"}, "re": {"fullmatch"}, "ACTIONS": {"values"}}

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
            broker.normalize_server,
            broker.admit_server,
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
            broker.client_request(["server", "rescue", "enable", "101"])["operation"],
            "server rescue enable",
        )


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
        data["allow_mutations"] = True
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
        data["allow_mutations"] = True
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
