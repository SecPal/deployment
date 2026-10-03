#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fixed backend publication and host-policy contract evidence for #101."""

from pathlib import Path
import ctypes
import ctypes.util
import importlib.util
import subprocess
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import product_backend_contract as contract


def policy_helper():
    path = Path(__file__).resolve().parents[1] / "scripts/product-backend-policy.py"
    spec = importlib.util.spec_from_file_location("backend_policy", path)
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    return policy


class BackendContractTest(unittest.TestCase):
    def test_withdrawal_removes_barrier_before_stopping_exact_backends(self):
        policy = policy_helper()
        calls = []
        account = SimpleNamespace(pw_name="secpal-runtime", pw_uid=20000, pw_dir="/srv/secpal")
        with mock.patch.object(policy, "administrator_authority"), mock.patch.object(policy, "runtime_identity", return_value=account), mock.patch.object(policy, "READY") as ready, mock.patch.object(policy, "observe", side_effect=lambda operation, args, **kw: calls.append((operation, args, ready.unlink.called)) or ""):
            policy.withdraw()
        self.assertTrue(calls)
        self.assertTrue(all(call[2] for call in calls))
        self.assertEqual(calls[0][1][-2:], ["secpal-frontend.service", "secpal-api.service"])
        service = (Path(__file__).resolve().parents[1] / "config/production/host-systemd/secpal-product-backend-policy.service").read_text()
        self.assertIn("ExecStop=/usr/bin/python3 -I /usr/local/libexec/secpal/product-backend-policy --withdraw", service)
        self.assertIn("After=nftables.service", service)

    def test_withdrawal_rejects_surviving_backend_listener(self):
        policy = policy_helper()
        account = SimpleNamespace(pw_name="secpal-runtime", pw_uid=20000, pw_dir="/srv/secpal")
        with mock.patch.object(policy, "administrator_authority"), mock.patch.object(policy, "runtime_identity", return_value=account), mock.patch.object(policy, "READY"), mock.patch.object(policy, "observe", side_effect=["", "LISTEN 0 128 127.0.0.1:18080 0.0.0.0:*"]):
            self.assertRaisesRegex(ValueError, "survived withdrawal", policy.withdraw)

    def test_effective_access_uses_the_platform_policy_decision(self):
        # Validate the libselinux observation against the installed distribution
        # policy. This does not qualify our not-yet-installed custom port type.
        if (not Path("/sys/fs/selinux/enforce").exists()
                or subprocess.run(["/usr/sbin/getsebool", "haproxy_connect_any"],
                                  capture_output=True, text=True).stdout.strip()
                != "haproxy_connect_any --> off"):
            self.skipTest("requires the enforcing targeted host qualification platform")
        policy = policy_helper()
        self.assertTrue(policy.effective_access("haproxy_t", "http_cache_port_t", "name_connect"))
        self.assertFalse(policy.effective_access("haproxy_t", "unreserved_port_t", "name_connect"))
        with self.assertRaisesRegex(ValueError, "observe-effective-selinux"):
            policy.effective_access("haproxy_t", "secpal_nonexistent_test_port_t", "name_connect")

    def test_selinux_module_compiles_with_the_platform_cil_compiler(self):
        library = ctypes.util.find_library("sepol")
        if library is None:
            self.skipTest("platform libsepol is unavailable; installed-policy qualification remains required")
        compiler = ctypes.CDLL(library)
        compiler.cil_db_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        compiler.cil_db_init.restype = None
        compiler.cil_add_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        compiler.cil_add_file.restype = ctypes.c_int
        compiler.cil_compile.argtypes = [ctypes.c_void_p]
        compiler.cil_compile.restype = ctypes.c_int
        compiler.cil_db_destroy.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        compiler.cil_db_destroy.restype = None
        # A synthetic compiler context, not the installed Rocky policy. s0 is
        # a sensitivity, not a named level; anonymous MLS levels must resolve.
        base = b"""(class tcp_socket (name_bind name_connect))
(classorder (tcp_socket))
(sid kernel)
(sidorder (kernel))
(sensitivity s0)
(sensitivityorder (s0))
(level low (s0))
(mls true)
(handleunknown deny)
(type base_t)
(type haproxy_t)
(type container_runtime_t)
(typeattribute port_type)
(role object_r)
(roletype object_r base_t)
(user system_u)
(userrole system_u object_r)
(userlevel system_u low)
(userrange system_u (low low))
(sidcontext kernel (system_u object_r base_t (low low)))
"""
        database = ctypes.c_void_p()
        compiler.cil_db_init(ctypes.byref(database))
        try:
            for name, data in ((b"base.cil", base),
                               (b"backends.cil", contract.host_policy(993)["product-backends.cil"].encode())):
                self.assertEqual(compiler.cil_add_file(database, name, data, len(data)), 0)
            self.assertEqual(compiler.cil_compile(database), 0)
        finally:
            compiler.cil_db_destroy(ctypes.byref(database))

    def test_reviewed_endpoints_and_readiness_have_one_owner(self):
        self.assertEqual(
            {role: backend.endpoint for role, backend in contract.BACKENDS.items()},
            {"frontend": "127.0.0.1:18080", "api": "127.0.0.1:18081"},
        )
        self.assertEqual(contract.publish_lines("worker-general"), ())
        self.assertEqual(contract.publish_lines("scheduler"), ())
        for backend in contract.BACKENDS.values():
            self.assertEqual(backend.container_port, 8080)
            self.assertEqual(backend.readiness_path, "/health/live")

    def test_host_policy_has_no_arbitrary_uid_or_port_interpolation(self):
        for uid in (0, -1, True, "100; flush ruleset", "001", 2**32):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                contract.host_policy(uid)
        policy = contract.host_policy(991)
        rules = policy["product-backends.nft"]
        self.assertIn("meta skuid 991", rules)
        self.assertIn("ip daddr 127.0.0.1", rules)
        self.assertIn("tcp dport { 18080, 18081 } reject", rules)
        self.assertIn('iifname != "lo" tcp dport { 18080, 18081 } reject', rules)
        self.assertNotIn("flush ruleset", rules)
        cil = policy["product-backends.cil"]
        self.assertIn("(allow haproxy_t secpal_backend_port_t (tcp_socket (name_connect)))", cil)
        self.assertNotIn("permissive", cil)
        self.assertNotIn("unreserved_port_t", cil)
        self.assertNotIn("name_bind name_connect", cil)

    def test_consumer_contains_only_static_backend_checks(self):
        text = contract.haproxy_backends()
        for backend in contract.BACKENDS.values():
            self.assertIn(f"server {backend.role} {backend.endpoint} check", text)
        self.assertNotRegex(text, r"(?im)resolvers|podman|docker|socket|^\s*(?:bind|frontend|listen) ")
        self.assertIn("http-check expect status 200", text)

    def test_policy_admission_rejects_identity_reuse_and_marker_drift(self):
        account = SimpleNamespace(pw_name="haproxy", pw_uid=993, pw_gid=993,
                                  pw_shell="/usr/sbin/nologin")
        self.assertEqual(contract.admit_policy_account(account, 20000), 993)
        for replacement in ({"pw_uid": 20000}, {"pw_uid": 0}, {"pw_uid": 1001},
                            {"pw_name": "unrelated"}, {"pw_shell": "/bin/bash"}):
            candidate = SimpleNamespace(**(vars(account) | replacement))
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                contract.admit_policy_account(candidate, 20000)
        with self.assertRaises(ValueError):
            contract.admit_policy_account(account, 993)
        policy = policy_helper()
        marker = {"schema_version": 1, "haproxy_uid": 993,
                  "policy_digest": contract.policy_digest(993)}
        policy.admit_marker(marker, 993)
        for candidate in ({}, marker | {"haproxy_uid": 992},
                          marker | {"policy_digest": "0" * 64}, marker | {"extra": True}):
            with self.subTest(marker=candidate), self.assertRaises(ValueError):
                policy.admit_marker(candidate, 993)


if __name__ == "__main__":
    unittest.main()
