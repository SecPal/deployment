#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Shared HAProxy contract; real binary behavior lives in haproxy-base-runtime.py."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import haproxy_base_contract as contract
from product_backend_contract import BACKENDS


class ContractTest(unittest.TestCase):
    def test_fixed_endpoints_and_application_readiness(self):
        text = contract.render(contract.Routing('app.example.test', 'api.example.test'),
                               (contract.Listener('127.0.0.1', 19090),))
        for role, backend in BACKENDS.items():
            self.assertIn(f'server {role} {backend.endpoint} check', text)
        self.assertIn('uri /health/ready', text)
        self.assertIn('uri /health/live', text)
        self.assertNotIn('resolvers', text)

    def test_closed_spec_rejects_discovery_runtime_and_identity_material(self):
        valid = {'frontend_host': 'app.example.test', 'api_host': 'api.example.test',
                 'listeners': [{'address': '127.0.0.1', 'port': 19090}]}
        self.assertEqual(contract.from_document(valid)[0].frontend_host, 'app.example.test')
        for key, value in [('backend_port', 12345), ('container_ip', '10.0.0.2'),
                           ('runtime_socket', '/run/podman/podman.sock'),
                           ('mode', 'DIRECT'), ('origin_secret', 'synthetic'),
                           ('certificate', '/tmp/key.pem'), ('identity', 'src'),
                           ('extra_config', 'lua-load /tmp/plugin')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.from_document(valid | {key: value})
        for extra in ({'accept_proxy': True}, {'ssl': True}, {'options': 'expose-fd listeners'}):
            with self.assertRaises(ValueError):
                contract.from_document(valid | {'listeners': [valid['listeners'][0] | extra]})

    def test_origin_and_listener_injection_rejected(self):
        for host in ('same.example', 'APP.example', 'x\nbackend injected', '*.example',
                     '127.0.0.1', 'https://app.example', 'app.example:443', 'x;' * 100):
            with self.assertRaises(ValueError):
                contract.Routing(host, host)
        for address, port in [('localhost', 80), ('127.0.0.1\n', 80),
                              ('127.0.0.1', True), ('127.0.0.1', 0),
                              ('127.0.0.1', 18080), ('127.0.0.1', 18081)]:
            with self.assertRaises(ValueError):
                contract.Listener(address, port)
        with self.assertRaises(ValueError):
            contract.render(contract.Routing('app.example.test', 'api.example.test'), ())

    def test_shared_policy_has_no_identity_or_mutable_runtime_extension(self):
        text = contract.render(contract.Routing('app.example.test', 'api.example.test'),
                               (contract.Listener('127.0.0.1', 19090),))
        for forbidden in ('set-src', 'set-header X-Forwarded', 'accept-proxy',
                          'send-proxy', 'ssl crt', 'lua-load', 'spoe', 'stats socket',
                          'server-state-file', 'resolvers', 'set-map', 'set-acl'):
            self.assertNotIn(forbidden, text)
        self.assertIn('del-header X-Forwarded- -m beg', text)
        self.assertIn('del-header X-SecPal- -m beg', text)
        self.assertNotIn('%r', text)
        self.assertNotIn('capture request header', text)
        self.assertNotIn('req.body', text)

    def test_systemd_consumes_existing_backend_owner_without_options(self):
        text = (ROOT / 'config/production/host-systemd/haproxy.service.d/secpal.conf').read_text()
        self.assertIn('BindsTo=secpal-product-backend-policy.service', text)
        self.assertIn('After=secpal-product-backend-policy.service', text)
        self.assertIn('EnvironmentFile=\n', text)
        self.assertNotIn('$OPTIONS', text)
        self.assertNotIn('conf.d', text)
        self.assertIn('ProtectSystem=strict', text)
        self.assertIn('NoNewPrivileges=true', text)
        self.assertIn('SocketBindDeny=any', text)
        self.assertNotIn('podman.sock', text)


    def test_invalid_byte_extensions_and_last_known_good_regeneration(self):
        routing = contract.Routing('app.example.test', 'api.example.test')
        listeners = (contract.Listener('127.0.0.1', 19090),)
        data = contract.render(routing, listeners).encode()
        self.assertEqual(contract.from_config(data), (routing, listeners))
        for candidate in (data + b'\nlua-load /tmp/plugin\n',
                          data.replace(b'127.0.0.1:18081', b'127.0.0.1:12345'),
                          data.replace(b'127.0.0.1:18080', b'10.0.0.12:8080'),
                          data + b'\nstats socket /run/podman/podman.sock\n'):
            with self.assertRaises(ValueError):
                contract.from_config(candidate)
        with self.assertRaises(ValueError):
            contract.decode_document(b'{"frontend_host":"a.example","frontend_host":"b.example"}')
        # Pending desired-input errors cannot invalidate accepted LKG bytes.
        with self.assertRaises(ValueError):
            contract.decode_document(b'{invalid}')
        self.assertEqual(contract.from_config(data), (routing, listeners))

    def test_exact_systemd_socket_seam(self):
        unit = contract.listener_constraints((contract.Listener('127.0.0.1', 19090),
                                             contract.Listener('::1', 19091)))
        self.assertIn('SocketBindAllow=ipv4:tcp:19090', unit)
        self.assertIn('SocketBindAllow=ipv6:tcp:19091', unit)
        self.assertNotIn('18080', unit)

    def test_supply_rejects_unreviewed_binary_or_feature_set(self):
        import haproxy_supply_contract as supply
        for arch, package in supply.PACKAGES.items():
            identity = f'haproxy|0|{supply.VERSION}|{supply.RELEASE}|{arch}'
            supply.admit_installed_package(arch, identity, package['binary_sha256'], supply.REQUIRED_FEATURES)
            for bad_arch, bad_identity, digest, features in (
                ('other', identity, package['binary_sha256'], supply.REQUIRED_FEATURES),
                (arch, identity.replace('3.0.5', '3.1.0'), package['binary_sha256'], supply.REQUIRED_FEATURES),
                (arch, identity, '0' * 64, supply.REQUIRED_FEATURES),
                (arch, identity, package['binary_sha256'], supply.REQUIRED_FEATURES - {'+SYSTEMD'})):
                with self.assertRaises(ValueError):
                    supply.admit_installed_package(bad_arch, bad_identity, digest, features)
        self.assertEqual(supply.normalize_features('Feature list : +SYSTEMD +THREAD\n'), frozenset({'+SYSTEMD', '+THREAD'}))
        for text in ('', 'Feature list : +SYSTEMD +SYSTEMD', 'Feature list : SYSTEMD'):
            with self.assertRaises(ValueError):
                supply.normalize_features(text)

    def test_atomic_lifecycle_rejects_failed_validation_before_publication(self):
        import tempfile
        from haproxy_config_lifecycle import publish
        with tempfile.TemporaryDirectory() as temporary:
            serving = Path(temporary) / 'accepted.cfg'
            serving.write_bytes(b'accepted')
            calls = []
            def invalid(candidate):
                self.assertEqual(serving.read_bytes(), b'accepted')
                self.assertEqual(candidate.read_bytes(), b'invalid')
                self.assertEqual(candidate.stat().st_mode & 0o777, 0o444)
                raise ValueError('synthetic-invalid-config')
            with self.assertRaises(ValueError):
                publish(serving, b'invalid', invalid, lambda: calls.append(True))
            self.assertEqual(calls, [])
            self.assertEqual(serving.read_bytes(), b'accepted')
            self.assertEqual(sorted(path.name for path in Path(temporary).iterdir()), ['accepted.cfg'])
            def failed_reload():
                self.assertEqual(serving.read_bytes(), b'candidate')
                raise ValueError('synthetic-failed-reload')
            def recover():
                self.assertEqual(serving.read_bytes(), b'accepted')
                calls.append('restored-before-recovery')
            with self.assertRaises(ValueError):
                publish(serving, b'candidate', lambda _: None, failed_reload, recover=recover)
            self.assertEqual(calls, ['restored-before-recovery'])
            self.assertEqual(serving.read_bytes(), b'accepted')

    def test_administrator_wrapper_is_fail_closed_in_the_worktree(self):
        import subprocess
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/haproxy-config.py'), '--check'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertIn('FAIL:', result.stderr)



    def test_reload_does_not_admit_transient_worker_without_serving_generation(self):
        import importlib.util
        from unittest import mock
        path = ROOT / 'scripts/haproxy-config.py'
        spec = importlib.util.spec_from_file_location('haproxy_config', path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            master = Path(temporary)
            (master / 'cgroup').write_text('0::/system.slice/haproxy.service')
            children = master / 'task/10/children'
            children.parent.mkdir(parents=True)
            children.write_text('11')
            identities = [(master, (0,) * 4), (master, (993,) * 4), (master, (993,) * 4)]
            with mock.patch.object(helper, 'process_identity', side_effect=identities), \
                 mock.patch.object(helper.os, 'kill', side_effect=lambda *_: children.write_text('11 12')), \
                 mock.patch.object(helper.time, 'monotonic', side_effect=[0, 0, 11]), \
                 mock.patch.object(helper.time, 'sleep'), \
                 mock.patch.object(helper, 'probe_generation', return_value=False, create=True):
                with self.assertRaisesRegex(ValueError, 'verify-haproxy-reload-generation'):
                    helper.reload_master(10, 993)


if __name__ == '__main__':
    unittest.main()
