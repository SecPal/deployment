#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Real HAProxy routing/reload evidence with synthetic HTTP product peers.

No runtime API, host service mutation, SELinux/firewall exemption, or product
qualification. Fixed ports must be unused; an existing service is never stopped.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import http.client
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import haproxy_base_contract as contract
from product_backend_contract import BACKENDS


class Backend(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, role):
        self.role = role
        self.ready = True
        self.reason = None
        self.seen = []
        self.slow_started = threading.Event()
        self.slow_release = threading.Event()
        super().__init__(('127.0.0.1', BACKENDS[role].host_port), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.slow_release.set()
        self.shutdown()
        self.server_close()
        self.thread.join(3)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        is_check = self.path in ('/health/live', '/health/ready')
        status = 200 if (self.path == '/health/live' and server.role == 'api') or server.ready else 503
        if not is_check:
            server.seen.append(dict(self.headers))
        if self.path.startswith('/slow'):
            server.slow_started.set()
            server.slow_release.wait(15)
        body = server.role.encode()
        self.send_response(status, server.reason)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        self.rfile.read(length)
        self.do_GET()


class RuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = shutil.which('haproxy')
        if not cls.binary:
            raise RuntimeError('real HAProxy is required for runtime evidence')
        cls.temporary = tempfile.TemporaryDirectory(prefix='secpal-haproxy-')
        cls.directory = Path(cls.temporary.name)
        cls.backends = {}
        cls.process = None
        cls.output = None
        try:
            for role in BACKENDS:
                cls.backends[role] = Backend(role)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                cls.port = listener.getsockname()[1]
            cls.listener = contract.Listener('127.0.0.1', cls.port)
            cls.routing = contract.Routing('app.example.test', 'api.example.test')
            cls.config = cls.directory / 'haproxy.cfg'
            cls.config.write_text(cls.configuration())
            cls.validate(cls.config)
            cls.output = (cls.directory / 'logs').open('w+')
            cls.process = subprocess.Popen([cls.binary, '-W', '-db', '-f', str(cls.config)],
                                           stdout=cls.output, stderr=cls.output, umask=0o077)
            cls.wait_status('app.example.test', 200)
            cls.wait_status('api.example.test', 200)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def configuration(cls, routing=None):
        # Only privilege dropping is projected out for this non-root process.
        # The actual host service's UID/SELinux boundary needs privileged evidence.
        return contract.render(routing or cls.routing, (cls.listener,)).replace(
            '    user haproxy\n    group haproxy\n', '')

    @classmethod
    def validate(cls, path):
        result = subprocess.run([cls.binary, '-c', '-f', str(path)], capture_output=True, timeout=10)
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors='replace'))

    @classmethod
    def tearDownClass(cls):
        if cls.process is not None:
            cls.process.terminate()
            try:
                cls.process.wait(5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait()
        for backend in cls.backends.values():
            backend.stop()
        if cls.output is not None:
            cls.output.close()
        cls.temporary.cleanup()

    @classmethod
    def request(cls, host, path='/', headers=None, method='GET', body=None):
        connection = http.client.HTTPConnection('127.0.0.1', cls.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers={'Host': host, **(headers or {})})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    @classmethod
    def wait_status(cls, host, status):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if cls.process is not None and cls.process.poll() is not None:
                cls.output.flush()
                raise AssertionError((cls.directory / 'logs').read_text())
            try:
                if cls.request(host)[0] == status:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(.1)
        raise AssertionError(f'expected HTTP {status} for {host}')

    @classmethod
    def wait_excluded(cls, host, role):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            status, body = cls.request(host)
            if status == 503 and body != role.encode():
                return
            time.sleep(.1)
        raise AssertionError(f'{role} was still selected while not ready')

    def raw(self, request):
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as connection:
            connection.sendall(request)
            return connection.recv(4096)

    def test_separate_origins_and_untrusted_forwarding(self):
        spoof = {'Forwarded': 'for=203.0.113.19', 'X-Forwarded-For': '203.0.113.19',
                 'X-Forwarded-Proto': 'https', 'X-Forwarded-Evil': 'yes',
                 'X-Real-IP': '203.0.113.19', 'X-SecPal-Origin-Token': 'synthetic-origin',
                 'X-Request-ID': 'caller-id'}
        for host, role in [('app.example.test', 'frontend'), ('api.example.test', 'api')]:
            status, body = self.request(host, headers=spoof)
            self.assertEqual((status, body), (200, role.encode()))
            delivered = {key.lower(): value for key, value in self.backends[role].seen[-1].items()}
            self.assertFalse(any(key in ('forwarded', 'x-real-ip') or
                                 key.startswith(('x-forwarded-', 'x-secpal-')) for key in delivered))
        for host in ('other.example.test', 'app.example.test.evil', 'api.example.test:1234'):
            self.assertEqual(self.request(host)[0], 421)
        self.assertEqual(self.request('app.example.test', '/v1/private')[1], b'frontend')
        self.assertEqual(self.request('app.example.test', '/sanctum/csrf-cookie')[1], b'frontend')

    def test_http_readiness_failure_and_recreation(self):
        for host, role in [('app.example.test', 'frontend'), ('api.example.test', 'api')]:
            backend = self.backends[role]
            try:
                backend.reason = 'synthetic-health-private-marker'
                backend.ready = False
                # API liveness still returns 200: only readiness may exclude it.
                self.wait_excluded(host, role)
                self.assertNotEqual(self.request(host)[1], role.encode())
                seen = len(backend.seen)
                self.request(host)
                self.assertEqual(len(backend.seen), seen)
                backend.ready = True
                backend.reason = None
                self.wait_status(host, 200)
                backend.stop()
                self.wait_status(host, 503)
                self.backends[role] = Backend(role)
                self.wait_status(host, 200)
                self.assertEqual(self.request(host)[1], role.encode())
            finally:
                self.backends[role].ready = True

    def test_malformed_methods_and_bounds(self):
        for method in ('TRACE', 'UNSUPPORTED'):
            self.assertEqual(self.request('api.example.test', method=method)[0], 405)
        self.assertIn(b' 405 ', self.raw(b'CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test\r\n\r\n').split(b'\r\n', 1)[0])
        for raw in (b'GET http://api.example.test/ HTTP/1.1\r\nHost: app.example.test\r\n\r\n',
                    b'GET https://app.example.test/ HTTP/1.1\r\nHost: api.example.test\r\n\r\n',
                    b'GET / HTTP/1.1\r\nHost: app.example.test\r\nHost: api.example.test\r\n\r\n',
                    b'GET / HTTP/1.1\r\nHost: app.example.test\r\nBad Header: invalid\r\n\r\n',
                    b'POST / HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx',
                    b'GET / HTTP/1.1\r\nHost: app.example.test\r\nBad: x\x00y\r\n\r\n'):
            self.assertIn(b' 400 ', self.raw(raw).split(b'\r\n', 1)[0])
        # HAProxy's RFC9112 framing owner drops extraneous Content-Length and
        # closes the client connection. Do not replace it with a custom parser.
        seen = len(self.backends['api'].seen)
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as connection:
            connection.sendall(b'POST / HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: app.example.test\r\n\r\n')
            response = b''
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
        self.assertEqual(response.count(b'HTTP/1.'), 1)
        self.assertEqual(len(self.backends['api'].seen), seen + 1)
        headers = {key.lower(): value for key, value in self.backends['api'].seen[-1].items()}
        self.assertNotIn('content-length', headers)
        long_headers = b'GET / HTTP/1.1\r\nHost: app.example.test\r\n' + b'X-Small: v\r\n' * 65 + b'\r\n'
        self.assertIn(b' 400 ', self.raw(long_headers).split(b'\r\n', 1)[0])
        huge_header = b'GET / HTTP/1.1\r\nHost: app.example.test\r\nX-Large: ' + b'x' * 16384 + b'\r\n\r\n'
        self.assertIn(b' 400 ', self.raw(huge_header).split(b'\r\n', 1)[0])
        self.assertEqual(self.request('api.example.test', '/' + 'x' * 8192)[0], 414)

    def test_generation_probe_binds_config_and_actual_worker(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location('haproxy_config', ROOT / 'scripts/haproxy-config.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        # Production admission reads exact generated bytes. The running test
        # process projects privilege drop only, preserving the same fingerprint.
        accepted = self.directory / 'accepted-input.cfg'
        accepted.write_text(contract.render(self.routing, (self.listener,)))
        children = Path('/proc') / str(self.process.pid) / 'task' / str(self.process.pid) / 'children'
        workers = [int(pid) for pid in children.read_text().split()]
        self.assertEqual(len(workers), 1)
        with mock.patch.object(helper, 'SERVING', accepted):
            self.assertTrue(helper.probe_generation(workers[0]))
            self.assertFalse(helper.probe_generation(self.process.pid))
            accepted.write_text(contract.render(contract.Routing('other.example.test', 'api.example.test'),
                                                (self.listener,)))
            self.assertFalse(helper.probe_generation(workers[0]))
        # Unrecognized diagnostic metadata grants no special access or identity.
        self.assertEqual(self.request('app.example.test', '/_secpal/proxy-generation',
                                     {'X-SecPal-Runtime-Probe': '0' * 64})[1], b'frontend')

    def test_incomplete_request_timeout(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=8) as connection:
            connection.sendall(b'GET / HTTP/1.1\r\nHost: api.example.test\r\nX-Incomplete: ')
            start = time.monotonic()
            response = connection.recv(4096)
            self.assertIn(b' 408 ', response.split(b'\r\n', 1)[0])
            self.assertLess(time.monotonic() - start, 7)

    def test_sensitive_request_fields_excluded_from_actual_logs(self):
        tokens = ['synthetic-auth-marker', 'synthetic-cookie-marker', 'synthetic-query-marker',
                  'synthetic-path-marker', 'synthetic-body-marker', 'synthetic-origin-marker']
        self.assertEqual(self.request('api.example.test', '/' + tokens[3] + '?token=' + tokens[2],
                         {'Authorization': 'Bearer ' + tokens[0], 'Cookie': 'session=' + tokens[1],
                          'X-SecPal-Origin-Token': tokens[5]}, 'POST', tokens[4])[0], 200)
        time.sleep(.2)
        self.output.flush()
        logs = (self.directory / 'logs').read_text()
        self.assertNotIn('synthetic-health-private-marker', logs)
        for token in tokens:
            self.assertNotIn(token, logs)
        for field in ('peer=127.0.0.1', 'request_id=', 'status=200', 'origin=api', 'backend=secpal_api', 'security=accepted'):
            self.assertIn(field, logs)

    def test_invalid_config_and_graceful_last_known_good_reload(self):
        import haproxy_config_lifecycle as lifecycle
        before = self.config.read_bytes()
        signals = []
        with self.assertRaises(ValueError):
            lifecycle.publish(self.config, before + b'\ninvalid-directive\n',
                              lambda path: self.validate_for_lifecycle(path), lambda: signals.append(True))
        self.assertEqual(signals, [])
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.request('app.example.test')[0], 200)
        backend = self.backends['frontend']
        backend.slow_started.clear()
        backend.slow_release.clear()
        result = []
        thread = threading.Thread(target=lambda: result.append(self.request('app.example.test', '/slow')))
        thread.start()
        self.assertTrue(backend.slow_started.wait(5))
        new_routing = contract.Routing('new-app.example.test', 'api.example.test')
        try:
            lifecycle.publish(self.config, self.configuration(new_routing).encode(),
                              self.validate_for_lifecycle, lambda: os.kill(self.process.pid, signal.SIGUSR2))
            self.wait_status('new-app.example.test', 200)
            backend.slow_release.set()
            thread.join(5)
            self.assertEqual(result, [(200, b'frontend')])
            self.assertEqual(self.request('app.example.test')[0], 421)
            # A reload failure restores disk bytes; the old live generation is serving.
            def fail_reload():
                raise ValueError('synthetic-reload-failure')
            current = self.config.read_bytes()
            with self.assertRaises(ValueError):
                lifecycle.publish(self.config, before, self.validate_for_lifecycle, fail_reload)
            self.assertEqual(self.config.read_bytes(), current)
            self.assertEqual(self.request('new-app.example.test')[0], 200)
        finally:
            backend.slow_release.set()
            thread.join(5)
            lifecycle.publish(self.config, before, self.validate_for_lifecycle,
                              lambda: os.kill(self.process.pid, signal.SIGUSR2))
            self.wait_status('app.example.test', 200)

    @classmethod
    def validate_for_lifecycle(cls, path):
        try:
            cls.validate(path)
        except AssertionError as error:
            raise ValueError('validate-haproxy-candidate') from error


if __name__ == '__main__':
    unittest.main()
