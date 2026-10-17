#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Real isolated DIRECT transport tests; synthetic peers are not product evidence."""

import importlib.util
from pathlib import Path
import http.client
import socket
import ssl
import subprocess
import struct
import os
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
module = importlib.util.spec_from_file_location('base_runtime', ROOT / 'tests/haproxy-base-runtime.py')
base = importlib.util.module_from_spec(module)
module.loader.exec_module(base)
import haproxy_direct_contract as direct


class DirectRuntimeTest(base.RuntimeTest):
    @classmethod
    def configuration(cls, routing=None):
        routing = routing or cls.routing
        if not hasattr(cls, 'ipv6_port'):
            with socket.socket(socket.AF_INET6) as listener:
                listener.bind(('::1', 0))
                cls.ipv6_port = listener.getsockname()[1]
        rows = [{'address': '127.0.0.1', 'port': cls.port, 'transport': 'http'},
                {'address': '::1', 'port': cls.ipv6_port, 'transport': 'http'}]
        text = direct.render(direct.from_document({'topology': 'single',
            'frontend_host': routing.frontend_host, 'api_host': routing.api_host, 'listeners': rows}))
        return text.replace('    user haproxy\n    group haproxy\n', '')

    def test_separate_origins_and_untrusted_forwarding(self):
        spoof = {'Forwarded': 'for=203.0.113.99;proto=https', 'X-Forwarded-For': '203.0.113.99',
                 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'evil.example.test',
                 'X-Forwarded-Port': '443', 'X-Forwarded-Prefix': '/evil',
                 'X-Real-IP': '203.0.113.99', 'X-SecPal-Client-IP': '203.0.113.99',
                 'X-SecPal-Origin-Token': 'synthetic-secret', 'X-Request-ID': 'caller-id'}
        for address, port, peer in [('127.0.0.1', self.port, '127.0.0.2'), ('::1', self.ipv6_port, '::1')]:
            for host, role in [('app.example.test', 'frontend'), ('api.example.test', 'api')]:
                with self.subTest(peer=peer, role=role):
                    connection = http.client.HTTPConnection(address, port, source_address=(peer, 0), timeout=5)
                    try:
                        connection.request('GET', '/', headers={'Host': host, **spoof})
                        response = connection.getresponse()
                        self.assertEqual((response.status, response.read()), (200, role.encode()))
                    finally:
                        connection.close()
                    headers = {k.lower(): v for k, v in self.backends[role].seen[-1].items()}
                    canonical = {k: v for k, v in headers.items() if k.startswith('x-forwarded-')}
                    self.assertEqual(canonical, {'x-forwarded-for': peer, 'x-forwarded-host': host,
                                                'x-forwarded-proto': 'http', 'x-forwarded-port': '80'})
                    self.assertFalse(any(k in ('forwarded', 'x-real-ip', 'x-request-id') or k.startswith('x-secpal-') for k in headers))
        for host in ('other.example.test', 'app.example.test.evil', 'api.example.test:1234'):
            self.assertEqual(self.request(host)[0], 421)
        self.assertEqual(self.request('app.example.test', '/v1/private')[1], b'frontend')

    def test_public_proxy_v1_v2_never_reach_backends(self):
        import struct
        request = b'GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n'
        v2 = b'\r\n\r\n\0\r\nQUIT\n' + bytes((0x21, 0x11)) + struct.pack('!H', 12)
        v2 += socket.inet_aton('203.0.113.99') + socket.inet_aton('127.0.0.1') + struct.pack('!HH', 4567, 80)
        for prefix in (b'PROXY TCP4 203.0.113.99 127.0.0.1 4567 80\r\n', v2):
            for address, port in [('127.0.0.1', self.port), ('::1', self.ipv6_port)]:
                before = sum(len(peer.seen) for peer in self.backends.values())
                with socket.create_connection((address, port), timeout=6) as connection:
                    connection.sendall(prefix + request)
                    try:
                        response = connection.recv(4096)
                    except ConnectionResetError:
                        response = b''
                self.assertNotIn(b' 200 ', response)
                self.assertEqual(sum(len(peer.seen) for peer in self.backends.values()), before)

    def test_generation_probe_binds_config_and_actual_worker(self):
        # Exercise the same installed helper with exact DIRECT accepted bytes.
        from unittest import mock
        module = importlib.util.spec_from_file_location('haproxy_config', ROOT / 'scripts/haproxy-config.py')
        helper = importlib.util.module_from_spec(module)
        module.loader.exec_module(helper)
        accepted = self.directory / 'accepted-direct.cfg'
        accepted.write_text(self.configuration().replace('global\n', 'global\n    user haproxy\n    group haproxy\n', 1))
        children = Path('/proc') / str(self.process.pid) / 'task' / str(self.process.pid) / 'children'
        workers = [int(pid) for pid in children.read_text().split()]
        self.assertEqual(len(workers), 1)
        with mock.patch.object(helper, 'SERVING', accepted):
            self.assertTrue(helper.probe_generation(workers[0]))
            self.assertFalse(helper.probe_generation(self.process.pid))

    def test_sensitive_request_fields_excluded_from_actual_logs(self):
        super().test_sensitive_request_fields_excluded_from_actual_logs()
        for address, port, peer in [('127.0.0.1', self.port, '127.0.0.2'), ('::1', self.ipv6_port, '::1')]:
            connection = http.client.HTTPConnection(address, port, source_address=(peer, 0), timeout=5)
            try:
                connection.request('GET', '/', headers={'Host': 'api.example.test'})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally:
                connection.close()
        time.sleep(.2)
        self.output.flush()
        logs = (self.directory / 'logs').read_text()
        for field in ('peer=127.0.0.2 client=127.0.0.2', 'peer=::1 client=::1'):
            self.assertTrue(field in logs, field)


class DirectTlsRuntimeTest(base.RuntimeTest):
    test_public_proxy_v1_v2_never_reach_backends = DirectRuntimeTest.test_public_proxy_v1_v2_never_reach_backends

    @classmethod
    def configuration(cls, routing=None):
        routing = routing or cls.routing
        cls.pem = cls.directory / 'fixture.pem'
        if not hasattr(cls, 'ipv6_port'):
            with socket.socket(socket.AF_INET6) as listener:
                listener.bind(('::1', 0))
                cls.ipv6_port = listener.getsockname()[1]
        if not cls.pem.exists():
            certificate = cls.directory / 'fixture.crt'
            key = cls.directory / 'fixture.key'
            result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(certificate), '-days', '1',
                '-subj', '/CN=app.example.test', '-addext',
                'subjectAltName=DNS:app.example.test,DNS:api.example.test,DNS:new-app.example.test'],
                capture_output=True, timeout=15, umask=0o077)
            if result.returncode:
                raise AssertionError('local synthetic certificate generation failed')
            cls.pem.write_bytes(certificate.read_bytes() + key.read_bytes())
            cls.pem.chmod(0o600)
        spec = direct.from_document({'topology': 'single', 'frontend_host': routing.frontend_host,
            'api_host': routing.api_host, 'listeners': [
                {'address': '127.0.0.1', 'port': cls.port, 'transport': 'https'},
                {'address': '::1', 'port': cls.ipv6_port, 'transport': 'https'}]})
        return direct.render(spec).replace(direct.VIEWER_PEM, str(cls.pem)).replace(
            '    user haproxy\n    group haproxy\n', '')

    @classmethod
    def request(cls, host, path='/', headers=None, method='GET', body=None):
        context = ssl.create_default_context(cafile=str(cls.pem))
        connection = http.client.HTTPSConnection(host, cls.port, timeout=5, context=context)
        create = connection._create_connection
        connection._create_connection = lambda target, *args, **kwargs: create(('127.0.0.1', target[1]), *args, **kwargs)
        try:
            connection.request(method, path, body=body, headers={'Host': host, **(headers or {})})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def raw(self, request):
        context = ssl.create_default_context(cafile=str(self.pem))
        with socket.create_connection(('127.0.0.1', self.port), timeout=8) as transport:
            with context.wrap_socket(transport, server_hostname=self.routing.api_host) as connection:
                connection.sendall(request)
                return connection.recv(4096)

    def test_separate_origins_and_untrusted_forwarding(self):
        for host, role in [('app.example.test', 'frontend'), ('api.example.test', 'api')]:
            status, body = self.request(host, '/sanctum/csrf-cookie', {
                'X-Forwarded-For': '203.0.113.99', 'X-Forwarded-Proto': 'http',
                'X-Forwarded-Host': 'evil.example.test', 'Origin': 'https://app.example.test',
                'Cookie': 'synthetic-session=synthetic-value', 'X-XSRF-TOKEN': 'synthetic-csrf'})
            self.assertEqual((status, body), (200, role.encode()))
            headers = {k.lower(): v for k, v in self.backends[role].seen[-1].items()}
            self.assertEqual(headers['x-forwarded-for'], '127.0.0.1')
            self.assertEqual(headers['x-forwarded-proto'], 'https')
            self.assertEqual(headers['x-forwarded-host'], host)
            self.assertEqual(headers['x-forwarded-port'], '443')
            self.assertEqual(headers['origin'], 'https://app.example.test')
            self.assertEqual(headers['cookie'], 'synthetic-session=synthetic-value')
            self.assertEqual(headers['x-xsrf-token'], 'synthetic-csrf')
        self.assertEqual(self.request('api.example.test', headers={'Host': 'foreign.example.test'})[0], 421)

    def test_generation_probe_binds_config_and_actual_worker(self):
        from unittest import mock
        module = importlib.util.spec_from_file_location('haproxy_config', ROOT / 'scripts/haproxy-config.py')
        helper = importlib.util.module_from_spec(module)
        module.loader.exec_module(helper)
        accepted = self.directory / 'accepted-direct-tls.cfg'
        accepted.write_text(self.configuration().replace(str(self.pem), direct.VIEWER_PEM).replace(
            'global\n', 'global\n    user haproxy\n    group haproxy\n', 1))
        children = Path('/proc') / str(self.process.pid) / 'task' / str(self.process.pid) / 'children'
        workers = [int(pid) for pid in children.read_text().split()]
        self.assertEqual(len(workers), 1)
        with mock.patch.object(helper, 'SERVING', accepted), mock.patch.object(helper, 'VIEWER_PEM', str(self.pem)):
            self.assertTrue(helper.probe_generation(workers[0]))
            self.assertFalse(helper.probe_generation(self.process.pid))

    def test_genuine_ipv6_tls_scheme_and_identity(self):
        context = ssl.create_default_context(cafile=str(self.pem))
        connection = http.client.HTTPSConnection('api.example.test', self.ipv6_port, timeout=5, context=context)
        create = connection._create_connection
        connection._create_connection = lambda target, *args, **kwargs: create(('::1', target[1]), *args, **kwargs)
        try:
            connection.request('GET', '/', headers={'Host': 'api.example.test', 'X-Forwarded-For': '203.0.113.99'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            connection.close()
        headers = {k.lower(): v for k, v in self.backends['api'].seen[-1].items()}
        self.assertEqual(headers['x-forwarded-for'], '::1')
        self.assertEqual(headers['x-forwarded-proto'], 'https')

    # These base transport probes use bare TCP or intentional foreign TLS SNI.
    # Their HTTP parsing coverage already runs on the DIRECT HTTP listener.
    test_incomplete_request_timeout = None
    test_malformed_methods_and_bounds = None


def proxy_v2(source, destination='127.0.0.1', source_port=4567, destination_port=80):
    family = socket.AF_INET6 if ':' in source else socket.AF_INET
    block = socket.inet_pton(family, source) + socket.inet_pton(family, destination)
    block += struct.pack('!HH', source_port, destination_port)
    return b'\r\n\r\n\0\r\nQUIT\n' + bytes((0x21, 0x21 if family == socket.AF_INET6 else 0x11)) + struct.pack('!H', len(block)) + block


class DirectHaRuntimeTest(base.RuntimeTest):
    @classmethod
    def configuration(cls, routing=None):
        routing = routing or cls.routing
        if not hasattr(cls, 'ipv6_port'):
            with socket.socket(socket.AF_INET6) as listener:
                listener.bind(('::1', 0))
                cls.ipv6_port = listener.getsockname()[1]
        cls.spec = direct.from_document({'topology': 'ha', 'frontend_host': routing.frontend_host,
            'api_host': routing.api_host, 'listeners': [
                {'address': '127.0.0.1', 'port': cls.port, 'transport': 'http', 'trusted_peers': ['127.0.0.2']},
                {'address': '::1', 'port': cls.ipv6_port, 'transport': 'http', 'trusted_peers': ['::1']}]})
        return direct.render(cls.spec).replace('    user haproxy\n    group haproxy\n', '')

    @classmethod
    def request(cls, host, path='/', headers=None, method='GET', body=None):
        connection = http.client.HTTPConnection('127.0.0.1', cls.port, timeout=6)
        connection.connect()
        connection.sock.sendall(proxy_v2('203.0.113.9'))
        try:
            connection.request(method, path, body=body, headers={'Host': host, **(headers or {})})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def raw(self, request):
        with socket.create_connection(('127.0.0.1', self.port), timeout=8) as connection:
            connection.sendall(proxy_v2('203.0.113.9') + request)
            return connection.recv(4096)

    def test_incomplete_request_timeout(self):
        start = time.monotonic()
        response = self.raw(b'GET / HTTP/1.1\r\nHost: api.example.test\r\nX-Incomplete: ')
        self.assertIn(b' 408 ', response.split(b'\r\n', 1)[0])
        self.assertLess(time.monotonic() - start, 7)

    def test_malformed_methods_and_bounds(self):
        for method in ('TRACE', 'UNSUPPORTED'):
            self.assertEqual(self.request('api.example.test', method=method)[0], 405)
        for request in (b'GET / HTTP/1.1\r\nHost: app.example.test\r\nHost: api.example.test\r\n\r\n',
                        b'GET http://api.example.test/ HTTP/1.1\r\nHost: app.example.test\r\n\r\n',
                        b'POST / HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx'):
            self.assertIn(b' 400 ', self.raw(request).split(b'\r\n', 1)[0])
        self.assertEqual(self.request('api.example.test', '/' + 'a' * 8192)[0], 414)

    def test_separate_origins_and_untrusted_forwarding(self):
        for address, port, peer in [('127.0.0.1', self.port, '127.0.0.2'), ('::1', self.ipv6_port, '::1')]:
            for client, destination in [('203.0.113.9', '127.0.0.1'), ('2001:db8::9', '::1')]:
                for host, role in [('app.example.test', 'frontend'), ('api.example.test', 'api')]:
                    with self.subTest(transport=address, client=client, role=role):
                        connection = http.client.HTTPConnection(address, port, source_address=(peer, 0), timeout=5)
                        connection.connect();connection.sock.sendall(proxy_v2(client, destination))
                        try:
                            connection.request('GET', '/', headers={'Host': host, 'Forwarded': 'for=198.51.100.99',
                                'X-Forwarded-For': '198.51.100.99', 'X-Forwarded-Proto': 'https',
                                'X-Real-IP': '198.51.100.99', 'X-SecPal-Client-IP': '198.51.100.99',
                                'X-Request-ID': 'caller-id'})
                            response=connection.getresponse();self.assertEqual((response.status,response.read()),(200,role.encode()))
                        finally: connection.close()
                        headers={key.lower():value for key,value in self.backends[role].seen[-1].items()}
                        self.assertEqual({k:v for k,v in headers.items() if k.startswith('x-forwarded-')},
                            {'x-forwarded-for':client,'x-forwarded-host':host,'x-forwarded-proto':'http','x-forwarded-port':'80'})
                        self.assertFalse(any(k in ('forwarded','x-real-ip','x-request-id') or k.startswith('x-secpal-') for k in headers))
        self.assertEqual(self.request('foreign.example.test')[0],421)

    def test_protocol_admission_rejects_untrusted_and_malformed(self):
        v4=proxy_v2('203.0.113.9');v6=proxy_v2('2001:db8::9','::1')
        frames=[b'PROXY TCP4 203.0.113.9 127.0.0.1 4567 80\r\n',b'',v4[:8],v4[:16],v4[:27],v6[:51],
                b'X'+v4[1:],v4[:12]+b'\x11'+v4[13:],v4[:12]+b'\x20'+v4[13:],
                v4[:13]+b'\x00'+v4[14:],v4[:13]+b'\x12'+v4[14:],v4[:13]+b'\x31'+v4[14:],
                v4[:14]+b'\x00\x0b'+v4[16:],v4[:14]+b'\x00\x0d'+v4[16:]+b'X',v4+v4,
                proxy_v2('0.0.0.0'),proxy_v2('224.0.0.1'),proxy_v2('::','::1'),
                proxy_v2('ff02::1','::1'),proxy_v2('::ffff:203.0.113.9','::1'),
                proxy_v2('203.0.113.9',source_port=0)]
        request=b'GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n'
        subprocess.run(['ip','-6','addr','add','::2/128','dev','lo'],check=True,capture_output=True)
        self.addCleanup(lambda:subprocess.run(['ip','-6','addr','del','::2/128','dev','lo'],check=True,capture_output=True))
        for source,frame,send_http in [('::2',v4,True),('::2',v6,True),('127.0.0.3',v4,True),('127.0.0.3',v6,True)]+[( '127.0.0.2',f,not f or len(f)>=28) for f in frames]:
            before=sum(len(b.seen) for b in self.backends.values())
            with self.subTest(source=source,frame=frame.hex()):
                with socket.socket(socket.AF_INET6 if ':' in source else socket.AF_INET) as connection:
                    connection.settimeout(6);connection.bind((source,0))
                    try:
                        connection.connect(('::1',self.ipv6_port) if ':' in source else ('127.0.0.1',self.port))
                        connection.sendall(frame+(request if send_http else b''))
                        response=connection.recv(4096)
                    except (OSError,TimeoutError):response=b''
                self.assertNotIn(b' 200 ',response)
                self.assertEqual(sum(len(b.seen) for b in self.backends.values()),before)

        # Even the read-only serving witness must reject invalid identity.
        generation = direct.generation_id(self.spec)
        with socket.socket() as connection:
            connection.settimeout(6);connection.bind(('127.0.0.2',0));connection.connect(('127.0.0.1',self.port))
            probe = f'GET /_secpal/proxy-generation HTTP/1.1\r\nHost: app.example.test\r\nX-SecPal-Runtime-Probe: {generation}\r\n\r\n'.encode()
            connection.sendall(proxy_v2('127.0.0.1',source_port=0)+probe)
            response=connection.recv(4096)
        self.assertIn(b' 400 ',response)
        self.assertNotIn(b'X-SecPal-Generation',response)

    def test_generation_probe_binds_config_and_actual_worker(self):
        from unittest import mock
        module=importlib.util.spec_from_file_location('haproxy_config',ROOT/'scripts/haproxy-config.py')
        helper=importlib.util.module_from_spec(module);module.loader.exec_module(helper)
        accepted=self.directory/'accepted-ha.cfg';accepted.write_text(self.configuration().replace('global\n','global\n    user haproxy\n    group haproxy\n',1))
        children=Path('/proc')/str(self.process.pid)/'task'/str(self.process.pid)/'children'
        workers=[int(pid) for pid in children.read_text().split()]
        self.assertEqual(len(workers),1)
        with mock.patch.object(helper,'SERVING',accepted):
            self.assertTrue(helper.probe_generation(workers[0]))
            self.assertFalse(helper.probe_generation(self.process.pid))

    def test_private_decoder_policy_and_log_correlation(self):
        import haproxy_direct_policy as policy
        rules=policy.host_policy(self.spec,994)['nft']
        self.assertEqual(subprocess.run(['nft','-f','-'],input=rules,text=True,capture_output=True).returncode,0)
        try:
            import json
            observed = json.loads(subprocess.check_output(['nft', '--json', 'list', 'table', 'inet', 'secpal_direct']))
            policy.admit_table(observed, self.spec, 994)
            # Removing the UID verdict is rejected by independent admission,
            # even when all paths and a source marker remain authentic.
            altered = json.loads(json.dumps(observed))
            altered['nftables'][-1]['rule']['expr'].pop(-2)
            with self.assertRaises(ValueError):
                policy.admit_table(altered, self.spec, 994)
            child="import os,socket; os.setgroups([]); os.setgid(1000); os.setuid(1000); s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',18082))"
            denied=subprocess.run([sys.executable,'-c',child],capture_output=True,text=True,timeout=5)
            self.assertNotEqual(denied.returncode,0)
            self.assertRegex(denied.stderr,'ConnectionRefusedError|PermissionError')
            # An unrelated local UID can bind an allowlisted loopback source;
            # source-IP admission alone cannot authenticate that process.
            outer = child[:child.index("s.connect(")] + "s.bind(('127.0.0.2',0)); s.connect(('127.0.0.1'," + str(self.port) + "))"
            denied = subprocess.run([sys.executable, '-c', outer], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(denied.returncode, 0)
            self.assertRegex(denied.stderr,'ConnectionRefusedError|PermissionError')
            # Administrative root's generation witness still traverses both stages.
            self.test_generation_probe_binds_config_and_actual_worker()
            self.test_sensitive_request_fields_excluded_from_actual_logs()
        finally:
            subprocess.run(['nft','delete','table','inet','secpal_direct'],check=True,capture_output=True)

    def test_sensitive_request_fields_excluded_from_actual_logs(self):
        import re
        before=(self.directory/'logs').read_text()
        connection=http.client.HTTPConnection('127.0.0.1',self.port,source_address=('127.0.0.2',0),timeout=5)
        connection.connect();connection.sock.sendall(proxy_v2('2001:db8::9','::1'))
        try:
            connection.request('GET','/private?token=synthetic-private-value',headers={'Host':'api.example.test',
                'Authorization':'Bearer synthetic-authorization','Cookie':'session=synthetic-cookie'})
            response=connection.getresponse();self.assertEqual(response.status,200);response.read()
        finally:connection.close()
        time.sleep(.15);self.output.flush();logs=(self.directory/'logs').read_text()[len(before):]
        outer=re.search(r'stage=admission worker=(\d+) peer=127\.0\.0\.2 edge=(127\.0\.0\.1:\d+>127\.0\.0\.1:18082)',logs)
        self.assertIsNotNone(outer)
        self.assertRegex(logs, rf'stage=http worker=\d+ edge={re.escape(outer[2])} client=2001:db8::9')
        for private in ('synthetic-private-value','synthetic-authorization','synthetic-cookie','/private'):
            self.assertNotIn(private,logs)


class DirectHaTlsRuntimeTest(DirectTlsRuntimeTest):
    @classmethod
    def configuration(cls, routing=None):
        # Reuse the single TLS fixture only; render the reviewed private seam.
        DirectTlsRuntimeTest.configuration.__func__(cls, routing)
        routing = routing or cls.routing
        cls.spec = direct.from_document({'topology':'ha','frontend_host':routing.frontend_host,
            'api_host':routing.api_host,'listeners':[
                {'address':'127.0.0.1','port':cls.port,'transport':'https','trusted_peers':['127.0.0.2']},
                {'address':'::1','port':cls.ipv6_port,'transport':'https','trusted_peers':['::1']}]})
        return direct.render(cls.spec).replace(direct.VIEWER_PEM,str(cls.pem)).replace('    user haproxy\n    group haproxy\n','')

    @classmethod
    def connection(cls, host, address, port, peer, client, destination):
        context=ssl.create_default_context(cafile=str(cls.pem))
        connection=http.client.HTTPSConnection(host,port,timeout=5,context=context)
        def create(target,timeout,source_address=None):
            transport=socket.create_connection((address,target[1]),timeout,(peer,0))
            header=proxy_v2(client,destination)
            # Positive control proves incomplete delivery is buffered until the
            # complete frame exists, then decoded before the TLS handshake.
            for offset in range(0,len(header),5):
                transport.sendall(header[offset:offset+5]);time.sleep(.002)
            return transport
        connection._create_connection=create
        return connection

    @classmethod
    def request(cls, host, path='/', headers=None, method='GET', body=None):
        connection=cls.connection(host,'127.0.0.1',cls.port,'127.0.0.2','203.0.113.9','127.0.0.1')
        try:
            connection.request(method,path,body=body,headers={'Host':host,**(headers or {})})
            response=connection.getresponse();return response.status,response.read()
        finally:connection.close()

    def test_separate_origins_and_untrusted_forwarding(self):
        for address,port,peer in [('127.0.0.1',self.port,'127.0.0.2'),('::1',self.ipv6_port,'::1')]:
            for client,destination in [('203.0.113.9','127.0.0.1'),('2001:db8::9','::1')]:
                for host,role in [('app.example.test','frontend'),('api.example.test','api')]:
                    with self.subTest(transport=address,client=client,host=host):
                        connection=self.connection(host,address,port,peer,client,destination)
                        try:
                            connection.request('GET','/sanctum/csrf-cookie',headers={'Host':host,
                                'X-Forwarded-For':'198.51.100.99','X-Real-IP':'198.51.100.99',
                                'Forwarded':'for=198.51.100.99','X-SecPal-Client-IP':'198.51.100.99',
                                'Origin':'https://app.example.test','Cookie':'synthetic-session=value'})
                            response=connection.getresponse();self.assertEqual((response.status,response.read()),(200,role.encode()))
                        finally:connection.close()
                        headers={k.lower():v for k,v in self.backends[role].seen[-1].items()}
                        self.assertEqual({k:v for k,v in headers.items() if k.startswith('x-forwarded-')},
                            {'x-forwarded-for':client,'x-forwarded-host':host,'x-forwarded-proto':'https','x-forwarded-port':'443'})
                        self.assertFalse(any(k in ('forwarded','x-real-ip') or k.startswith('x-secpal-') for k in headers))
                        self.assertEqual(headers['origin'],'https://app.example.test')
                        self.assertEqual(headers['cookie'],'synthetic-session=value')

    def test_generation_probe_binds_config_and_actual_worker(self):
        from unittest import mock
        module=importlib.util.spec_from_file_location('haproxy_config',ROOT/'scripts/haproxy-config.py')
        helper=importlib.util.module_from_spec(module);module.loader.exec_module(helper)
        accepted=self.directory/'accepted-ha-tls.cfg';accepted.write_text(direct.render(direct.from_config(
            self.configuration().replace(str(self.pem),direct.VIEWER_PEM).replace('global\n','global\n    user haproxy\n    group haproxy\n',1).encode())))
        children=Path('/proc')/str(self.process.pid)/'task'/str(self.process.pid)/'children'
        workers=[int(pid) for pid in children.read_text().split()]
        self.assertEqual(len(workers),1)
        with mock.patch.object(helper,'SERVING',accepted),mock.patch.object(helper,'VIEWER_PEM',str(self.pem)):
            self.assertTrue(helper.probe_generation(workers[0]))
            self.assertFalse(helper.probe_generation(self.process.pid))

    # These properties already have complete HTTP/single-TLS cases; avoid
    # projecting bare public transport tests onto the distinct HA transport.
    test_public_proxy_v1_v2_never_reach_backends=None
    test_genuine_ipv6_tls_scheme_and_identity=None
    test_sensitive_request_fields_excluded_from_actual_logs=None


if __name__ == '__main__':
    unittest.main()
