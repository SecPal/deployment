#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Real HAProxy -> API-pinned Symfony identity primitive, using synthetic peers.

Supply the independently authenticated HttpFoundation source from the API lock.
Full Laravel/Sanctum/session and host qualification remain separate evidence.
"""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    raise SystemExit('usage: haproxy-direct-application.py PINNED_HTTP_FOUNDATION_ROOT')
FRAMEWORK = Path(sys.argv.pop()).resolve()
module = importlib.util.spec_from_file_location('direct_runtime', ROOT / 'tests/haproxy-direct-runtime.py')
runtime = importlib.util.module_from_spec(module)
module.loader.exec_module(runtime)


class ApplicationIdentityTest(runtime.DirectRuntimeTest):
    def framework_request(self, headers, peer='127.0.0.1'):
        result = subprocess.run(['/usr/bin/php', str(ROOT / 'tests/haproxy-direct-application.php'), str(FRAMEWORK)],
            input=json.dumps({'headers': headers, 'peer': peer}), capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_application_identity(self):
        self.test_separate_origins_and_untrusted_forwarding()
        # The last request delivered by that matrix is a real IPv6 TCP client.
        headers = self.backends['api'].seen[-1]
        self.assertEqual(self.framework_request(headers), {
            'client': '::1', 'scheme': 'http', 'host': 'api.example.test', 'port': 80})
        import http.client
        connection = http.client.HTTPConnection('127.0.0.1', self.port, source_address=('127.0.0.2', 0), timeout=5)
        try:
            connection.request('GET', '/', headers={'Host': 'api.example.test',
                'Forwarded': 'for=203.0.113.99;proto=https', 'X-Forwarded-For': '203.0.113.99',
                'X-Real-IP': '203.0.113.99', 'X-SecPal-Client-IP': '203.0.113.99'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            connection.close()
        headers = self.backends['api'].seen[-1]
        self.assertEqual(self.framework_request(headers), {
            'client': '127.0.0.2', 'scheme': 'http', 'host': 'api.example.test', 'port': 80})
        # Exact proxy trust cannot grant identity authority to a different
        # application transport peer even if it forges the complete header set.
        self.assertEqual(self.framework_request(headers, peer='127.0.0.9')['client'], '127.0.0.9')


class ApplicationTlsIdentityTest(runtime.DirectTlsRuntimeTest):
    framework_request = ApplicationIdentityTest.framework_request

    def test_application_tls_identity(self):
        self.test_separate_origins_and_untrusted_forwarding()
        headers = self.backends['api'].seen[-1]
        self.assertEqual(self.framework_request(headers), {
            'client': '127.0.0.1', 'scheme': 'https', 'host': 'api.example.test', 'port': 443})
        self.test_genuine_ipv6_tls_scheme_and_identity()
        self.assertEqual(self.framework_request(self.backends['api'].seen[-1]), {
            'client': '::1', 'scheme': 'https', 'host': 'api.example.test', 'port': 443})


class ApplicationHaIdentityTest(runtime.DirectHaRuntimeTest):
    framework_request = ApplicationIdentityTest.framework_request

    def test_application_ha_identity(self):
        self.test_separate_origins_and_untrusted_forwarding()
        headers=self.backends['api'].seen[-1]
        self.assertEqual(self.framework_request(headers),{
            'client':'2001:db8::9','scheme':'http','host':'api.example.test','port':80})
        self.assertEqual(self.framework_request(headers,peer='127.0.0.9')['client'],'127.0.0.9')
        self.request('api.example.test')
        self.assertEqual(self.framework_request(self.backends['api'].seen[-1])['client'],'203.0.113.9')


class ApplicationHaTlsIdentityTest(runtime.DirectHaTlsRuntimeTest):
    framework_request = ApplicationIdentityTest.framework_request

    def test_application_ha_tls_identity(self):
        self.test_separate_origins_and_untrusted_forwarding()
        self.assertEqual(self.framework_request(self.backends['api'].seen[-1]),{
            'client':'2001:db8::9','scheme':'https','host':'api.example.test','port':443})


if __name__ == '__main__':
    suite = unittest.TestSuite([ApplicationIdentityTest('test_application_identity'),
                               ApplicationTlsIdentityTest('test_application_tls_identity'),
                               ApplicationHaIdentityTest('test_application_ha_identity'),
                               ApplicationHaTlsIdentityTest('test_application_ha_tls_identity')])
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
