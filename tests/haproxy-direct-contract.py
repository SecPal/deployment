#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""DIRECT typed composition and exact regeneration owned by deployment#220."""

from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import haproxy_direct_contract as direct


class DirectContractTest(unittest.TestCase):
    def document(self):
        return {'topology': 'single', 'frontend_host': 'app.example.test',
                'api_host': 'api.example.test', 'listeners': [
                    {'address': '0.0.0.0', 'port': 80, 'transport': 'http'},
                    {'address': '::', 'port': 443, 'transport': 'https'}]}

    def test_closed_input_and_public_proxy_rejection(self):
        spec = direct.decode_document(json.dumps(self.document()).encode())
        text = direct.render(spec)
        self.assertNotIn('accept-proxy', text)
        self.assertNotIn('expect-proxy', text)
        self.assertIn('bind [::]:443 v6only ssl crt /etc/haproxy/secpal-viewer.pem', text)
        self.assertIn('http-request set-header X-Forwarded-For %[src]', text)
        self.assertIn('peer=%[fc_src] client=%ci', text)
        self.assertEqual(direct.from_config(text.encode()), spec)
        for key in ('fragment', 'module', 'certificate', 'backend', 'trusted_peers'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                direct.from_document(self.document() | {key: 'unreviewed'})
        for row in ({'transport': 'tls'}, {'port': 18081}, {'accept_proxy': True}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                direct.from_document(self.document() | {'listeners': [self.document()['listeners'][0] | row]})
        # HA requires explicit private peer input. Single never silently
        # substitutes for a requested HA.
        with self.assertRaises(ValueError):
            direct.from_document(self.document() | {'topology': 'ha'})

    def test_ha_strict_preface_and_closed_private_seam(self):
        doc = self.document() | {'topology': 'ha', 'listeners': [
            {'address': '10.0.0.2', 'port': 80, 'transport': 'http',
             'trusted_peers': ['10.0.0.1', 'fd00::1']}]}
        spec = direct.from_document(doc)
        text = direct.render(spec)
        self.assertIn('req.payload(0,16) -m bin 0d0a0d0a000d0a515549540a2111000c', text)
        self.assertIn('req.payload(0,16) -m bin 0d0a0d0a000d0a515549540a21210024', text)
        self.assertIn('bind 127.0.0.1:18082 accept-proxy', text)
        self.assertNotIn('bind 10.0.0.2:80 accept-proxy', text)
        self.assertIn('peer=%ci edge=%[bc_src]:%[bc_src_port]', text)
        self.assertEqual(direct.from_config(text.encode()), spec)
        with self.assertRaises(ValueError):
            direct.from_document(doc | {'listeners': [
                {'address': '127.0.0.1', 'port': 19000 + index, 'transport': 'http', 'trusted_peers': ['127.0.0.2']}
                for index in range(8)]})
        for address in ('0.0.0.0', '::', '203.0.113.2'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                direct.from_document(doc | {'listeners': [doc['listeners'][0] | {'address': address}]})
        for peers in ([], ['*'], ['10.0.0.0/8'], ['10.0.0.1'] * 2, ['0.0.0.0']):
            with self.subTest(peers=peers), self.assertRaises(ValueError):
                direct.from_document(doc | {'listeners': [doc['listeners'][0] | {'trusted_peers': peers}]})

    def test_sanitize_before_canonical_emission_and_no_extensions(self):
        spec = direct.from_document(self.document())
        text = direct.render(spec)
        self.assertLess(text.index('del-header X-SecPal-'), text.index('set-header X-Forwarded-For'))
        for field in ('Forwarded', 'X-Real-IP', 'X-SecPal-', 'X-Request-ID'):
            self.assertIn('del-header ' + field, text)
        for candidate in (text + '\nlua-load /tmp/plugin\n', text.replace('127.0.0.1:18081', '10.0.0.1:8080')):
            with self.assertRaises(ValueError):
                direct.from_config(candidate.encode())
        for value in (b'{"topology":"single","topology":"ha"}', b'{broken', b'{}', b'x' * 65537):
            with self.assertRaises(ValueError):
                direct.decode_document(value)

    def test_listener_overlap_and_typed_construction(self):
        doc = self.document()
        for rows in ([doc['listeners'][0]] * 2,
                     [doc['listeners'][0], {'address': '127.0.0.1', 'port': 80, 'transport': 'http'}],
                     [{'address': '0.0.0.0', 'port': 80, 'transport': True}]):
            with self.assertRaises(ValueError):
                direct.from_document(doc | {'listeners': rows})
        with self.assertRaises(ValueError):
            direct.render('operator fragment')

    def test_exact_application_peer_rejects_wildcard_trust(self):
        for peer in ('127.0.0.1', '10.89.0.1', 'fd00::1'):
            self.assertEqual(direct.application_proxy_peer(peer), peer)
        self.assertEqual(direct.application_proxy_peers(('10.89.0.7', '10.89.1.4')), '10.89.0.7,10.89.1.4')
        for peers in ((), ['127.0.0.1'], ('127.0.0.1',) * 2, ('127.0.0.1', '::1', '10.89.0.1'), ('*',)):
            with self.subTest(peers=peers), self.assertRaises(ValueError):
                direct.application_proxy_peers(peers)
        for peer in ('*', '**', 'REMOTE_ADDR', '0.0.0.0/0', '::/0', '127.0.0.1,10.0.0.1',
                     'localhost', '0.0.0.0', '::', 'ff02::1', '127.0.0.1\n', '::1%lo', '::1%x\n    mode tcp'):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                direct.application_proxy_peer(peer)

    def test_shared_neutral_generation_bytes_are_preserved(self):
        import hashlib
        import haproxy_base_contract as base
        # Independently compared byte-for-byte with accepted #304 source at
        # c4e11cc6db2db480afcc2a375e629e3c7a70cf5b before recording this digest.
        # The characterization stays portable in shallow clones.
        text = base.render(base.Routing('app.example.test', 'api.example.test'),
                           (base.Listener('127.0.0.1', 19090),))
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
                         '5827de577fb03c2fa5fcfa6150e5173acecc19b60965d66d9e57ecea39a0c354')

    def test_neutral_helper_cannot_activate_public_identity_bypass(self):
        import haproxy_base_contract as base
        import haproxy_composition_contract as composition
        routing = base.Routing('app.example.test', 'api.example.test')
        for address in ('0.0.0.0', '::', '10.0.0.1', '2001:db8::1', '::1%lo', '::1%x\n    mode tcp'):
            doc = {'frontend_host': routing.frontend_host, 'api_host': routing.api_host,
                   'listeners': [{'address': address, 'port': 80}]}
            with self.subTest(address=address), self.assertRaises(ValueError):
                composition.decode_document(json.dumps(doc).encode())
            with self.assertRaises(ValueError):
                composition.from_config(base.render(routing, (base.Listener(address, 80),)).encode())

    def test_viewer_address_cannot_carry_scope_or_config_tokens(self):
        for address in ('::1%lo', '::1%x\n    mode tcp'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                direct.from_document(self.document() | {'listeners': [
                    {'address': address, 'port': 80, 'transport': 'http'}]})

    def test_public_ports_have_closed_transport_pairing(self):
        for port, transport in ((5432, 'http'), (2375, 'http'), (443, 'http'), (80, 'https')):
            with self.subTest(port=port), self.assertRaises(ValueError):
                direct.from_document(self.document() | {'listeners': [
                    {'address': '0.0.0.0', 'port': port, 'transport': transport}]})

    def test_installed_authority_precedes_project_module_execution(self):
        import subprocess
        import tempfile
        for helper, library in (('haproxy-config.py', 'haproxy_base_contract.py'),
                                ('haproxy-direct-policy.py', 'haproxy_direct_contract.py')):
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                entry = folder / helper
                entry.write_bytes((ROOT / 'scripts' / helper).read_bytes())
                marker = folder / 'executed'
                (folder / library).write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise SystemExit(1)\n')
                result = subprocess.run([sys.executable, '-I', str(entry), '--check'], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists(), 'project code executed before installed source admission')

    def test_historical_payload_record_rejects_tampering(self):
        import copy
        import importlib.util
        spec = importlib.util.spec_from_file_location('historical_reference', ROOT / 'scripts/validate-haproxy-reference.py')
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        record = json.loads((ROOT / 'docs/evidence/haproxy-rocky-reference.json').read_text())
        for negative in (False, True):
            changed = copy.deepcopy(record)
            correction = changed['remediation_qualification'][0]
            hashes = (correction['negative_admission_and_fault_injection']['source_sha256'] if negative
                      else correction['installed_source_sha256'])
            hashes['/usr/local/libexec/secpal/haproxy-config'] = '0' * 64
            with self.assertRaises(ValueError):
                validator.admit(changed, ROOT)



if __name__ == '__main__':
    unittest.main()
