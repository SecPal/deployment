#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Public finding admission and independent Self-Hosted delivery contract."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from public_findings import Source, accept, notify, stream_adapter, tls_finding
from viewer_tls_contract import health

NOW = 2000000
SUBJECT = 'a' * 64
EVIDENCE = 'b' * 64
SOURCE = Source('host-conformance', 'conformance', 'Security',
                frozenset({('HEALTHY', 'baseline-current'), ('UNKNOWN', 'observation-unavailable')}), 60)


def document():
    return dict(schema_version=1, producer=SOURCE.producer, category=SOURCE.category,
                capability=SOURCE.capability, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE,
                condition='HEALTHY', reason='baseline-current', observed_at=NOW)


def wire(value):
    return json.dumps(value).encode()


def admission(raw, **changes):
    arguments = dict(source=SOURCE, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE, now=NOW)
    arguments.update(changes)
    return accept(raw, **arguments)


class Findings(unittest.TestCase):
    def test_closed_bounded_independently_bound_finding(self):
        accepted = admission(wire(document()))
        self.assertEqual(json.loads(accepted), document())
        self.assertEqual(admission(accepted), accepted)
        mutations = [
            dict(producer='caller'), dict(subject_sha256='c'*64), dict(evidence_sha256='c'*64),
            dict(category='incident'), dict(condition='DEPLOY'), dict(reason='token-value'),
            dict(observed_at=NOW+1), dict(observed_at=True), dict(schema_version=True),
            dict(observed_at=NOW-61), dict(observed_at=None),
        ]
        for delta in mutations:
            with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, '^finding-'):
                admission(wire(dict(document(), **delta)))
        for key in ('credential', 'cookie', 'body', 'labels', 'customer', 'fleet', 'authorized', 'action', 'destination'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission(wire(dict(document(), **{key: 'ignored-is-unsafe'})))
        missing = document(); del missing['evidence_sha256']
        for raw in (wire(missing), b'x'*4097, b'[]', b'null', b'not-json',
                    wire(document())[:-1]+b',"producer":"caller"}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                admission(raw)
        with self.assertRaises(ValueError):
            admission(wire(document()), now=True)

    def test_unknown_is_not_synthetic_healthy(self):
        unknown = dict(document(), condition='UNKNOWN', reason='observation-unavailable', observed_at=None)
        self.assertEqual(json.loads(admission(wire(unknown))), unknown)
        unknown['observed_at'] = NOW-1000
        self.assertEqual(json.loads(admission(wire(unknown)))['condition'], 'UNKNOWN')

    def test_self_hosted_notification_and_delivery_are_separate(self):
        raw = wire(document())
        stream = io.BytesIO()
        result = notify(raw, source=SOURCE, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE,
                        now=NOW, notification_id='c'*64, send=stream_adapter(stream))
        envelope = json.loads(stream.getvalue())
        self.assertEqual(envelope['finding'], document())
        self.assertEqual(result, dict(schema_version=1, notification_id='c'*64,
                         finding_sha256=hashlib.sha256(admission(raw)).hexdigest(), delivery='DELIVERED'))
        self.assertEqual(raw, wire(document()))

    def test_failure_and_silence_do_not_change_facts_or_expose_errors(self):
        raw = wire(document())
        calls = []
        def broken(message):
            calls.append(message)
            raise RuntimeError('sensitive destination or credential must not escape')
        arguments = dict(source=SOURCE, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE,
                         now=NOW, notification_id='d'*64, send=broken)
        failed = notify(raw, **arguments)
        self.assertEqual(failed['delivery'], 'FAILED')
        self.assertNotIn('sensitive', json.dumps(failed))
        self.assertEqual(notify(raw, **arguments, silent=True)['delivery'], 'SILENCED')
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(admission(raw)), document())
        for invalid in (1, 'yes'):
            with self.assertRaises(ValueError):
                notify(raw, **arguments, silent=invalid)

    def test_data_never_selects_actions_adapters_or_destinations(self):
        calls = []
        arguments = dict(source=SOURCE, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE,
                         now=NOW, notification_id='e'*64, send=calls.append)
        for extra in ({'action': 'provider-delete'}, {'send': 'os.system'}, {'authorized': True}):
            with self.assertRaises(ValueError):
                notify(wire(dict(document(), **extra)), **arguments)
        self.assertEqual(calls, [])
        with self.assertRaises(ValueError):
            notify(wire(document()), **dict(arguments, notification_id='unsafe\nvalue'))
        # The accepted #104 consumer still requires its separately supplied
        # configuration/canonical peer/TTL. A finding is not a mutation request.
        from host_firewall_contract import remediation
        config = dict(edge_mode='DIRECT', management_ipv4=['192.0.2.10/32'],
                      management_ipv6=[], dhcp_interfaces=['ens3'])
        with self.assertRaises(ValueError):
            remediation(config, None, admission(wire(document())), ttl=60)
        self.assertEqual(remediation(config, None, '198.51.100.20', ttl=60),
                         ('remediation4', '198.51.100.20'))
        with self.assertRaises(ValueError):
            remediation(config, None, '192.0.2.10', ttl=60)

    def test_stream_failure_and_partial_write_are_not_delivery(self):
        class Short:
            def write(self, data): return len(data)-1
            def flush(self): pass
        arguments = dict(source=SOURCE, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE,
                         now=NOW, notification_id='f'*64)
        self.assertEqual(notify(wire(document()), send=stream_adapter(Short()), **arguments)['delivery'], 'FAILED')
        self.assertEqual(notify(wire(document()), send=lambda _: None, **arguments)['delivery'], 'FAILED')

    def test_tls_consumes_existing_fact_without_changing_health_semantics(self):
        observation = dict(observed_at=NOW, not_after=NOW+100*86400,
                           served='MATCH', renewal='SUCCESS', renewal_at=NOW)
        original = copy.deepcopy(observation)
        for delta in ({}, {'served':'MISMATCH'}, {'renewal':'FAILURE'},
                      {'served':'UNKNOWN'}, {'observed_at':None}, {'observed_at':NOW-86401},
                      {'not_after':NOW-1}, {'not_after':NOW+86400}):
            observed = dict(observation, **delta)
            fact = health(observed, NOW)
            accepted = json.loads(tls_finding(observed, subject_sha256=SUBJECT,
                                             evidence_sha256=hashlib.sha256(json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), now=NOW))
            self.assertEqual((accepted['condition'], accepted['reason']), (fact['state'], fact['reason']))
            self.assertEqual(accepted['observed_at'], fact['observed_at'])
            self.assertEqual(accepted['capability'], 'Security')
        self.assertEqual(observation, original)
        with self.assertRaisesRegex(ValueError, 'finding-tls-evidence'):
            tls_finding(observation, subject_sha256=SUBJECT, evidence_sha256=EVIDENCE, now=NOW)
        invalid = dict(observation, not_after='invalid')
        digest = hashlib.sha256(json.dumps(invalid, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'admit-tls-health-time'):
            tls_finding(invalid, subject_sha256=SUBJECT, evidence_sha256=digest, now=NOW)



if __name__ == '__main__':
    unittest.main()
