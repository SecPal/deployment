#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Reference-host boundary fixtures; never real-system qualification evidence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import postgresql_qualification_contract as contract


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReferenceHost(unittest.TestCase):
    def fixture(self, arch='amd64'):
        legacy = load('legacy_pg_fixture', 'tests/postgresql-qualification-contract.py')
        profile = 'gcp-rocky-10-2-' + ('x86-64' if arch == 'amd64' else 'arm64')
        evidence, options = legacy.CandidateData().system_fixture(profile)
        host = {'machine_id': '8'*32, 'address': '192.0.2.81',
                'ssh_host_key': 'ssh-ed25519 ' + base64.b64encode(
                    b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'x'*32).decode()}
        auth = evidence['authorization']
        auth.update(profile='reference-rocky-10-2-' + arch, pull_request=286, reference_host=host)
        facts = {'os_release': {'ID': 'rocky', 'VERSION_ID': '10.2'},
                 'architecture': evidence['architecture'], 'selinux': 'Enforcing', **host,
                 'runtime': {'podman_host': {'security': {'rootless': True, 'seccompEnabled': True},
                     'ociRuntime': {'name': 'crun'}, 'networkBackend': 'netavark', 'serviceIsRemote': False},
                     'cgroup_filesystem': 'cgroup2fs', 'systemd_user': 'active', 'socket_exists': False,
                     'podman_socket_enabled': False, 'container_host_present': False, 'sudo_authorized': False,
                     'uid': 1000, 'gid': 1000, 'groups': [1000]}}
        evidence.pop('instance_id'); evidence.pop('instance_name')
        evidence['reference_host'] = host
        evidence['host_admission'] = {'reference_host_facts': facts,
            'evidence_sha256': contract.reference_host_digest(facts)}
        options.pop('instance_id'); options.pop('instance_name')
        options.update(reference_host=host, reference_host_facts=facts,
                       host_evidence_sha256=contract.reference_host_digest(facts))
        return evidence, options

    def test_real_shaped_reference_fixtures_share_pg_fact_admission(self):
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT/'schemas/postgresql-qualification-evidence.schema.json').read_text())
        for arch in ('amd64', 'arm64'):
            e, options = self.fixture(arch)
            contract.admit_authorization(e['authorization'], control_sha='e'*40,
                profile=e['authorization']['profile'], run_id='100', run_attempt='1', now=1001)
            Draft202012Validator(schema).validate(e)
            self.assertEqual(contract.admit_evidence(e, **options), e)

    def test_host_source_run_architecture_and_cleanup_cannot_be_substituted(self):
        evidence, options = self.fixture()
        cases = [('reference_host', {'machine_id':'9'*32}),
                 ('authorization', {'candidate_sha':'9'*40}),
                 ('authorization', {'candidate_tree':'9'*40}),
                 ('authorization', {'control_sha':'9'*40}),
                 ('authorization', {'probe_sha256':'9'*64}),
                 ('architecture', 'aarch64'), ('qualification_run_id', '201'),
                 ('cleanup', {'service_stopped':False}), ('host_admission', {'evidence_sha256':'9'*64}),
                 ('observations', {'listeners':['0.0.0.0:5432']}),
                 ('observations', {'application':{'runtime':{'image':'untrusted'}}})]
        for key, delta in cases:
            changed = copy.deepcopy(evidence)
            if isinstance(delta, dict): changed[key].update(delta)
            else: changed[key] = delta
            with self.subTest(key=key, delta=delta), self.assertRaises(contract.QualificationError):
                contract.admit_evidence(changed, **options)
        for key in ('provider', 'password', 'PASS', 'command', 'script'):
            changed = copy.deepcopy(evidence); changed[key] = 'caller-value'
            with self.subTest(key=key), self.assertRaises(contract.QualificationError):
                contract.admit_evidence(changed, **options)

    def test_authorization_is_closed_bounded_and_not_provider_authority(self):
        e, _ = self.fixture(); auth = e['authorization']
        options = dict(control_sha='e'*40, profile=auth['profile'], run_id='100', run_attempt='1', now=1001)
        for delta in ({'pull_request':400}, {'expires_at':1001}, {'profile':'hetzner-rocky'},
                      {'provider':'gcp'}, {'reference_host':{'machine_id':'9'*32}}, {'command':'true'}):
            with self.subTest(delta=delta), self.assertRaises(contract.QualificationError):
                contract.admit_authorization(dict(auth, **delta), **options)
        for host in (dict(auth['reference_host'], address='app.secpal.dev'),
                     dict(auth['reference_host'], ssh_host_key='ssh-ed25519 invalid')):
            with self.assertRaises(contract.QualificationError):
                contract.admit_authorization(dict(auth, reference_host=host), **options)

    def test_precondition_has_actual_identity_os_and_selinux_observations(self):
        e, _ = self.fixture(); facts = e['host_admission']['reference_host_facts']
        for delta in ({'machine_id':'9'*32}, {'architecture':'aarch64'}, {'selinux':'Permissive'},
                      {'ssh_host_key':'wrong'}, {'os_release':{'ID':'ubuntu','VERSION_ID':'10.2'}},
                      {'os_release':{'ID':'rocky','VERSION_ID':'10.1'}}):
            with self.subTest(delta=delta), self.assertRaises(contract.QualificationError):
                contract.admit_reference_host_facts(dict(facts, **delta), e['authorization'])

    def test_reference_baseline_reuses_runtime_authority_and_denies_socket_or_root(self):
        e, _ = self.fixture(); facts = e['host_admission']['reference_host_facts']
        self.assertEqual(contract.admit_reference_host_facts(facts, e['authorization']), facts)
        for delta in ({'socket_exists':True}, {'podman_socket_enabled':True}, {'sudo_authorized':True},
                      {'uid':0}, {'groups':[1000,0]}, {'container_host_present':True},
                      {'cgroup_filesystem':'tmpfs'}, {'systemd_user':'inactive'}):
            bad = copy.deepcopy(facts); bad['runtime'].update(delta)
            with self.subTest(delta=delta), self.assertRaises(contract.QualificationError):
                contract.admit_reference_host_facts(bad, e['authorization'])

    def test_transport_pins_ssh_and_cannot_select_a_command(self):
        transport = load('pg_reference_transport', 'scripts/ci-cloud/postgresql-reference-host.py')
        e, _ = self.fixture()
        with tempfile.TemporaryDirectory() as d:
            key = Path(d)/'identity'; key.write_text('synthetic fixture'); key.chmod(0o600)
            ssh = transport.Transport(e['authorization'], key)
            with mock.patch.object(transport.guest, 'bounded_process') as run:
                run.return_value = mock.Mock(returncode=0, stdout='{}', stderr='')
                ssh.observe('check')
                args = run.call_args.args[0]
                self.assertIn('StrictHostKeyChecking=yes', args)
                self.assertIn('BatchMode=yes', args)
                self.assertIn('GlobalKnownHostsFile=/dev/null', args)
                self.assertIn('HostKeyAlias=secpal-postgresql-reference', args)
                self.assertIn('-F', args)
                self.assertEqual(args[-1], transport.COMMANDS['check'])
                self.assertNotIn('gcloud', args)
                self.assertNotIn('GITHUB_TOKEN', run.call_args.kwargs['environment'])
            with self.assertRaises(contract.QualificationError): ssh.observe('arbitrary command')

    def test_one_use_claim_survives_failure_and_rejects_reuse(self):
        transport = load('pg_reference_claim', 'scripts/ci-cloud/postgresql-reference-host.py')
        with tempfile.TemporaryDirectory() as d:
            transport.claim(Path(d), '100', '1')
            with self.assertRaises(contract.QualificationError): transport.claim(Path(d), '100', '1')
            with self.assertRaises(contract.QualificationError): transport.claim(Path(d), '../escape', '1')

    def test_transport_has_no_caller_json_pass_mode(self):
        transport = load('pg_reference_no_pass', 'scripts/ci-cloud/postgresql-reference-host.py')
        self.assertEqual(set(transport.COMMANDS), {'check', 'run'})
        self.assertIn('contract.admit_evidence(', (ROOT/'scripts/ci-cloud/postgresql-reference-host.py').read_text())
        self.assertIn('reference_host_check()', (ROOT/'scripts/ci-cloud/qualify-native-postgresql.py').read_text())
        self.assertNotIn('--evidence', (ROOT/'scripts/ci-cloud/postgresql-reference-host.py').read_text())

    def test_authenticated_transport_fixture_is_admitted_but_substitution_is_not(self):
        transport = load('pg_reference_execute_fixture', 'scripts/ci-cloud/postgresql-reference-host.py')
        evidence, _ = self.fixture()
        auth = evidence['authorization']
        evidence['qualification_run_id'] = auth['run_id']
        logins = contract.qualification_logins(auth['run_id'], auth['run_attempt'], auth['expires_at'])
        evidence['observations']['issued_logins'] = logins
        evidence['observations']['memberships'] = contract.qualification_memberships(logins)
        prepared = {'authorization': auth, 'declaration': dict(contract.DECLARATION)}
        checked = {'authorization': auth, 'probe_sha256': auth['probe_sha256'],
            'host_facts': evidence['host_admission']['reference_host_facts'],
            'resource': dict(control_sha=auth['control_sha'], profile=auth['profile'],
                access_run_id=auth['run_id'], access_run_attempt=auth['run_attempt'],
                reference_host=auth['reference_host'])}
        cases = [(checked, evidence, True)]
        bad = copy.deepcopy(checked); bad['resource']['reference_host']['machine_id'] = '9'*32
        cases.append((bad, evidence, False))
        bad = copy.deepcopy(evidence); bad['cleanup']['credentials_forgotten'] = False
        cases.append((checked, bad, False))
        bad = copy.deepcopy(evidence); bad['provider'] = 'trusted-provider'
        cases.append((checked, bad, False))
        bad = copy.deepcopy(evidence); bad['password'] = 'MUST-NOT-RETAIN'
        cases.append((checked, bad, False))
        for observed_host, observed_result, valid in cases:
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.object(transport, 'authenticate_control'), \
                 mock.patch.object(transport.control, 'resolve', return_value=prepared), \
                 mock.patch.object(transport.control, 'probe_digest', return_value=auth['probe_sha256']), \
                 mock.patch.object(transport.time, 'time', return_value=1001), \
                 mock.patch.object(transport, 'Transport') as ssh:
                ssh.return_value.observe.side_effect = [observed_host, observed_result]
                ssh.return_value.failure = None
                root = Path(directory)
                if valid:
                    self.assertEqual(transport.execute(prepared, root/'private-fixture', root), evidence)
                    self.assertTrue((root/'admitted.json').is_file())
                else:
                    with self.assertRaises(contract.QualificationError):
                        transport.execute(prepared, root/'private-fixture', root)
                    self.assertFalse((root/'admitted.json').exists())
                    diagnostic = (root/'diagnostic.json').read_text()
                    self.assertNotIn('MUST-NOT-RETAIN', diagnostic)

    def test_wrong_ssh_authentication_and_malformed_output_never_become_pass(self):
        transport = load('pg_reference_ssh_failure', 'scripts/ci-cloud/postgresql-reference-host.py')
        e, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory)/'identity'; key.write_text('synthetic'); key.chmod(0o600)
            ssh = transport.Transport(e['authorization'], key)
            for status, output in ((255, '{}'), (0, 'not-json'), (0, '{"x":1,"x":2}')):
                with self.subTest(status=status), mock.patch.object(transport.guest, 'bounded_process') as process:
                    process.return_value = mock.Mock(returncode=status, stdout=output, stderr='untrusted secret message')
                    with self.assertRaises(contract.QualificationError): ssh.observe('check')

    def test_control_is_accepted_source_not_caller_selected_sha(self):
        transport = load('pg_reference_control_failure', 'scripts/ci-cloud/postgresql-reference-host.py')
        observer = mock.Mock()
        observer.request.return_value = {'sha':'a'*40,'commit':{'verification':{'verified':True,'reason':'valid'}}}
        with self.assertRaises(contract.QualificationError): transport.authenticate_control(observer, 'b'*40)
        observer.request.return_value['commit']['verification']['verified'] = False
        with self.assertRaises(contract.QualificationError): transport.authenticate_control(observer, 'a'*40)

    def test_control_closure_rejects_malformed_and_altered_qualifier_bytes(self):
        transport = load('pg_reference_control_closure', 'scripts/ci-cloud/postgresql-reference-host.py')
        for response in ([], {'sha':'a'*40,'commit':None}):
            observer = mock.Mock(); observer.request.return_value = response
            with self.subTest(response=response), self.assertRaises(contract.QualificationError):
                transport.authenticate_control(observer, 'a'*40)
        import hashlib
        blobs = {}
        entries = []
        for path in (*transport.control.PROBE_PATHS, 'scripts/ci-cloud/postgresql-reference-host.py'):
            content = (ROOT/path).read_bytes()
            oid = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
            entries.append({'path':path,'type':'blob','mode':'100644','sha':oid})
            blobs[oid] = {'encoding':'base64','size':len(content),'content':base64.b64encode(content).decode()}
        head = {'sha':'a'*40,'commit':{'tree':{'sha':'b'*40},'verification':{'verified':True,'reason':'valid'}}}
        def response(path):
            if path.endswith('/commits/main'): return head
            if '/git/trees/' in path: return {'truncated':False,'tree':entries}
            return blobs[path.rsplit('/',1)[1]]
        observer = mock.Mock(); observer.request.side_effect = response
        transport.authenticate_control(observer, 'a'*40)
        qualifier = next(e['sha'] for e in entries if e['path'].endswith('/qualify-native-postgresql.py'))
        blobs[qualifier]['content'] = base64.b64encode(b'altered qualifier').decode()
        with self.assertRaises(contract.QualificationError):
            transport.authenticate_control(observer, 'a'*40)

    def test_legacy_and_reference_admission_agree_on_database_facts(self):
        legacy = load('legacy_pg_agreement_fixture', 'tests/postgresql-qualification-contract.py')
        reference, ref_options = self.fixture()
        cloud, cloud_options = legacy.CandidateData().system_fixture('gcp-rocky-10-2-x86-64')
        for field, value in (('listeners', ['0.0.0.0:5432']), ('roles', {}), ('hba', []),
                             ('locking', {}), ('application', {}), ('restart_row_count', '0')):
            for evidence, options in ((reference, ref_options), (cloud, cloud_options)):
                changed = copy.deepcopy(evidence); changed['observations'][field] = value
                with self.subTest(field=field), self.assertRaises(contract.QualificationError):
                    contract.admit_evidence(changed, **options)


if __name__ == '__main__':
    unittest.main()
