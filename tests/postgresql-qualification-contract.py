#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Adversarial contract evidence for the trusted PostgreSQL data boundary."""

import base64
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import postgresql_qualification_contract as contract


class CandidateData(unittest.TestCase):
    def test_psql_only_evidence_cannot_establish_application_readiness(self):
        evidence, options = self.system_fixture('gcp-rocky-10-2-arm64')
        # The historical contract has only psql readiness and sleep-container
        # liveness. It must fail after actual application observations are required.
        evidence['observations'].pop('application', None)
        with self.assertRaises(contract.QualificationError):
            contract.admit_evidence(evidence, **options)

    def test_application_evidence_rejects_identity_policy_and_health_substitution(self):
        app = {'runtime': copy.deepcopy(contract.APPLICATION_RUNTIME),
               'probes': copy.deepcopy(contract.APPLICATION_PROBES),
               'health': copy.deepcopy(contract.APPLICATION_HEALTH), 'same_process': True}
        self.assertEqual(contract.admit_application(app), app)
        for path, value in ((('runtime','image'), 'ghcr.io/secpal/api:main'),
                            (('runtime','source_commit'), '1'*40),
                            (('runtime','platform_digests','arm64'), 'sha256:'+'1'*64),
                            (('probes','pdo','sslmode'), 'prefer'),
                            (('probes','pdo','host'), 'host.containers.internal'),
                            (('probes','pdo','sslrootcert'), '/caller/root.crt'),
                            (('probes','wrong-ca','reason'), 'hostname'),
                            (('probes','plaintext','connected'), True),
                            (('probes','environment-substitution','tls'), False),
                            (('health','ready-down','http_status'), 200),
                            (('health','live-down','body_status'), 'not_ready'),
                            (('same_process',), False)):
            changed = copy.deepcopy(app)
            owner = changed
            for key in path[:-1]:
                owner = owner[key]
            owner[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(contract.QualificationError):
                contract.admit_application(changed)
        app['probes']['pdo']['tls'] = 'TLSv1.2'
        self.assertEqual(contract.admit_application(app), app)
        for key in ('PASS', 'credentials', 'php', 'grader'):
            with self.subTest(key=key), self.assertRaises(contract.QualificationError):
                contract.admit_application(dict(app, **{key: 'caller bytes'}))

    def test_actual_application_http_representation_is_closed(self):
        good = {'http_status': 503, 'body_status': 'not_ready'}
        self.assertEqual(contract.normalize_application_http(json.dumps(good)), good)
        for raw in ('true', '{"http_status":true,"body_status":"ready"}',
                    '{"http_status":503,"body_status":"not_ready","PASS":true}',
                    '{"http_status":200,"body_status":"sleep-running"}',
                    '{"http_status":200,"http_status":503,"body_status":"ready"}'):
            with self.subTest(raw=raw), self.assertRaises(contract.QualificationError):
                contract.normalize_application_http(raw)

    def test_stable_privilege_roles_cannot_authenticate(self):
        bundle = contract.render_configuration(contract.DECLARATION, 1234)
        for name in contract.ROLE_POLICY:
            self.assertFalse(contract.ROLE_POLICY[name][-1])
            self.assertIn(f'CREATE ROLE {name} NOLOGIN ', bundle['roles.sql'])
        self.assertIn('+secpal_runtime,+secpal_migration', bundle['pg_hba.conf'])
        self.assertIn('WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', bundle['roles.sql'])

    def system_fixture(self, profile):
        architecture = contract.rpm.PROFILE_ARCHITECTURES[profile]
        auth = {'schema_version': 1, 'selector': contract.SELECTOR, 'repository': 'SecPal/deployment',
                'issue': 81, 'pull_request': 400, 'candidate_sha': 'a' * 40, 'candidate_tree': 'b' * 40,
                'candidate_blob': 'c' * 40, 'consumer_blob': 'd' * 40,
                'declaration_sha256': contract.declaration_digest(contract.DECLARATION),
                'control_sha': 'e' * 40, 'probe_sha256': 'f' * 64, 'profile': profile,
                'run_id': '100', 'run_attempt': '1', 'issued_at': 1000, 'expires_at': 11800}
        packages = {}
        for name in contract.PACKAGES:
            identity = [name, '0', '18.6', '1.el10_2', architecture, f'{name}-18.6-1.el10_2.{architecture}']
            packages[name] = dict(zip(('name', 'epoch', 'version', 'release', 'architecture', 'nevra'), identity))
            packages[name].update(repositories=['appstream'], signed_header='\n'.join(identity + [
                'a' * 64, '8', 'b' * 64, 'RSA/SHA256, synthetic, Key ID 5b106c736fedfc85']),
                verification='\n'.join(sorted(contract.rpm.VERIFIED_HEADER_LINES)))
        observations = {'server_version_num': '180006',
            'service': {'User': 'postgres', 'Group': 'postgres', 'ActiveState': 'active',
                        'UnitFileState': 'enabled', 'FragmentPath': '/usr/lib/systemd/system/postgresql.service'},
            'data_directory': {'owner': 'postgres', 'group': 'postgres', 'mode': '700', 'type': 'postgresql_db_t'},
            'tls_material': {name: {'owner': 'postgres', 'group': 'postgres', 'mode': '600', 'type': 'postgresql_db_t'}
                             for name in ('server.crt', 'server.key', 'ca.crt')},
            'process_label': 'postgresql_t', 'listeners': ['127.0.0.1:5432', '[::1]:5432'],
            'settings': {'listen_addresses': '127.0.0.1,::1', 'port': '5432', 'ssl': 'on',
                'ssl_min_protocol_version': 'TLSv1.2', 'password_encryption': 'scram-sha-256',
                'data_directory': '/var/lib/pgsql/data', 'ssl_cert_file': '/etc/secpal/postgresql/current/server.crt',
                'ssl_key_file': '/etc/secpal/postgresql/current/server.key', 'ssl_ca_file': '/etc/secpal/postgresql/current/ca.crt'},
            'roles': {'secpal_owner': [False,False,False,False,False,False,False],
                      'secpal_runtime': [False,False,False,False,False,False,False],
                      'secpal_migration': [False,False,False,False,False,False,False],
                      'secpal_backup': [False,False,False,False,False,False,False],
                      'secpal_replication': [False,False,False,False,True,False,False]},
            'issued_logins': contract.qualification_logins('200','1',auth['expires_at']),
            'memberships': contract.qualification_memberships(contract.qualification_logins('200','1',auth['expires_at'])),
            'password_algorithms': {'runtime': 'SCRAM-SHA-256','migration':'SCRAM-SHA-256'},
            'hba': [['local',['all'],['postgres'],None,None,'peer',None],
                    ['local',['all'],['all'],None,None,'reject',None],
                    ['hostssl',['secpal'],['+secpal_runtime','+secpal_migration'],'127.0.0.1','255.255.255.255','scram-sha-256',None],
                    ['hostssl',['secpal'],['+secpal_runtime','+secpal_migration'],'::1','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff','scram-sha-256',None],
                    ['host',['all'],['all'],'0.0.0.0','0.0.0.0','reject',None],
                    ['host',['all'],['all'],'::','::','reject',None]],
            'probes': dict(contract.PROBES), 'locking': {'row_sqlstate':'55P03','advisory_held':'f','advisory_released':'t'},
            'rootless_liveness':True, 'container_servers':[], 'loopback_sentinel_host':0,
            'native_cgroup':'0::/system.slice/postgresql.service', 'restart_row_count':'1',
            'native_storage': {'data_directory':'/var/lib/pgsql/data', 'headroom': {
                'filesystem_total_bytes':100*1024**3, 'free_bytes':30*1024**3, 'free_percent':30,
                'filesystem_total_inodes':1000000, 'free_inodes':300000, 'free_inode_percent':30}},
            'application': {'runtime': dict(contract.APPLICATION_RUNTIME),
                'probes': copy.deepcopy(contract.APPLICATION_PROBES),
                'health': copy.deepcopy(contract.APPLICATION_HEALTH), 'same_process': True}}
        evidence = {'schema_version':1,'claim':contract.SELECTOR,'authorization':auth,
                    'qualification_run_id':'200','qualification_run_attempt':'1',
                    'instance_id':'123456789','instance_name':'sprk-100-1-instance','architecture':architecture,
                    'host_admission':{'target_sha':'402c22b0a1d69a5a3dba74ffb68cf016caba606b',
                                     'harness_sha256':'436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac',
                                     'evidence_sha256':'0'*64},'packages':packages,
                    'signer_fingerprint':contract.rpm.ROCKY_FINGERPRINT,'observations':observations,
                    'cleanup':dict(contract.CLEANUP_POSTCONDITIONS)}
        options = dict(authorization=auth,instance_id=evidence['instance_id'],instance_name=evidence['instance_name'],
                       qualification_run_id='200',qualification_run_attempt='1',host_evidence_sha256='0'*64)
        return evidence, options

    def test_both_architecture_observations_cross_schema_and_admission(self):
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT / 'schemas/postgresql-qualification-evidence.schema.json').read_text())
        validator = Draft202012Validator(schema)
        for profile in contract.rpm.PROFILE_ARCHITECTURES:
            evidence, options = self.system_fixture(profile)
            validator.validate(evidence)
            self.assertEqual(contract.admit_evidence(evidence, **options), evidence)
            for path, value in ((('authorization','candidate_tree'),'1'*40),
                                (('instance_id',),'987654321'),(('architecture',),'other'),
                                (('host_admission','evidence_sha256'),'1'*64),
                                (('observations','listeners'),['0.0.0.0:5432']),
                                (('observations','process_label'),'unconfined_t'),
                                (('observations','roles','secpal_runtime'),[True]*7),
                                (('observations','memberships'),[['secpal_owner','secpal_runtime',True,True]]),
                                (('observations','issued_logins','runtime','expires_at'),11801),
                                (('observations','issued_logins','migration','name'),'secpal_qualification_migration_201_1'),
                                (('observations','issued_logins','runtime','attributes'),[True]*7),
                                (('observations','probes','wrong-hostname'),0),
                                (('observations','probes','ready-down'),0),
                                (('observations','hba'),[['host',['all'],['all'],'0.0.0.0','0.0.0.0','trust',None]]),
                                (('observations','password_algorithms','runtime'),'md5'),
                                (('observations','tls_material','server.key','mode'),'644'),
                                (('cleanup','client_material_absent'),False),
                                (('cleanup','database_material_absent'),False),
                                (('packages','postgresql18','repositories'),['untrusted']),
                                (('packages','postgresql18','release'),'2.el10_2')):
                changed = copy.deepcopy(evidence)
                owner = changed
                for part in path[:-1]:
                    owner = owner[part]
                owner[path[-1]] = value
                with self.subTest(profile=profile,path=path), self.assertRaises(contract.QualificationError):
                    contract.admit_evidence(changed, **options)
            changed = copy.deepcopy(evidence)
            changed['observations']['PASS'] = True
            self.assertFalse(validator.is_valid(changed))
            with self.assertRaises(contract.QualificationError):
                contract.admit_evidence(changed, **options)

    def test_failure_bindings_do_not_admit_substitution_or_pass(self):
        from jsonschema import Draft202012Validator
        evidence, options = self.system_fixture('gcp-rocky-10-2-arm64')
        auth = evidence['authorization']
        binding = dict(control_sha=auth['control_sha'],profile=auth['profile'], access_run_id='200',
                       access_run_attempt='1',instance_id=evidence['instance_id'],instance_name=evidence['instance_name'])
        options.pop('instance_id'); options.pop('instance_name'); options['binding'] = binding
        schema = json.loads((ROOT / 'schemas/postgresql-qualification-diagnostic.schema.json').read_text())
        for admitted in (auth,None):
            document = contract.bound_diagnostic('probe-transport','invariant-failed',authorization=admitted,
                binding=binding,qualification_run_id='200',qualification_run_attempt='1',
                host_evidence_sha256='0'*64,cleanup_complete=True)
            Draft202012Validator(schema).validate(document)
            self.assertEqual(contract.admit_diagnostic(document, **options),document)
            for key, value in (('resource',dict(binding,instance_id='99')),('qualification_run_id','201'),
                               ('host_evidence_sha256','1'*64),('reason','password=secret'),('PASS',True)):
                changed = dict(document); changed[key] = value
                with self.subTest(key=key), self.assertRaises(contract.QualificationError):
                    contract.admit_diagnostic(changed, **options)

    def test_architecture_gate_rejects_pure_execution_and_diagnostic_drift(self):
        spec = importlib.util.spec_from_file_location('pg_gate', ROOT / 'scripts/validate-postgresql-qualification.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        gate.validate(ROOT)
        pure = 'scripts/ci-cloud/postgresql_qualification_contract.py'
        diagnostic = 'schemas/postgresql-qualification-diagnostic.schema.json'
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            for name in (pure, diagnostic, 'scripts/ci-cloud/rocky_preparation_contract.py'):
                destination = temporary / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            source = (temporary / pure).read_text()
            (temporary / pure).write_text(source.replace('import hashlib', 'import os\nimport hashlib'))
            with self.assertRaisesRegex(ValueError, 'import closure'):
                gate.validate(temporary)
            (temporary / pure).write_text(source)
            schema = json.loads((temporary / diagnostic).read_text())
            schema['properties']['reason']['enum'].pop()
            (temporary / diagnostic).write_text(json.dumps(schema))
            with self.assertRaisesRegex(ValueError, 'diagnostic schema'):
                gate.validate(temporary)

    def test_real_representation_normalization_rejects_ambiguity(self):
        unit = 'User=postgres\nGroup=postgres\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/usr/lib/systemd/system/postgresql.service\nMainPID=100\n'
        fields, pid = contract.normalize_service(unit)
        self.assertEqual(pid,'100'); self.assertEqual(fields['User'],'postgres')
        for text in (unit+'User=attacker\n',unit.replace('MainPID=100','MainPID=0'),unit+'Unknown=ignored\n'):
            with self.assertRaises(contract.QualificationError):
                contract.normalize_service(text)
        self.assertEqual(contract.normalize_listeners('LISTEN 0 244 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 244 [::1]:5432 [::]:*'), ['127.0.0.1:5432','[::1]:5432'])
        for raw in ('{"role":false,"role":true}','NaN','{',' '*262145):
            with self.assertRaises(contract.QualificationError):
                contract.normalize_json_fact(raw)

    def test_actual_candidate_bytes_are_consumed_and_closed(self):
        bundle = contract.DECLARATION['configuration']
        self.assertEqual(contract.render_configuration(contract.DECLARATION, 1234),
                         {name: text.replace('@RUNTIME_UID@', '1234') for name, text in bundle.items()})
        for name, text in bundle.items():
            candidate = copy.deepcopy(contract.DECLARATION)
            candidate['configuration'][name] = text + '# arbitrary candidate substitution\n'
            with self.subTest(name=name), self.assertRaises(contract.QualificationError):
                contract.admit_declaration(candidate)

    def test_package_pins_are_bounded_data(self):
        for version, release in (('18.7', '2.el10_2'), ('18.6', '1.el10_2')):
            d = dict(contract.DECLARATION, package_version=version, package_release=release)
            self.assertEqual(contract.admit_declaration(d), d)
        for version, release in (('17.9', '1.el10_2'), ('18.6 --nogpgcheck', '1.el10_2'),
                                 ('18.6', '--disableplugin=*'), ('18.6', '1.other')):
            with self.assertRaises(contract.QualificationError):
                contract.admit_declaration(dict(contract.DECLARATION, package_version=version, package_release=release))

    def test_shared_configuration_rendering_preserves_narrow_policy(self):
        result = contract.render_configuration(contract.DECLARATION, 1234)
        self.assertIn("listen_addresses = '127.0.0.1,::1'", result['postgresql.conf'])
        self.assertIn('hostssl secpal +secpal_runtime,+secpal_migration 127.0.0.1/32 scram-sha-256', result['pg_hba.conf'])
        self.assertIn('meta skuid 1234 ip daddr 127.0.0.0/8 tcp dport 5432 accept', result['loopback.nft'])
        self.assertIn('meta skuid 1234 ip daddr 127.0.0.0/8 reject', result['loopback.nft'])
        self.assertIn('NOINHERIT', result['roles.sql'])
        self.assertNotIn('PASSWORD', result['roles.sql'])
        self.assertNotIn('trust', result['pg_hba.conf'])
        for invalid in (0, -1, '1234; arbitrary', True):
            with self.assertRaises(contract.QualificationError):
                contract.render_configuration(contract.DECLARATION, invalid)

    def test_observer_claims_cannot_substitute_for_native_facts(self):
        for raw in ({'PASS': True}, {'probes': contract.PROBES}, dict.fromkeys(contract.OBSERVATION_FIELDS, True)):
            with self.assertRaises(contract.QualificationError):
                contract.admit_observations(raw, run_id='200', run_attempt='1', expires_at=11800)

    def test_unique_signed_primary_candidate(self):
        pr = {'number': 400, 'state': 'OPEN', 'repository': 'SecPal/deployment',
              'head_repository': 'SecPal/deployment', 'base': 'main',
              'head': 'a' * 40, 'body': 'Fixes #81\n\nPart of: #134',
              'closing_issues': ['SecPal/deployment#81'], 'draft': True,
              'ready_events': 0, 'draft_events': 0,
              'commits': [{'sha': 'a' * 40, 'verified': True, 'reason': 'valid'}]}
        self.assertEqual(contract.select_candidate([pr]), pr)
        for key, value in (('head_repository', 'attacker/deployment'), ('base', 'other'),
                           ('commits', [{'sha': 'a' * 40, 'verified': False, 'reason': 'invalid'}]),
                           ('head', 'b' * 40), ('draft', False), ('draft_events', 1)):
            d = copy.deepcopy(pr)
            d[key] = value
            with self.subTest(key=key), self.assertRaises(contract.QualificationError):
                contract.select_candidate([d])
        for candidates in ([], [pr, pr]):
            with self.assertRaises(contract.QualificationError):
                contract.select_candidate(candidates)
        ready = dict(pr, draft=False, ready_events=1)
        self.assertEqual(contract.select_candidate([ready]), ready)

    def test_authorization_binds_source_control_run_and_expiry(self):
        d = {'schema_version': 1, 'selector': contract.SELECTOR,
             'repository': 'SecPal/deployment', 'issue': 81, 'pull_request': 400,
             'candidate_sha': 'a' * 40, 'candidate_tree': 'f' * 40, 'candidate_blob': 'b' * 40, 'consumer_blob': 'e' * 40,
             'declaration_sha256': contract.declaration_digest(contract.DECLARATION),
             'control_sha': 'c' * 40, 'probe_sha256': 'd' * 64,
             'profile': 'gcp-rocky-10-2-x86-64', 'run_id': '100', 'run_attempt': '1',
             'issued_at': 1000, 'expires_at': 11800}
        options = dict(control_sha='c' * 40, profile=d['profile'], run_id='100', run_attempt='1', now=1001)
        self.assertEqual(contract.admit_authorization(d, **options), d)
        for key, value in (('control_sha', 'e' * 40), ('run_id', '101'),
                           ('profile', 'gcp-rocky-10-2-arm64'), ('candidate_blob', '../bad'),
                           ('declaration_sha256', 'e' * 64), ('expires_at', 1000),
                           ('command', 'caller script')):
            changed = dict(d)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(contract.QualificationError):
                contract.admit_authorization(changed, **options)

    def test_separate_package_inventory_reuses_rpm_authority(self):
        self.assertEqual(len(contract.rpm.PACKAGES), 22)
        name = 'postgresql18-server'
        nevra = f'{name}-18.6-1.el10_2.x86_64'
        identity = [name, '0', '18.6', '1.el10_2', 'x86_64', nevra]
        raw = dict(zip(('name', 'epoch', 'version', 'release', 'architecture', 'nevra'), identity))
        raw.update(repositories=['appstream'], signed_header='\n'.join(identity + [
            'a' * 64, '8', 'b' * 64, 'RSA/SHA256, synthetic, Key ID 5b106c736fedfc85']),
            verification='\n'.join(sorted(contract.rpm.VERIFIED_HEADER_LINES)))
        result = contract.admit_postgresql_package(name, raw, 'x86_64', contract.rpm.ROCKY_FINGERPRINT)
        self.assertEqual(result['resolved_repository'], 'appstream')
        with self.assertRaises(contract.rpm.ContractError):
            contract.rpm.normalize_package(name, raw, 'x86_64')
        for key, value in (('repositories', ['baseos']), ('version', '17.9'),
                           ('architecture', 'aarch64'), ('verification', 'forged')):
            altered = copy.deepcopy(raw)
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(contract.QualificationError):
                contract.admit_postgresql_package(name, altered, 'x86_64', contract.rpm.ROCKY_FINGERPRINT)

    def test_closed_declaration_is_data(self):
        self.assertEqual(contract.admit_declaration(contract.DECLARATION), contract.DECLARATION)
        for path, value in (
            (('major',), 17), (('port',), 5433),
            (('data_directory',), '../../etc'),
            (('listen_addresses',), ['0.0.0.0']),
            (('transport', 'sslmode'), 'require'),
            (('transport', 'authentication'), 'md5'),
            (('network', 'mapping'), '--map-gw'),
            (('roles', 'runtime'), 'secpal_migration'),
        ):
            with self.subTest(path=path):
                d = copy.deepcopy(contract.DECLARATION)
                owner = d
                for part in path[:-1]:
                    owner = owner[part]
                owner[path[-1]] = value
                with self.assertRaises(contract.QualificationError):
                    contract.admit_declaration(d)
        for key in ('command', 'sql', 'unit', 'include', 'password', 'ssl_key'):
            with self.subTest(key=key):
                d = copy.deepcopy(contract.DECLARATION)
                d[key] = 'arbitrary candidate bytes'
                with self.assertRaises(contract.QualificationError):
                    contract.admit_declaration(d)

    def test_duplicate_and_non_json_input_rejected(self):
        for raw in ('{"major":18,"major":17}', '{}', '[]', 'null', '{', ' ' * 8193):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(contract.QualificationError):
                    contract.parse_declaration(raw)
        self.assertEqual(contract.parse_declaration(json.dumps(contract.DECLARATION)), contract.DECLARATION)

    def test_diagnostics_are_closed_and_non_secret(self):
        for operation in contract.OPERATIONS:
            for reason in contract.REASONS:
                result = contract.diagnostic(operation, reason)
                self.assertEqual(set(result), {'schema_version', 'claim', 'operation', 'reason'})
                self.assertNotIn('stderr', result)
        with self.assertRaises(contract.QualificationError):
            contract.diagnostic('caller-command', 'secret')


    def reference_fixture(self, arch='amd64'):
        profile = 'gcp-rocky-10-2-' + ('x86-64' if arch == 'amd64' else 'arm64')
        evidence, options = self.system_fixture(profile)
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
            e, options = self.reference_fixture(arch)
            contract.admit_authorization(e['authorization'], control_sha='e'*40,
                profile=e['authorization']['profile'], run_id='100', run_attempt='1', now=1001)
            Draft202012Validator(schema).validate(e)
            self.assertEqual(contract.admit_evidence(e, **options), e)

    def test_host_source_run_architecture_and_cleanup_cannot_be_substituted(self):
        evidence, options = self.reference_fixture()
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
        e, _ = self.reference_fixture(); auth = e['authorization']
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
        e, _ = self.reference_fixture(); facts = e['host_admission']['reference_host_facts']
        for delta in ({'machine_id':'9'*32}, {'architecture':'aarch64'}, {'selinux':'Permissive'},
                      {'ssh_host_key':'wrong'}, {'os_release':{'ID':'ubuntu','VERSION_ID':'10.2'}},
                      {'os_release':{'ID':'rocky','VERSION_ID':'10.1'}}):
            with self.subTest(delta=delta), self.assertRaises(contract.QualificationError):
                contract.admit_reference_host_facts(dict(facts, **delta), e['authorization'])

    def test_reference_baseline_reuses_runtime_authority_and_denies_socket_or_root(self):
        e, _ = self.reference_fixture(); facts = e['host_admission']['reference_host_facts']
        self.assertEqual(contract.admit_reference_host_facts(facts, e['authorization']), facts)
        for delta in ({'socket_exists':True}, {'podman_socket_enabled':True}, {'sudo_authorized':True},
                      {'uid':0}, {'groups':[1000,0]}, {'container_host_present':True},
                      {'cgroup_filesystem':'tmpfs'}, {'systemd_user':'inactive'}):
            bad = copy.deepcopy(facts); bad['runtime'].update(delta)
            with self.subTest(delta=delta), self.assertRaises(contract.QualificationError):
                contract.admit_reference_host_facts(bad, e['authorization'])

    def test_legacy_and_reference_admission_agree_on_database_facts(self):
        reference, ref_options = self.reference_fixture()
        cloud, cloud_options = self.system_fixture('gcp-rocky-10-2-x86-64')
        for field, value in (('listeners', ['0.0.0.0:5432']), ('roles', {}), ('hba', []),
                             ('locking', {}), ('application', {}), ('restart_row_count', '0')):
            for evidence, options in ((reference, ref_options), (cloud, cloud_options)):
                changed = copy.deepcopy(evidence); changed['observations'][field] = value
                with self.subTest(field=field), self.assertRaises(contract.QualificationError):
                    contract.admit_evidence(changed, **options)


if __name__ == '__main__':
    unittest.main()
