#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Adversarial contract evidence for the trusted PostgreSQL data boundary."""

import copy
import base64
import gzip
import json
import importlib.util
import os
import re
from pathlib import Path
import sys
import shutil
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import postgresql_qualification_contract as contract


class CandidateData(unittest.TestCase):
    def load_module(self, name, filename):
        spec = importlib.util.spec_from_file_location(name, ROOT / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_guest_staged_probe_closure_matches_controller_identity(self):
        control = self.load_module('pg_guest_probe_closure', 'scripts/ci-cloud/postgresql-qualification-control.py')
        terraform = (ROOT / 'infra/ci-cloud/gcp-rocky/main.tf').read_text()
        template = (ROOT / 'scripts/ci-cloud/bootstrap-rocky-host.tftpl').read_text()
        sources = dict(re.findall(
            r'(\w+_base64gzip)\s*=\s*base64gzip\(file\("\$\{path.module\}/\.\./\.\./\.\./([^"\n]+)"\)\)', terraform))
        destinations = re.findall(
            r"decode_script '\$\{(\w+_base64gzip)\}' /opt/secpal-control/([^\s]+)", template)
        expected = control.probe_digest()
        with tempfile.TemporaryDirectory() as directory:
            guest = Path(directory)
            for variable, destination in destinations:
                if destination not in control.PROBE_PATHS:
                    continue
                payload = base64.b64encode(gzip.compress((ROOT / sources[variable]).read_bytes(), mtime=0))
                path = guest / destination
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(gzip.decompress(base64.b64decode(payload)))
            with mock.patch.object(control, 'ROOT', guest):
                self.assertEqual(control.probe_digest(), expected)

    def test_failed_image_pull_cleanup_accepts_absence_but_requires_readback(self):
        module = self.load_module('pg_failed_image_pull_cleanup', 'scripts/ci-cloud/qualify-native-postgresql.py')
        observer = module.Observer.__new__(module.Observer)
        observer.children = []
        observer.passwords = {}
        observer.data_created = False
        observer.application_image_created = True
        image_still_present = False

        def system(operation, arguments, *, accepted=(0,), **options):
            status, output = 0, ''
            if arguments[:2] == ['podman', 'rmi']:
                status = 0 if '--ignore' in arguments else 1
            elif arguments[:2] == ['systemctl', 'is-active']:
                status, output = 3, 'inactive'
            elif arguments[:2] == ['nft', 'list'] or arguments[:3] == ['podman', 'container', 'exists']:
                status = 1
            elif arguments[:3] == ['podman', 'image', 'exists']:
                status = 0 if image_still_present else 1
            if status not in accepted:
                raise contract.QualificationError(operation, 'command-failed')
            return status, output, ''

        observer.run = mock.Mock(side_effect=system)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.multiple(module, DATA=base/'data', CLIENT=base/'client',
                                     MATERIAL=base/'material', STATE=base/'state', APPLICATION_IMAGE_STATE=base/'image-state'):
                self.assertEqual(observer.cleanup(), contract.CLEANUP_POSTCONDITIONS)
                observer.run.assert_any_call('cleanup-test-material',
                    ['podman', 'image', 'exists', contract.APPLICATION_RUNTIME['image']],
                    user='secpal-runtime', accepted=(1,))
                image_still_present = True
                with self.assertRaises(contract.QualificationError):
                    observer.cleanup()

    def test_attested_application_index_accepts_exact_platform_child_representation(self):
        import hashlib
        from types import SimpleNamespace
        module = self.load_module('pg_application_child_identity', 'scripts/ci-cloud/qualify-native-postgresql.py')
        repository = contract.APPLICATION_RUNTIME['image'].split('@')[0]
        index = json.dumps({'manifests': [
            {'platform': {'os': 'linux', 'architecture': architecture}, 'digest': digest}
            for architecture, digest in contract.APPLICATION_RUNTIME['platform_digests'].items()
        ]}).encode()
        identity = copy.deepcopy(contract.APPLICATION_RUNTIME)
        identity['image'] = repository + '@sha256:' + hashlib.sha256(index).hexdigest()
        tooling = SimpleNamespace(CLOUD_GH_RELEASES={'x86_64': {}, 'aarch64': {}},
                                  stage_gh_cli=mock.Mock(return_value='/trusted-fixture/gh'))
        for machine, architecture in [('x86_64', 'amd64'), ('aarch64', 'arm64')]:
            child = repository + '@' + identity['platform_digests'][architecture]
            for digests, os_name, observed_arch, valid in [
                ([child], 'linux', architecture, True),
                ([identity['image'], child], 'linux', architecture, True),
                ([identity['image']], 'linux', architecture, False),
                ([repository + '@sha256:' + '0'*64], 'linux', architecture, False),
                ([child], 'windows', architecture, False),
                ([child], 'linux', 'other', False),
                (child, 'linux', architecture, False),
            ]:
                with self.subTest(machine=machine, digests=digests, os=os_name, architecture=observed_arch), \
                     tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    client = base / 'client'
                    client.mkdir()
                    observer = module.Observer.__new__(module.Observer)
                    observer.environment = {'PATH': '/usr/bin:/bin'}
                    observer.runtime = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
                    def command(operation, arguments, **options):
                        if arguments[0] == 'python3':
                            Path(arguments[2]).write_bytes(index)
                            Path(arguments[3]).write_text('{}')
                        if arguments[:3] == ['podman', 'image', 'inspect']:
                            return 0, json.dumps([{'Os': os_name, 'Architecture': observed_arch, 'RepoDigests': digests}]), ''
                        return (1, '', '') if arguments[:3] == ['podman', 'image', 'exists'] else (0, '', '')
                    observer.run = mock.Mock(side_effect=command)
                    with mock.patch.multiple(module, APPLICATION_IMAGE_STATE=base/'image-state', CLIENT=client), \
                         mock.patch.object(module, 'trusted_module', return_value=tooling), \
                         mock.patch.object(module.os, 'uname', return_value=SimpleNamespace(machine=machine)), \
                         mock.patch.object(contract, 'APPLICATION_RUNTIME', identity):
                        if valid:
                            observer.admit_application_image()
                        else:
                            with self.assertRaises(contract.QualificationError):
                                observer.admit_application_image()
                    observer.run.assert_any_call('admit-application-image',
                        ['podman', 'pull', '--authfile=' + str(client/'anonymous-auth.json'), identity['image']],
                        user='secpal-runtime', timeout=300)

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

    def test_application_commands_have_fixed_runtime_code_and_role_authority(self):
        module = self.load_module('pg_application_commands', 'scripts/ci-cloud/qualify-native-postgresql.py')
        observer = module.Observer.__new__(module.Observer)
        observer.logins = contract.qualification_logins('200', '1', 11800)
        observer.run = mock.Mock(side_effect=AssertionError('construction must not execute'))
        normal = observer.application_command('pdo')
        self.assertIn(contract.APPLICATION_RUNTIME['image'], normal)
        self.assertIn('--userns=keep-id:uid=10001,gid=10001', normal)
        self.assertIn('--env=DB_SSLMODE=verify-full', normal)
        self.assertFalse(any('DB_PASSWORD=' in a or 'APP_KEY=' in a for a in normal))
        self.assertFalse(any('application-migration' in a for a in normal))
        self.assertNotIn('psql', normal)
        serve = observer.application_command('serve', detached=True)
        self.assertIn('--entrypoint=/usr/local/bin/frankenphp', serve)
        self.assertEqual(serve[-3:], ['run', '--config', '/etc/frankenphp/Caddyfile'])
        self.assertNotIn('sleep', serve)
        for arguments in (('php -r caller', {}), ('pdo', {'scenario': '$(caller)'}),
                          ('pdo', {'role': 'migration'}), ('initialize', {}),
                          ('serve', {'detached': False})):
            with self.subTest(arguments=arguments), self.assertRaises(contract.QualificationError):
                observer.application_command(arguments[0], **arguments[1])

    def test_readiness_is_http_not_database_client_and_tracks_same_process(self):
        module = self.load_module('pg_application_http', 'scripts/ci-cloud/qualify-native-postgresql.py')
        observer = module.Observer.__new__(module.Observer)
        observer.run = mock.Mock(return_value=(0, '{"http_status":503,"body_status":"not_ready"}', ''))
        self.assertEqual(observer.application_http('ready'), {'http_status':503,'body_status':'not_ready'})
        argv = observer.run.call_args.args[1]
        self.assertEqual(argv[-2:], ['/run/secpal-qualification/probe.php','ready'])
        self.assertNotIn('psql', argv)
        observer.run.return_value = (0, '12000', '')
        self.assertEqual(observer.application_pid(), '12000')
        observer.run.return_value = (0, '0', '')
        with self.assertRaises(contract.QualificationError):
            observer.application_pid()
        with self.assertRaises(contract.QualificationError):
            observer.application_http('caller-selected')

    def test_graphql_document_uses_json_media_type(self):
        control = self.load_module('pg_request', 'scripts/ci-cloud/postgresql-qualification-control.py')
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{}'
        observer = control.GitHubObserver()
        with mock.patch.dict(os.environ, {'GH_TOKEN': 'synthetic-test-only'}), \
             mock.patch.object(observer.opener, 'open', return_value=response) as request:
            observer.request('/graphql', {'query': control.QUERY})
        self.assertEqual(request.call_args.args[0].get_header('Content-type'), 'application/json')

    def github_candidate_fixture(self, timeline, *, draft=True):
        # Reviewed GitHub timeline representations are fixtures, never PASS authority.
        head = '23f04d218ec299fd933353fd438e921da6ff2694'
        pull = {'number': 286, 'state': 'OPEN', 'isDraft': draft,
                'body': 'Fixes #81\n\nPart of: #134', 'headRefOid': head,
                'baseRefName': 'main', 'headRepository': {'nameWithOwner': 'SecPal/deployment'},
                'repository': {'nameWithOwner': 'SecPal/deployment'}, 'commits': {'totalCount': 1},
                'closingIssuesReferences': {'totalCount': 1, 'pageInfo': {'hasNextPage': False},
                    'nodes': [{'number': 81, 'repository': {'nameWithOwner': 'SecPal/deployment'}}]},
                'timelineItems': timeline}
        result = {'data': {'repository': {'nameWithOwner': 'SecPal/deployment',
            'defaultBranchRef': {'name': 'main'}, 'pullRequests': {
                'totalCount': 1, 'pageInfo': {'hasNextPage': False}, 'nodes': [pull]}}}}
        commits = [{'sha': head, 'commit': {'verification': {'verified': True, 'reason': 'valid'}}}]
        return result, commits

    def test_complete_selected_lifecycle_representation_reaches_admission(self):
        control = self.load_module('pg_lifecycle', 'scripts/ci-cloud/postgresql-qualification-control.py')
        # #286 and #193 had 3/0 and 20/0; fresh #286 is 4/0. Ready #247 is 9/1.
        for total, events, draft in ((3, [], True), (20, [], True), (4, [], True),
                                    (9, ['ReadyForReviewEvent'], False),
                                    (0, ['ReadyForReviewEvent'], False)):
            with self.subTest(total=total, events=events):
                timeline = {'totalCount': total, 'pageInfo': {'hasNextPage': False},
                            'nodes': [{'__typename': event} for event in events]}
                result, commits = self.github_candidate_fixture(timeline, draft=draft)
                # An unrelated open PR must use the same reviewed representation.
                unrelated = copy.deepcopy(result['data']['repository']['pullRequests']['nodes'][0])
                unrelated['number'] = 193
                unrelated['closingIssuesReferences'] = {
                    'totalCount': 0, 'pageInfo': {'hasNextPage': False}, 'nodes': []}
                unrelated['timelineItems'] = {
                    'totalCount': 20, 'pageInfo': {'hasNextPage': False}, 'nodes': []}
                result['data']['repository']['pullRequests']['nodes'].append(unrelated)
                result['data']['repository']['pullRequests']['totalCount'] = 2
                observer = control.GitHubObserver()
                with mock.patch.object(observer, 'request', side_effect=[result, commits]) as request:
                    candidate = observer.candidate()
                self.assertEqual(candidate['head'], commits[0]['sha'])
                self.assertEqual((candidate['ready_events'], candidate['draft_events']), (len(events), 0))
                self.assertEqual(candidate['draft'], draft)
                self.assertEqual(contract.select_candidate([candidate]), candidate)
                request.assert_any_call('/graphql', {'query': control.QUERY})

    def test_lifecycle_representation_and_candidate_fail_closed(self):
        control = self.load_module('pg_lifecycle_reject', 'scripts/ci-cloud/postgresql-qualification-control.py')
        timeline = {'totalCount': 3, 'pageInfo': {'hasNextPage': False}, 'nodes': []}
        result, commits = self.github_candidate_fixture(timeline)
        pull_path = ('data', 'repository', 'pullRequests', 'nodes', 0)
        cases = [
            (('timelineItems', 'pageInfo', 'hasNextPage'), True),
            (('timelineItems', 'pageInfo', 'hasNextPage'), 0),
            (('timelineItems', 'pageInfo'), {}),
            (('timelineItems', 'pageInfo', 'endCursor'), 'caller-cursor'),
            (('timelineItems', 'totalCount'), True),
            (('timelineItems', 'totalCount'), -1),
            (('timelineItems', 'totalCount'), '3'),
            (('timelineItems', 'nodes'), [{'__typename': 'ReadyForReviewEvent'}] * 101),
            (('timelineItems', 'nodes'), {}),
            (('timelineItems', 'nodes'), [None]),
            (('timelineItems', 'nodes'), [{}]),
            (('timelineItems', 'nodes'), [{'__typename': 'UnknownEvent'}]),
            (('timelineItems', 'nodes'), [{'__typename': ['ReadyForReviewEvent']}]),
            (('timelineItems', 'nodes'), [{'__typename': 'ReadyForReviewEvent', 'createdAt': 'invalid'}]),
            (('timelineItems', 'PASS'), True),
            (('timelineItems',), None),
            (('timelineItems', 'nodes'), [{'__typename': 'ReadyForReviewEvent'}]),
            (('timelineItems', 'nodes'), [{'__typename': 'ConvertToDraftEvent'}]),
            (('isDraft',), False),
            (('headRefOid',), 'a' * 40),
            (('baseRefName',), 'other'),
            (('repository', 'nameWithOwner'), 'attacker/deployment'),
            (('headRepository', 'nameWithOwner'), 'attacker/deployment'),
            (('closingIssuesReferences', 'totalCount'), 2),
        ]
        for path, value in cases:
            changed = copy.deepcopy(result)
            owner = changed
            for key in pull_path + path[:-1]:
                owner = owner[key]
            owner[path[-1]] = value
            with self.subTest(path=path, value=value), \
                 mock.patch.object(control.GitHubObserver, 'request', side_effect=[changed, commits]), \
                 self.assertRaises(contract.QualificationError):
                control.GitHubObserver().candidate()
        for events in (['ReadyForReviewEvent'] * 2,
                       ['ReadyForReviewEvent', 'ConvertToDraftEvent'],
                       ['ReadyForReviewEvent', 'ConvertToDraftEvent', 'ReadyForReviewEvent']):
            changed, signatures = self.github_candidate_fixture(dict(timeline,
                nodes=[{'__typename': event} for event in events]), draft=False)
            with self.subTest(events=events), \
                 mock.patch.object(control.GitHubObserver, 'request', side_effect=[changed, signatures]), \
                 self.assertRaises(contract.QualificationError):
                control.GitHubObserver().candidate()
        for count in (0, 2):
            changed = copy.deepcopy(result)
            connection = changed['data']['repository']['pullRequests']
            connection['nodes'] *= count
            connection['totalCount'] = count
            with self.subTest(deliveries=count), \
                 mock.patch.object(control.GitHubObserver, 'request', side_effect=[changed] + [commits] * count), \
                 self.assertRaises(contract.QualificationError):
                control.GitHubObserver().candidate()
        commits[0]['commit']['verification']['verified'] = False
        with mock.patch.object(control.GitHubObserver, 'request', side_effect=[result, commits]), \
             self.assertRaises(contract.QualificationError):
            control.GitHubObserver().candidate()
        # Strict connection semantics elsewhere must not inherit the timeline exception.
        with self.assertRaises(contract.QualificationError):
            control.GitHubObserver.connection(timeline)

    def test_lifecycle_resolution_reconfirms_source_and_closed_authorization(self):
        from types import SimpleNamespace
        from jsonschema import Draft202012Validator
        control = self.load_module('pg_lifecycle_resolve', 'scripts/ci-cloud/postgresql-qualification-control.py')
        timeline = {'totalCount': 3, 'pageInfo': {'hasNextPage': False}, 'nodes': []}
        result, commits = self.github_candidate_fixture(timeline)
        options = SimpleNamespace(control_sha='c' * 40, profile='gcp-rocky-10-2-x86-64',
                                  run_id='100', run_attempt='1')
        schema = json.loads((ROOT/'schemas/postgresql-qualification-evidence.schema.json').read_text())
        for drift in (False, True):
            current, current_commits = copy.deepcopy(result), copy.deepcopy(commits)
            if drift:
                current['data']['repository']['pullRequests']['nodes'][0]['headRefOid'] = 'a' * 40
                current_commits[0]['sha'] = 'a' * 40
            with self.subTest(drift=drift), \
                 mock.patch.object(control.GitHubObserver, 'request',
                    side_effect=[result, commits, current, current_commits]), \
                 mock.patch.object(control.GitHubObserver, 'declaration',
                    return_value=('f' * 40, 'b' * 40, 'e' * 40, contract.DECLARATION)):
                if drift:
                    with self.assertRaises(contract.QualificationError) as error:
                        control.resolve(options)
                    self.assertEqual(error.exception.reason, 'source-drift')
                else:
                    resolved = control.resolve(options)
                    authorization = resolved['authorization']
                    Draft202012Validator(schema['properties']['authorization']).validate(authorization)
                    self.assertEqual(authorization['candidate_sha'], commits[0]['sha'])
                    self.assertEqual(authorization['selector'], 'native-postgresql-18')
                    self.assertEqual(authorization['probe_sha256'], control.probe_digest())

    def test_stable_privilege_roles_cannot_authenticate(self):
        bundle = contract.render_configuration(contract.DECLARATION, 1234)
        for name in contract.ROLE_POLICY:
            self.assertFalse(contract.ROLE_POLICY[name][-1])
            self.assertIn(f'CREATE ROLE {name} NOLOGIN ', bundle['roles.sql'])
        self.assertIn('+secpal_runtime,+secpal_migration', bundle['pg_hba.conf'])
        self.assertIn('WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', bundle['roles.sql'])

    def test_cleanup_removes_only_run_created_database_material(self):
        module = self.load_module('pg_cleanup', 'scripts/ci-cloud/qualify-native-postgresql.py')
        observer = module.Observer.__new__(module.Observer)
        observer.children = []
        observer.passwords = {'synthetic': 'synthetic-test-only'}
        observer.data_created = True
        observer.application_image_created = False
        observer.run = mock.Mock(return_value=(3, 'inactive', ''))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.multiple(module, DATA=base/'data', CLIENT=base/'client',
                                     MATERIAL=base/'material', STATE=base/'state', APPLICATION_IMAGE_STATE=base/'image-state'):
                module.DATA.mkdir()
                (module.DATA/'PG_VERSION').write_text('18')
                (module.DATA/'synthetic-verifier').write_text('synthetic-test-only')
                cleanup = observer.cleanup()
                self.assertFalse(module.DATA.exists())
                self.assertTrue(cleanup['database_material_absent'])
                module.DATA.mkdir()
                (module.DATA/'unowned').write_text('preserve')
                observer.data_created = False
                with self.assertRaises(contract.QualificationError):
                    observer.prepare(contract.DECLARATION)
                self.assertEqual((module.DATA/'unowned').read_text(), 'preserve')

    def test_pre_observer_failure_still_writes_admissible_diagnostic(self):
        from jsonschema import Draft202012Validator
        module = self.load_module('pg_early_failure', 'scripts/ci-cloud/qualify-native-postgresql.py')
        evidence, options = self.system_fixture('gcp-rocky-10-2-arm64')
        auth = evidence['authorization']
        binding = dict(control_sha=auth['control_sha'], profile=auth['profile'], access_run_id='200',
                       access_run_attempt='1', instance_id=evidence['instance_id'], instance_name=evidence['instance_name'])
        schema = json.loads((ROOT/'schemas/postgresql-qualification-diagnostic.schema.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base/'prepared').touch()
            with mock.patch.multiple(module, __file__='/opt/secpal-control/scripts/ci-cloud/qualify-native-postgresql.py',
                                     STATE=base, AUTHORIZATION=base/'missing', DIAGNOSTIC=base/'diagnostic.json'), \
                 mock.patch.object(module.os, 'geteuid', return_value=0), \
                 mock.patch.object(module.os, 'fchown'), \
                 mock.patch.object(module.pwd, 'getpwnam', return_value=mock.Mock(pw_gid=os.getgid())), \
                 mock.patch.object(module, 'Observer', side_effect=AssertionError('must not construct observer')), \
                 mock.patch.object(sys, 'argv', ['qualify', '--run-id', '200', '--run-attempt', '1']):
                self.assertEqual(module.main(), 1)
            document = json.loads((base/'diagnostic.json').read_text())
            Draft202012Validator(schema).validate(document)
            self.assertIsNone(document['resource'])
            self.assertFalse(document['cleanup_complete'])
            self.assertEqual(contract.admit_diagnostic(document, authorization=auth, binding=binding,
                qualification_run_id='200', qualification_run_attempt='1', host_evidence_sha256='0'*64), document)

    def test_qualification_runner_installs_its_own_pinned_schema_dependency(self):
        import yaml
        job = yaml.safe_load((ROOT/'.github/workflows/rocky-cloud-qualification.yml').read_text())['jobs']['qualify_target']
        self.assertTrue(any('jsonschema==4.25.1' in step.get('run', '') for step in job['steps']))

    def test_workflow_composes_pg_data_with_frozen_host_authority(self):
        source = (ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text()
        self.assertIn('native-postgresql-18', source)
        self.assertIn('Bind independently confirmed PostgreSQL data before provisioning', source)
        self.assertIn('Retrieve and independently admit native PostgreSQL evidence', source)
        self.assertIn('expected_target_sha=402c22b0a1d69a5a3dba74ffb68cf016caba606b', source)
        self.assertIn('inputs.qualification', source)
        self.assertNotIn('inputs.candidate_sha', source)
        self.assertNotIn('inputs.harness', source)

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

    def test_architecture_gate_rejects_bypass_and_missing_diagnostics(self):
        spec = importlib.util.spec_from_file_location('pg_gate', ROOT / 'scripts/validate-postgresql-qualification.py')
        gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
        gate.validate(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            paths = ('scripts/ci-cloud/postgresql_qualification_contract.py',
                     'scripts/ci-cloud/rocky_preparation_contract.py',
                     'scripts/ci-cloud/qualify-native-postgresql.py',
                     'scripts/ci-cloud/postgresql-qualification-control.py',
                     'schemas/postgresql-qualification-diagnostic.schema.json',
                     '.github/workflows/rocky-cloud-qualification.yml')
            for name in paths:
                destination = temporary / name; destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT / name,destination)
            for name, before, after in (
                (paths[0],'import hashlib','import os\nimport hashlib'),
                (paths[2],'import argparse','import argparse\nsubprocess.run(["unbounded"])'),
                (paths[2],'observer.cleanup()','observer.omit_cleanup()'),
                (paths[3],'contract.admit_diagnostic(','contract.trust_diagnostic('),
                (paths[5],'scripts/validate-postgresql-qualification.py','scripts/skip-postgresql-gate.py')):
                original = (temporary / name).read_text()
                (temporary / name).write_text(original.replace(before,after))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    gate.validate(temporary)
                (temporary / name).write_text(original)

    def test_fixed_git_blob_checks_identity_modes_and_consumer_closure(self):
        import base64, hashlib
        spec = importlib.util.spec_from_file_location('pg_control', ROOT / 'scripts/ci-cloud/postgresql-qualification-control.py')
        control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
        raw = contract.canonical_bytes(contract.DECLARATION)
        blob_sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        representations = [
            {'sha':'a'*40,'truncated':False,'tree':[{'path':'config','type':'tree','mode':'040000','sha':'b'*40}]},
            {'sha':'b'*40,'truncated':False,'tree':[{'path':'production','type':'tree','mode':'040000','sha':'c'*40}]},
            {'sha':'c'*40,'truncated':False,'tree':[{'path':'postgresql-contract.json','type':'blob','mode':'100644','sha':blob_sha}]},
            {'sha':blob_sha,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}]
        observer = control.GitHubObserver()
        with mock.patch.object(observer,'request',side_effect=representations):
            self.assertEqual(observer.fixed_blob('a'*40,contract.CANDIDATE_PATH),(blob_sha,raw))
        for index, key, value in ((0,'truncated',True),(3,'sha','d'*40),(3,'content',base64.b64encode(b'{}').decode())):
            changed = copy.deepcopy(representations);changed[index][key] = value
            with self.subTest(key=key), mock.patch.object(observer,'request',side_effect=changed), self.assertRaises(contract.QualificationError):
                observer.fixed_blob('a'*40,contract.CANDIDATE_PATH)
        changed = copy.deepcopy(representations);changed[2]['tree'][0]['mode']='120000'
        with mock.patch.object(observer,'request',side_effect=changed), self.assertRaises(contract.QualificationError):
            observer.fixed_blob('a'*40,contract.CANDIDATE_PATH)
        module_raw = (ROOT / 'scripts/ci-cloud/rocky_preparation_contract.py').read_bytes()
        module_sha = hashlib.sha1(b'blob ' + str(len(module_raw)).encode() + b'\0' + module_raw).hexdigest()
        rows = [{'sha':'a'*40,'truncated':False,'tree':[{'path':'scripts','type':'tree','mode':'040000','sha':'b'*40}]},
                {'sha':'b'*40,'truncated':False,'tree':[{'path':'ci-cloud','type':'tree','mode':'040000','sha':'c'*40}]},
                {'sha':'c'*40,'truncated':False,'tree':[{'path':'rocky_preparation_contract.py','type':'blob','mode':'100755','sha':module_sha}]},
                {'sha':module_sha,'encoding':'base64','size':len(module_raw),'content':base64.b64encode(module_raw).decode()}]
        with mock.patch.object(observer,'request',side_effect=rows):
            self.assertEqual(observer.fixed_blob('a'*40,'scripts/ci-cloud/rocky_preparation_contract.py'),(module_sha,module_raw))
        with self.assertRaises(contract.QualificationError):
            observer.fixed_blob('a'*40,'../../caller')
        # Entrypoint equality cannot hide a substituted local admission import.
        with mock.patch.object(observer,'request',return_value={'sha':'a'*40,'tree':{'sha':'b'*40}}), \
             mock.patch.object(observer,'fixed_blob',side_effect=[(blob_sha,raw),('e'*40,(ROOT / contract.CONSUMER_PATH).read_bytes()),('f'*40,b'import malicious')]), \
             self.assertRaises(contract.QualificationError):
            observer.declaration('a'*40)

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

    def test_guest_identity_does_not_reopen_metadata(self):
        source = (ROOT / 'scripts/ci-cloud/qualify-native-postgresql.py').read_text()
        bootstrap = (ROOT / 'scripts/ci-cloud/bootstrap-rocky-host.tftpl').read_text()
        self.assertNotIn('http://169.254.169.254', source)
        self.assertIn('postgresql-resource-binding.json', bootstrap)
        self.assertLess(bootstrap.index('postgresql-resource-binding.json'),
                        bootstrap.index('/usr/local/sbin/secpal-prepare-rocky-host \\'))

    def test_process_collection_is_bounded_during_execution(self):
        spec = importlib.util.spec_from_file_location('pg_observer', ROOT / 'scripts/ci-cloud/qualify-native-postgresql.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        opts = dict(environment={'PATH': '/usr/bin:/bin'}, timeout=2, limit=4096, operation='probe-semantics')
        result = module.bounded_process([sys.executable, '-c', 'print("bounded")'], **opts)
        self.assertEqual(result.stdout, 'bounded\n')
        for code in ('print("x" * 1048576)', 'import time; time.sleep(10)'):
            with self.subTest(code=code), self.assertRaises(contract.QualificationError):
                module.bounded_process([sys.executable, '-c', code], **opts)

    def test_package_pins_are_bounded_data(self):
        for version, release in (('18.7', '2.el10_2'), ('18.6', '1.el10_2')):
            d = dict(contract.DECLARATION, package_version=version, package_release=release)
            self.assertEqual(contract.admit_declaration(d), d)
        for version, release in (('17.9', '1.el10_2'), ('18.6 --nogpgcheck', '1.el10_2'),
                                 ('18.6', '--disableplugin=*'), ('18.6', '1.other')):
            with self.assertRaises(contract.QualificationError):
                contract.admit_declaration(dict(contract.DECLARATION, package_version=version, package_release=release))

    def test_candidate_execution_and_provider_credentials_are_absent_from_guest(self):
        source = (ROOT / 'scripts/ci-cloud/qualify-native-postgresql.py').read_text()
        self.assertNotIn('os.environ', source)
        self.assertNotIn('git fetch', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('eval(', source)
        self.assertIn('observer.mutated', source)
        self.assertIn('O_NOFOLLOW', source)
        schema = json.loads((ROOT / 'schemas/postgresql-qualification-evidence.schema.json').read_text())
        self.assertFalse(schema['additionalProperties'])
        self.assertEqual(schema['properties']['claim']['const'], contract.SELECTOR)

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


if __name__ == '__main__':
    unittest.main()
