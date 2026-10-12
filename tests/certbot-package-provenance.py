#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Scoped Certbot supply agreement; synthetic facts never prove native runtime."""

import copy
import importlib.util
import json
import hashlib
import os
import platform
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import rocky_preparation_contract as contract


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CertbotProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / 'config/production/certbot-package-policy.json').read_text())
        cls.validator = load_module('production_validator', 'scripts/validate-production-contract.py')
        cls.control = load_module('rocky_control', 'scripts/ci-cloud/rocky-control.py')
        cls.qualifier = load_module('certbot_qualifier', 'scripts/qualify-certbot-packages.py')
        schema = json.loads((ROOT / 'schemas/production-host-facts.schema.json').read_text())
        cls.schema = schema['properties']['os']['properties']['package_provenance']

    def test_native_dnf_is_required_only_for_dependency_solving(self):
        real_import = __import__

        def without_dnf(name, *args, **kwargs):
            if name == 'dnf' or name.startswith('dnf.'):
                raise ModuleNotFoundError("No module named 'dnf'", name='dnf')
            return real_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=without_dnf):
            qualifier = load_module('certbot_without_dnf', 'scripts/qualify-certbot-packages.py')
            with tempfile.TemporaryDirectory() as directory:
                temporary = Path(directory)
                with self.assertRaises(qualifier.QualificationError) as caught:
                    qualifier.verify_dependency_closure(temporary, 'x86_64', self.policy, temporary)
                self.assertEqual(caught.exception.operation, 'resolve-exact-dependency-closure')
                self.assertEqual(caught.exception.reason, 'native-dnf-unavailable')
                self.assertEqual(list(temporary.iterdir()), [])

    def test_isolated_runtime_selects_rpm_module_directories(self):
        # Rocky's default prefix is /usr/local. This synthetic scheme fixture
        # tests path selection only; native installed execution is separate.
        rpm_scheme = dict(sysconfig._INSTALL_SCHEMES['posix_prefix'],
                          purelib='/usr/lib/python3.12/site-packages',
                          platlib='/usr/lib64/python3.12/site-packages')
        with patch.dict(sysconfig._INSTALL_SCHEMES, {'rpm_prefix': rpm_scheme}):
            with patch.object(sys, 'path', sys.path.copy()):
                exec(self.qualifier.IMPORT_SETUP, {})
                self.assertEqual(sys.path[-2:], [
                    '/usr/lib/python3.12/site-packages',
                    '/usr/lib64/python3.12/site-packages',
                ])

    def test_dependency_solver_has_independent_rocky_bootstrap(self):
        events = []
        from contextlib import contextmanager

        @contextmanager
        def bindings(architecture):
            self.assertEqual(architecture, 'x86_64')
            events.append('bootstrap')
            yield
            events.append('withdraw')

        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            with patch.object(self.qualifier, 'native_bindings', bindings), \
                    patch.object(self.qualifier, '_verify_dependency_closure',
                                 side_effect=lambda *args: events.append('strong-solver')):
                self.qualifier.verify_dependency_closure(temporary, 'x86_64', self.policy, temporary)
        self.assertEqual(events, ['bootstrap', 'strong-solver', 'withdraw'])

    def test_bootstrap_rejects_unreviewed_scheme_and_source_ancestors(self):
        with patch.object(sysconfig, 'get_path', return_value='/usr/local/lib/python3.12/site-packages'):
            with self.assertRaisesRegex(self.qualifier.QualificationError, 'rpm-python-scheme-invalid'):
                self.qualifier.native_module_paths()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'native.py'
            source.write_text('raise AssertionError("must not execute")')
            with self.assertRaisesRegex(self.qualifier.QualificationError, 'administrator-path-invalid'):
                self.qualifier.trusted_native_path(source, regular=True)

    def test_bootstrap_checks_owner_signer_and_payload_before_loading(self):
        qualifier = self.qualifier
        roots = qualifier.native_module_paths()
        finder = qualifier.RockyBindingFinder(roots, 'x86_64')
        origin = roots[0] / 'dnf/__init__.py'
        signature = 'RSA/SHA256, fixed timestamp, Key ID ' + contract.ROCKY_FINGERPRINT[-16:]
        observed = 'python3-dnf|noarch|' + signature
        with patch.object(qualifier, 'trusted_native_path'), \
                patch.object(qualifier, 'run', side_effect=[observed, '']) as command:
            finder.admit_origin('dnf', origin)
        self.assertEqual([call.args[0] for call in command.call_args_list],
                         ['observe-native-module-owner', 'verify-native-module-package'])
        self.assertIn('--noscripts', command.call_args_list[1].args[1])
        self.assertNotIn('--nodeps', command.call_args_list[1].args[1])
        for observed in ('unowned|noarch|' + signature,
                         'python3-dnf|noarch|RSA/SHA256, Key ID e37ed158',
                         'python3-dnf|aarch64|' + signature):
            with patch.object(qualifier, 'trusted_native_path'), \
                    patch.object(qualifier, 'run', return_value=observed), \
                    self.assertRaisesRegex(qualifier.QualificationError, 'module-package-invalid'):
                qualifier.RockyBindingFinder(roots, 'x86_64').admit_origin('dnf', origin)
        for origin in (Path('/usr/local/lib/python3.12/site-packages/dnf/__init__.py'),
                       roots[0] / 'unreviewed/__init__.py'):
            with self.assertRaisesRegex(qualifier.QualificationError, 'module-path-invalid'):
                finder.admit_origin('dnf', origin)
        with patch.object(qualifier, 'trusted_native_path'), \
                patch.object(qualifier, 'run', side_effect=[
                    'python3-dnf|noarch|' + signature, 'S.5....T. forged payload',
                ]), self.assertRaisesRegex(qualifier.QualificationError, 'module-payload-invalid'):
            qualifier.RockyBindingFinder(roots, 'x86_64').admit_origin('dnf', roots[0] / 'dnf/__init__.py')

    def test_bootstrap_finder_never_falls_back_to_caller_paths(self):
        finder = self.qualifier.RockyBindingFinder(self.qualifier.native_module_paths(), 'x86_64')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'dnf.py').write_text('raise AssertionError("untrusted dnf executed")')
            with patch.object(sys, 'path', [directory]), \
                    patch.object(importlib.machinery.PathFinder, 'find_spec', return_value=None):
                with self.assertRaises(ModuleNotFoundError):
                    finder.find_spec('dnf')
                with self.assertRaises(ModuleNotFoundError):
                    finder.find_spec('unreviewed_third_party')

    def test_bootstrap_consumes_canonical_signing_key_owner(self):
        with patch.object(self.qualifier, 'trusted_native_path'), \
                patch.object(self.qualifier, 'run', return_value='6fedfc85\nZm9yZ2Vk'), \
                self.assertRaisesRegex(self.qualifier.QualificationError, 'rocky-key-invalid'):
            with self.qualifier.native_bindings('x86_64'):
                self.fail('unknown signer packet admitted')

    def test_bootstrap_does_not_execute_adjacent_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'native.py'
            source.write_text('value = "source"')
            loader = self.qualifier.NativeSourceLoader('native', str(source))
            with patch.object(loader, 'get_data', return_value=b'value = "verified-source"') as data:
                namespace = {}
                exec(loader.get_code('native'), namespace)
            self.assertEqual(namespace['value'], 'verified-source')
            data.assert_called_once_with(str(source))

    def test_installed_observation_keeps_every_admission_stage_read_only(self):
        from contextlib import contextmanager
        qualifier = self.qualifier
        rows = [dict(row, signature_verified=True) for row in self.policy['closures']['x86_64']]
        operations = []
        payloads = []
        epel = [row['name'] for row in rows if row['repository'] == 'epel-certbot-10.2']

        @contextmanager
        def authenticated(*args, **kwargs):
            self.assertFalse(kwargs['acquire'])
            operations.extend(['signed-snapshot', 'strong-dependency-solver'])
            yield rows, Path('/authenticated-snapshot')

        def observe(operation, argv, **kwargs):
            operations.append(operation)
            if operation == 'observe-native-architecture': return 'x86_64'
            if operation == 'inspect-installed-rpm-header':
                row = next(row for row in rows if row['name'] == argv[-1])
                return '\n'.join(row[key] for key in (
                    'name', 'epoch', 'version', 'release', 'architecture', 'payload_digest', 'header_sha256'
                )) + '\nRSA/SHA256, Key ID ' + row['signer_fingerprint'][-16:]
            if operation == 'observe-installed-signers':
                return '\n'.join(name + '|Key ID ' + self.policy['keys']['epel']['fingerprint'][-16:] for name in epel)
            if operation == 'observe-global-signing-keys': return ''
            if operation == 'observe-effective-repositories': return 'baseos\nappstream\nextras'
            if operation == 'execute-qualified-python-imports':
                return json.dumps({'python_machine': 'x86_64', 'python_version': '3.12.15', 'certbot_version': '4.2.0'})
            if operation == 'execute-qualified-standalone-plugin': return ''
            if operation == 'execute-qualified-certbot-client':
                self.assertIn('--version', argv[4])
                return 'certbot 4.2.0'
            self.fail('unreviewed operation: ' + operation)

        with patch.object(qualifier, 'authenticated_bundle', authenticated), \
                patch.object(qualifier, 'run', side_effect=observe), \
                patch.object(qualifier, 'verify_installed_payload', side_effect=lambda row, *args: payloads.append(row['name'])), \
                patch.object(Path, 'read_text', return_value='ID=rocky\nVERSION_ID=10.2\n'):
            result = qualifier.observe_installed(Path('/bundle'), 'x86_64', self.policy)
        self.assertEqual(payloads, [row['name'] for row in rows])
        self.assertEqual(operations, ['observe-native-architecture', 'signed-snapshot', 'strong-dependency-solver']
                         + ['inspect-installed-rpm-header'] * 106
                         + ['observe-installed-signers', 'observe-global-signing-keys', 'observe-effective-repositories',
                            'execute-qualified-python-imports', 'execute-qualified-standalone-plugin', 'execute-qualified-certbot-client'])
        self.assertTrue(all(row['installed_payload_verified'] for row in result['certbot_exception']['packages']))

    def test_native_tools_ignore_shadowed_path_and_caller_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'uname'
            fake.write_text('#!/bin/sh\nprintf forged-architecture\n')
            fake.chmod(0o700)
            with patch.dict(os.environ, {
                'PATH': directory, 'HOME': directory,
                'RPM_CONFIGDIR': directory, 'LANG': 'untrusted-locale',
            }):
                self.assertEqual(self.qualifier.run('observe-native-architecture', ['uname', '-m']), platform.machine())
                environment = json.loads(self.qualifier.run('observe-tool-environment', [
                    '/usr/bin/python3', '-I', '-S', '-c',
                    'import os,json; print(json.dumps(dict(os.environ)))',
                ]))
            self.assertEqual(environment['PATH'], '/usr/sbin:/usr/bin')
            self.assertEqual(environment['LC_ALL'], 'C')
            self.assertNotEqual(environment['HOME'], directory)
            self.assertNotIn('RPM_CONFIGDIR', environment)

    def test_rpm_commands_explicitly_select_system_configuration(self):
        response = subprocess.CompletedProcess([], 0, b'', b'')
        with patch.object(self.qualifier.subprocess, 'run', return_value=response) as command:
            self.qualifier.run('inspect-signed-rpm-header', ['rpm', '-qp', 'fixture.rpm'])
        argv = command.call_args.args[0]
        self.assertEqual(argv[0], '/usr/bin/rpm')
        self.assertIn('--rcfile', argv)
        self.assertEqual(argv[argv.index('--rcfile') + 1], '/usr/lib/rpm/rpmrc')
        self.assertIn('--macros', argv)
        macros = argv[argv.index('--macros') + 1]
        self.assertNotIn('~', macros)
        self.assertNotIn('/etc/', macros)

    def test_acquisition_rejects_redirected_repository_identity(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, maximum): return b'reviewed bytes'
            def geturl(self): return 'https://unreviewed.invalid/substitution.rpm'
        response = Response()
        # This tests the acquisition seam only, never native supply admission.
        with patch('urllib.request.urlopen', return_value=response):
            with patch('urllib.request.OpenerDirector.open', return_value=response):
                with self.assertRaises(self.qualifier.QualificationError):
                    self.qualifier.fetch('acquire-reviewed-rpm', self.policy['closures']['x86_64'][0]['url'], 1024)

    def test_authenticated_snapshot_survives_input_replacement_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.rpm'
            source.write_bytes(b'authenticated snapshot fixture')
            reviewed = {'rpm_sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
            private = root / 'private.rpm'
            self.qualifier.snapshot_authenticated_rpm(source, private, reviewed)
            source.write_bytes(b'changed after authentication')
            self.assertEqual(private.read_bytes(), b'authenticated snapshot fixture')
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            link = root / 'link.rpm'
            link.symlink_to(private)
            with self.assertRaises(self.qualifier.QualificationError):
                self.qualifier.snapshot_authenticated_rpm(link, root / 'substitution.rpm', reviewed)

    def test_payload_verification_uses_authenticated_rpm_file(self):
        row = self.policy['closures']['x86_64'][0]
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            with patch.object(self.qualifier, 'run', return_value='') as command:
                self.qualifier.verify_installed_payload(row, private, None)
            argv = command.call_args.args[1]
            self.assertEqual(argv[:4], ['/usr/bin/python3', '-I', '-S', '-c'])
            self.assertIn('file.verify()', argv[4])
            self.assertIn('rpm.RPMFILE_CONFIG', argv[4])
            self.assertIn('transaction.setVSFlags(0)', argv[4])
            self.assertIn('transaction.setVfyLevel(3)', argv[4])
            self.assertEqual(argv[-2], str(private / row['url'].rsplit('/', 1)[1]))
            self.assertEqual(argv[-1], str(private.parent / 'rpmdb'))

    def fixture(self, architecture):
        rows = copy.deepcopy(self.policy['closures'][architecture])
        return {
            'distribution': 'rocky',
            'gpg_key': 'RPM-GPG-KEY-Rocky-10',
            'enabled_repository_ids': ['appstream', 'baseos', 'extras'],
            'rpm_signatures_verified': True,
            'external_repositories_enabled': False,
            'certbot_exception': {
                'policy_id': self.policy['policy_id'],
                'host_architecture': architecture,
                'packages': [dict(row, signature_verified=True, installed_payload_verified=True) for row in rows],
                'installed_epel_names': sorted(row['name'] for row in rows if row['repository'] == 'epel-certbot-10.2'),
                'global_epel_key_present': False,
                'runtime': {
                    'machine': architecture, 'python_machine': architecture,
                    'python_version': '3.12.15', 'certbot_version': '4.2.0',
                    'imports_status': 0, 'standalone_plugin_status': 0,
                },
            },
        }

    def decisions(self, value, architecture):
        schema = not list(Draft202012Validator(self.schema).iter_errors(value))
        try:
            contract.admit_certbot_exception(value, architecture, self.policy)
            domain = True
        except contract.ContractError:
            domain = False
        try:
            self.validator.validate_tls_package_provenance(value, architecture)
            boundary = True
        except self.validator.ContractViolation:
            boundary = False
        observation = {
            'schema_version': 1, 'evidence_class': 'rocky-native', 'target_sha': 'a' * 40,
            'architecture': architecture, 'package_provenance': value,
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as handle:
            json.dump(observation, handle)
            handle.flush()
            try:
                self.control.validate_certbot_observation(Path(handle.name), 'a' * 40)
                native = True
            except self.control.ControlError:
                native = False
        return schema, domain, boundary, native

    def test_default_and_exact_qualified_closures(self):
        for architecture in ('x86_64', 'aarch64'):
            with self.subTest(architecture=architecture):
                value = self.fixture(architecture)
                self.assertFalse(list(Draft202012Validator(self.schema).iter_errors(value)))
                self.assertEqual((True, True, True, True), self.decisions(value, architecture))
                del value['certbot_exception']
                # Ordinary host facts remain valid; a Certbot-specific native
                # observation must actually contain the selected exception.
                self.assertEqual((True, True, True, False), self.decisions(value, architecture))

    def test_uncontrolled_supply_and_runtime_are_rejected_at_all_boundaries(self):
        for architecture in ('x86_64', 'aarch64'):
            valid = self.fixture(architecture)
            mutations = []
            def mutation(name, change):
                value = copy.deepcopy(valid)
                change(value)
                mutations.append((name, value))
            mutation('epel enabled', lambda v: v['enabled_repository_ids'].append('epel'))
            mutation('CRB enabled', lambda v: v['enabled_repository_ids'].append('crb'))
            mutation('external enabled', lambda v: v.update(external_repositories_enabled=True))
            mutation('unrelated EPEL installed', lambda v: v['certbot_exception']['installed_epel_names'].append('htop'))
            mutation('global EPEL signer', lambda v: v['certbot_exception'].update(global_epel_key_present=True))
            mutation('missing closure', lambda v: v['certbot_exception']['packages'].pop())
            mutation('extra package', lambda v: v['certbot_exception']['packages'].append(copy.deepcopy(v['certbot_exception']['packages'][0])))
            mutation('noarch without runtime', lambda v: v['certbot_exception'].pop('runtime'))
            mutation('emulated/cross architecture', lambda v: v['certbot_exception']['runtime'].update(machine='aarch64' if architecture == 'x86_64' else 'x86_64'))
            mutation('imports failure', lambda v: v['certbot_exception']['runtime'].update(imports_status=1))
            mutation('missing standalone plugin', lambda v: v['certbot_exception']['runtime'].update(standalone_plugin_status=1))
            mutation('boolean runtime status', lambda v: v['certbot_exception']['runtime'].update(imports_status=False))
            mutation('null exception', lambda v: v.update(certbot_exception=None))
            for field, value in (
                ('version', '999.0'), ('rpm_sha256', '0' * 64),
                ('payload_digest', '0' * 64), ('header_sha256', '0' * 64),
                ('signer_fingerprint', '0' * 40), ('repository', 'epel'),
                ('url', 'https://example.invalid/substitution.rpm'),
                ('signature_verified', False), ('installed_payload_verified', False),
                ('signature_verified', 1), ('installed_payload_verified', 1),
            ):
                mutation(field, lambda v, f=field, x=value: v['certbot_exception']['packages'][0].update({f:x}))
            for name, value in mutations:
                with self.subTest(architecture=architecture, mutation=name):
                    decisions = self.decisions(value, architecture)
                    # The schema owns closure/shape; exact digests and identities
                    # are owned once by admission and shared by both boundaries.
                    self.assertEqual((False, False, False), decisions[1:])

    def test_signed_rpm_header_identity_is_separate_from_noarch_runtime(self):
        for architecture in ('x86_64', 'aarch64'):
            for row in self.policy['closures'][architecture]:
                header = [row[field] for field in (
                    'name', 'epoch', 'version', 'release', 'architecture', 'payload_digest', 'header_sha256'
                )] + [f"RSA/SHA256, reviewed RPM timestamp, Key ID {row['signer_fingerprint'][-16:]}"]
                self.qualifier.admit_header(header, row)
                forged = header.copy()
                forged[6] = '0' * 64
                with self.assertRaises(self.qualifier.QualificationError):
                    self.qualifier.admit_header(forged, row)

    def test_certbot_owner_helper_retains_purity(self):
        gate = load_module('rocky_architecture', 'scripts/validate-rocky-evidence-architecture.py')
        helper = ROOT / 'scripts/ci-cloud/certbot_package_admission.py'
        gate.validate_pure_capabilities(helper)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py') as handle:
            handle.write(helper.read_text() + '\nimport os\n')
            handle.flush()
            with self.assertRaises(gate.ArchitectureError):
                gate.validate_pure_capabilities(Path(handle.name))

    def test_epel_authority_cannot_admit_an_ordinary_rocky_package(self):
        fact = {
            'name':'podman', 'repositories':['appstream'], 'header_nevra':'podman-5.8.2-1.el10_2.x86_64',
            'nevra':'podman-5.8.2-1.el10_2.x86_64', 'architecture':'x86_64',
        }
        with self.assertRaises(contract.ContractError):
            contract.admit_package(fact, self.policy['keys']['epel']['fingerprint'], 'x86_64')


if __name__ == '__main__':
    unittest.main()
