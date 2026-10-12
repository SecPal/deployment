#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Scoped Certbot supply agreement; synthetic facts never prove native runtime."""

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

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
