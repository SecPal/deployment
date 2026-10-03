#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Exact provider rendering, pre-provision admission and guest byte integrity."""

import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[1]
TF_ROOT = ROOT / 'infra/ci-cloud/gcp-rocky'


def fixture(architecture):
    return json.loads((ROOT / 'tests/fixtures' /
                      f'rocky-postgresql-metadata-{architecture}.json').read_text())


class RockyMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tofu = shutil.which('tofu')
        if cls.tofu is None:
            raise RuntimeError('pinned OpenTofu is required for exact transport evidence')
        version = subprocess.run([cls.tofu, 'version', '-json'], check=True,
                                 capture_output=True, text=True)
        if json.loads(version.stdout)['terraform_version'] != '1.12.5':
            raise RuntimeError('metadata renderer must be OpenTofu 1.12.5')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.module = cls.root / 'infra/ci-cloud/gcp-rocky'
        cls.module.mkdir(parents=True)
        for name in ('scripts', 'schemas', 'config', 'tests'):
            (cls.root / name).symlink_to(ROOT / name, target_is_directory=True)
        # Exact producer and variable contract; no provider or credentials.
        shutil.copyfile(TF_ROOT / 'variables.tf', cls.module / 'variables.tf')
        cls.canonical = (TF_ROOT / 'metadata.tf').read_text()
        (cls.module / 'metadata.tf').write_text(cls.canonical)
        subprocess.run([cls.tofu, '-chdir=' + str(cls.module), 'init',
                        '-backend=false', '-input=false'], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        (self.module / 'metadata.tf').write_text(self.canonical)

    def variables(self, architecture='amd64', candidate=None):
        data = fixture(architecture)
        auth = json.loads(data['candidate_json'])['authorization']
        return {
            'project_id': 'secpal-dev',
            'bootstrap_service_account': 'secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com',
            'trusted_control_sha': auth['control_sha'],
            'target_sha': '402c22b0a1d69a5a3dba74ffb68cf016caba606b',
            'profile': auth['profile'], 'zone': 'europe-west3-a',
            'machine_type': 'c3-standard-4' if architecture == 'amd64' else 'c4a-standard-4',
            'disk_type': 'hyperdisk-balanced', 'disk_size_gib': 120,
            'exact_image_self_link': 'https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/global/images/'
                + ('rocky-linux-10-v20260930' if architecture == 'amd64' else 'rocky-linux-10-arm64-v20260930'),
            'run_id': auth['run_id'], 'run_attempt': auth['run_attempt'],
            'runner_ipv4': '203.0.113.10',
            'ssh_public_key': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDKiPWdlHKFaHJL+GQ3EQRs9St95lITw217D17rZ2qB '
                + f"secpal-rocky-{auth['run_id']}-{auth['run_attempt']}",
            'created_at': '1791014400', 'expires_at': '1791025200',
            'postgresql_candidate_json': data['candidate_json'] if candidate is None else candidate,
        }

    def render(self, architecture='amd64', candidate=None, backend=False):
        variables = self.variables(architecture, candidate)
        if backend:
            import sys
            sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'scripts/ci-cloud')]
            import product_backend_qualification_contract as contract
            sources = {name: (ROOT / relative).read_bytes() for name, relative in contract.SOURCES.items()}
            variables['postgresql_candidate_json'] = ''
            variables['product_backend_policy_json'] = json.dumps(contract.manifest(
                variables['trusted_control_sha'], variables['profile'], variables['run_id'], variables['run_attempt'], sources))
        (self.module / 'run.auto.tfvars.json').write_text(json.dumps(variables))
        result = subprocess.run([self.tofu, '-chdir=' + str(self.module), 'console', '-no-color'],
            input='nonsensitive(jsonencode({metadata=local.rocky_metadata, report=local.rocky_metadata_admission, sources=local.rocky_bootstrap_sources}))\n',
            text=True, capture_output=True, check=True)
        return json.loads(json.loads(result.stdout))

    def reconstruct(self, startup):
        decoder = startup.split("<<'PYTHON_TRANSPORT'\n", 1)[1].split('\nPYTHON_TRANSPORT', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-', directory], input=decoder,
                                    text=True, capture_output=True)
            files = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
        return result, files

    def substitute_payload(self, startup, payload, *, rebind=False):
        encoded = base64.b64encode(gzip.compress(payload, mtime=0)).decode()
        startup = re.sub(r"encoded = '[A-Za-z0-9+/=]+'", "encoded = '" + encoded + "'", startup)
        if rebind:
            startup = re.sub(r'expected_size = [0-9]+', 'expected_size = ' + str(len(payload)), startup)
            startup = re.sub(r"hexdigest\(\) != '[0-9a-f]{64}'",
                             "hexdigest() != '" + hashlib.sha256(payload).hexdigest() + "'", startup)
        return startup

    def assert_rejected_before_provisioning(self, expected):
        result = subprocess.run([self.tofu, '-chdir=' + str(self.module), 'plan',
                                 '-input=false', '-refresh=false', '-no-color'],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stderr)
        self.assertNotIn('postgresql_candidate_json', result.stderr)
        self.assertFalse((self.module / 'terraform.tfstate').exists())

    def test_historical_real_candidate_rejected_before_provider_creation(self):
        original = '''
locals {
  legacy_startup = templatefile("${path.module}/../../../tests/fixtures/rocky-bootstrap-before-289.tftpl", {
    for name, value in local.rocky_bootstrap_sources : "${name}_base64gzip" => base64gzip(value)
  })
}
'''
        source = self.canonical.replace('"startup-script"                     = local.rocky_startup',
                                        '"startup-script"                     = local.legacy_startup') + original
        (self.module / 'metadata.tf').write_text(source)
        for architecture in ('amd64', 'arm64'):
            with self.subTest(architecture=architecture):
                rendered = self.render(architecture)
                # Historical measurement remains immutable. Common accepted
                # preparation source can grow; the legacy layout must still
                # reproduce provider rejection with the current bytes.
                self.assertGreaterEqual(len(rendered['metadata']['startup-script'].encode()),
                                        fixture(architecture)['startup_bytes'])
                self.assertFalse(rendered['report']['admitted'])
                self.assert_rejected_before_provisioning('ROCKY_METADATA_VALUE_TOO_LARGE')

    def test_real_candidate_complete_sources_and_bash_fit_both_profiles(self):
        old = (ROOT / 'tests/fixtures/rocky-bootstrap-before-289.tftpl').read_text()
        expected = set(re.findall(r'\$\{(\w+)_base64gzip\}', old))
        for architecture in ('amd64', 'arm64'):
            with self.subTest(architecture=architecture):
                rendered = self.render(architecture)
                script = rendered['metadata']['startup-script']
                self.assertTrue(rendered['report']['admitted'])
                self.assertEqual(expected, set(rendered['sources']))
                result, files = self.reconstruct(script)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue({k: v.encode() for k, v in rendered['sources'].items()} == files, 'source bytes differ')
                paths = re.findall(r'(\w+)\s*=\s*file\("\$\{path.module\}/../../../([^"\n]+)"\)', self.canonical)
                for name, relative in paths:
                    if name not in files:
                        self.assertTrue(name.startswith('backend_'))
                        continue
                    self.assertTrue((ROOT / relative).read_bytes() == files[name], name)

                self.assertTrue(fixture(architecture)['candidate_json'].encode() == files['postgresql_candidate'], 'candidate bytes differ')
                parsed = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
                self.assertEqual(0, parsed.returncode, parsed.stderr)
                self.assertLessEqual(len(script.encode()), 237568)
                self.assertLessEqual(rendered['report']['aggregate_bytes'], 499712)

    def test_backend_profile_authenticates_selected_bytes_and_fits_both_profiles(self):
        import sys
        sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'scripts/ci-cloud')]
        import product_backend_qualification_contract as contract
        for architecture in ('amd64', 'arm64'):
            with self.subTest(architecture=architecture):
                rendered = self.render(architecture, backend=True)
                self.assertTrue(rendered['report']['admitted'])
                script = rendered['metadata']['startup-script']
                result, files = self.reconstruct(script)
                self.assertEqual(0, result.returncode)
                self.assertTrue({k: v.encode() for k,v in rendered['sources'].items()} == files)
                sources = {name: files[name] for name in contract.SOURCES}
                for name, relative in contract.SOURCES.items():
                    self.assertTrue((ROOT / relative).read_bytes() == sources[name], name)
                contract.admit_manifest(json.loads(files['backend_authorization']), sources)
                self.assertNotIn('postgresql_runner', files)
                self.assertNotIn('postgresql_application_probe', files)
                self.assertNotIn("decode_script 'postgresql_runner'", script)
                self.assertIn('secpal-cloud-product-backends', script)
                self.assertEqual(0, subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True).returncode)

    def test_maximum_candidate_envelope_fits_both_profiles(self):
        # High entropy at the Terraform ceiling is conservative; closed source
        # admission before transport accepts a strictly smaller semantic set.
        alphabet = ''.join(chr(v) for v in range(33, 127) if chr(v) not in '\\"')
        for architecture in ('amd64', 'arm64'):
            bundle = json.loads(fixture(architecture)['candidate_json'])
            bundle['growth'] = ''
            overhead = len(json.dumps(bundle, separators=(',', ':')))
            generator = random.Random(289)
            bundle['growth'] = ''.join(generator.choice(alphabet) for _ in range(16384 - overhead))
            candidate = json.dumps(bundle, separators=(',', ':'))
            self.assertEqual(16384, len(candidate.encode()))
            rendered = self.render(architecture, candidate)
            self.assertTrue(rendered['report']['admitted'])
            result, files = self.reconstruct(rendered['metadata']['startup-script'])
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(candidate.encode() == files['postgresql_candidate'], 'candidate bytes differ')

    def test_value_boundary_utf8_encoded_bytes_and_aggregate_overflow(self):
        actual = len(self.render()['metadata']['startup-script'].encode())
        marker = '"startup-script"                     = local.rocky_startup'
        for overflow in (0, 1):
            source = self.canonical.replace(marker, '"startup-script" = "${local.rocky_startup}${local.padding}"')
            source += '\nlocals { padding = ' + json.dumps('x' * (237568 - actual + overflow)) + ' }\n'
            (self.module / 'metadata.tf').write_text(source)
            report = self.render()['report']
            self.assertEqual(237568 + overflow, report['values']['startup-script']['value_bytes'])
            self.assertEqual(overflow == 0, report['admitted'])
            if overflow:
                self.assert_rejected_before_provisioning('ROCKY_METADATA_VALUE_TOO_LARGE')
        source = self.canonical.replace(marker, '"startup-script" = "${local.rocky_startup}${local.padding}"')
        source += '\nlocals { padding = ' + json.dumps('é' * 16000) + ' }\n'
        (self.module / 'metadata.tf').write_text(source)
        self.assertEqual(actual + 32000, self.render()['report']['values']['startup-script']['value_bytes'])
        self.assert_rejected_before_provisioning('ROCKY_METADATA_VALUE_TOO_LARGE')
        source = self.canonical.replace(marker, marker + '\n    padding-one = local.padding\n    padding-two = local.padding')
        source += '\nlocals { padding = ' + json.dumps('x' * 200000) + ' }\n'
        (self.module / 'metadata.tf').write_text(source)
        report = self.render()['report']
        self.assertTrue(all(size['value_bytes'] <= report['value_safe_maximum'] for size in report['values'].values()))
        self.assertFalse(report['admitted'])
        self.assert_rejected_before_provisioning('ROCKY_METADATA_AGGREGATE_TOO_LARGE')

    def test_integrity_inventory_substitution_and_expansion_fail_closed(self):
        rendered = self.render()
        script = rendered['metadata']['startup-script']
        encoded = re.search(r"encoded = '([A-Za-z0-9+/=]+)'", script)[1]
        raw = gzip.decompress(base64.b64decode(encoded))
        missing = dict(rendered['sources']); missing.pop('postgresql_application_probe')
        extra = dict(rendered['sources']); extra['unexpected'] = 'x'
        duplicate = raw[:-1] + b',"postgresql_control":"substituted"}'
        candidate = dict(rendered['sources']); candidate['postgresql_candidate'] = '{}'
        control = dict(rendered['sources']); control['postgresql_control'] = 'substituted'
        profile = dict(rendered['sources']); profile['arm64_profile'] = profile['x86_64_profile']
        variants = [
            self.substitute_payload(script, raw[:-1]),
            script.replace(encoded, encoded[:-4]),
            script.replace(hashlib.sha256(raw).hexdigest(), '0' * 64),
            self.substitute_payload(script, json.dumps(missing).encode(), rebind=True),
            self.substitute_payload(script, json.dumps(extra).encode(), rebind=True),
            self.substitute_payload(script, duplicate, rebind=True),
            self.substitute_payload(script, json.dumps(candidate).encode()),
            self.substitute_payload(script, json.dumps(control).encode()),
            self.substitute_payload(script, json.dumps(profile).encode()),
            self.substitute_payload(script, b'x' * (1024 * 1024 + 1), rebind=True),
            self.substitute_payload(script, b'x' * (len(raw) + 1)),
            script.replace(encoded, encoded + encoded),
            script.replace(encoded, base64.b64encode(base64.b64decode(encoded) * 2).decode()),
            self.substitute_payload(script, json.dumps(dict(reversed(list(rendered['sources'].items())))).encode()),
            re.sub(r'expected_size = [0-9]+', 'expected_size = ' + str(len(raw) + 1), script),
        ]
        for index, variant in enumerate(variants):
            with self.subTest(variant=index):
                result, files = self.reconstruct(variant)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual('ROCKY_BOOTSTRAP_TRANSPORT_INTEGRITY_FAILED\n', result.stderr)
                self.assertEqual({}, files)
        self.assertLess(script.index('PYTHON_TRANSPORT\n'), script.index('decode_script postgresql_candidate'))
        self.assertLess(script.index('decode_script postgresql_candidate'), script.index('\n/usr/local/sbin/secpal-prepare-rocky-host'))

    def test_canonical_resource_guard_and_pre_credential_workflow_order(self):
        main = (TF_ROOT / 'main.tf').read_text()
        self.assertIn('metadata = local.rocky_metadata', main)
        for resource in ('google_compute_network', 'google_compute_disk'):
            body = main.split(f'resource "{resource}" "qualification" {{', 1)[1].split('\n}', 1)[0]
            self.assertRegex(body, r'depends_on\s*=\s*\[terraform_data\.rocky_metadata_admission\]')
        variables = (TF_ROOT / 'variables.tf').read_text()
        self.assertNotRegex(variables, r'variable "[^"\n]*(url|transport|chunk|inventory)')
        workflow = (ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text()
        admit = workflow.index('python3 scripts/ci-cloud/admit-rocky-metadata.py')
        self.assertLess(admit, workflow.index('      - name: Authenticate trusted provisioning through OIDC'))
        self.assertLess(admit, workflow.index('          tofu apply --auto-approve --input=false'))

    def test_candidate_ceiling_counts_utf8_bytes(self):
        bundle = json.loads(fixture('amd64')['candidate_json'])
        bundle['growth'] = ''
        overhead = len(json.dumps(bundle, ensure_ascii=False, separators=(',', ':')))
        bundle['growth'] = 'é' * (16384 - overhead)
        candidate = json.dumps(bundle, ensure_ascii=False, separators=(',', ':'))
        self.assertEqual(16384, len(candidate))
        self.assertGreater(len(candidate.encode()), 16384)
        (self.module / 'run.auto.tfvars.json').write_text(json.dumps(self.variables(candidate=candidate)))
        result = subprocess.run([self.tofu, '-chdir=' + str(self.module), 'plan',
                                 '-input=false', '-refresh=false', '-no-color'],
                                text=True, capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('PostgreSQL qualification data must be bounded', result.stderr)
        self.assertTrue('growth' not in result.stderr, 'candidate body leaked in variable rejection')

    def test_maximum_control_expansion_and_overflow(self):
        decoded = self.render()['report']['decoded_bytes']
        needle = 'prepare_script                      = file("${path.module}/../../../scripts/ci-cloud/prepare-rocky-host.sh")'
        self.assertIn(needle, self.canonical)
        for overflow in (0, 1):
            source = self.canonical.replace(needle,
                'prepare_script = "${file("${path.module}/../../../scripts/ci-cloud/prepare-rocky-host.sh")}${local.growth}"')
            source += '\nlocals { growth = ' + json.dumps(' ' * (1024 * 1024 - decoded + overflow)) + ' }\n'
            (self.module / 'metadata.tf').write_text(source)
            report = self.render()['report']
            self.assertEqual(1024 * 1024 + overflow, report['decoded_bytes'])
            self.assertEqual(overflow == 0, report['admitted'])
            if overflow:
                self.assert_rejected_before_provisioning('ROCKY_BOOTSTRAP_EXPANSION_TOO_LARGE')

    def test_controller_diagnostics_never_relay_payload_or_tool_stderr(self):
        spec = importlib.util.spec_from_file_location('rocky_metadata_admission',
                    ROOT / 'scripts/ci-cloud/admit-rocky-metadata.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        report = self.render()['report']
        with mock.patch.object(module, 'ROOT', self.module), mock.patch('builtins.print') as output:
            self.assertEqual(0, module.main())
            self.assertTrue('candidate_json' not in str(output.call_args_list), 'admission leaked candidate data')
        result = subprocess.CompletedProcess([], 0, json.dumps(json.dumps(report)), 'private material')
        with mock.patch.object(module.subprocess, 'run', return_value=result), mock.patch('builtins.print') as output:
            self.assertEqual(0, module.main())
            self.assertNotIn('private material', str(output.call_args_list))
        with mock.patch.object(module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, [], stderr='private material')), mock.patch('builtins.print') as output:
            self.assertEqual(1, module.main())
            output.assert_called_once_with('ROCKY_METADATA_ADMISSION_UNAVAILABLE', file=sys.stderr)


if __name__ == '__main__':
    unittest.main()
