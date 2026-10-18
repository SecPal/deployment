#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Execute the production one-shot against bounded application collaborators.

These tests prove the deployment caller, not HTTP, CSV, PostgreSQL or the API
importer's activation algorithm. Those remain API-owned contract evidence.
Only absolute mount paths are relocated in the script under test.
"""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "address_renderer", ROOT / "scripts/render-production-quadlets.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

COLLABORATORS = r'''<?php
namespace Illuminate\Contracts\Console { class Kernel {} }
namespace Illuminate\Support\Facades {
    class Http {
        static function globalOptions($options) { \event(['http-options', $options]); }
    }
    class DB {
        static function statement($sql) { \event($sql); }
        static function disconnect() { \event('disconnect-owner'); }
        static function purge($name) { \event('purge:'.$name); }
        static function connection() { return new class {
            function setReconnector($callback) { $GLOBALS['reconnect'] = $callback; }
        }; }
    }
    class Artisan {
        static function call($command, $options = []) {
            \event([$command, $options]);
            if ($command === 'addresses:import' && \getenv('CASE') === 'lost-session') {
                ($GLOBALS['reconnect'])();
            }
            if ($command === 'migrate' && \getenv('CASE') === 'migration-failure') { return 7; }
            if ($command === 'addresses:import') {
                // The API maps network/concurrency/checksum/activation failure to
                // nonzero. The caller must propagate all of them, without retry.
                return (int) \getenv('IMPORT_RESULT');
            }
            return 0;
        }
    }
}
namespace App\Models { class AddressDataImport { const STATUS_SUCCEEDED = 'succeeded'; } }
namespace App\Services\AddressData {
    class AddressDataSourceAdmission {
        function expectedSha256($value) {
            if (\getenv('CASE') === 'incompatible-release') { throw new \RuntimeException('private detail'); }
            return $value;
        }
        function remoteSourceUrl($value) { return $value; }
    }
    class AddressSuggestionService {
        function activeImport($country) {
            \event('active:'.$country);
            if (\getenv('CASE') === 'no-active') { return null; }
            return (object) ['status' => 'succeeded', 'row_count' => 12,
                'source_sha256' => \getenv('CASE') === 'wrong-hash' ? 'wrong' : \str_repeat('a', 64)];
        }
    }
}
namespace {
    function event($value) { file_put_contents(getenv('TRACE'), json_encode($value)."\n", FILE_APPEND); }
    function secpalDatabaseCredentials($root) {
        event('import-credentials');
        return ['username' => 'fixture_runtime', 'password' => 'fixture-only',
                'sslrootcert' => $root.'/postgres-ca.crt'];
    }
    function config($value) {
        if (is_array($value)) {
            if ($value['database.connections.pgsql.username'] !== 'fixture_runtime'
                || $value['database.connections.pgsql.password'] !== 'fixture-only'
                || $value['database.connections.pgsql.sslrootcert'] !== '/run/secpal/secrets/import/postgres-ca.crt') {
                throw new \RuntimeException('Wrong import connection configuration.');
            }
            event('runtime-configuration');
            return null;
        }
        return match ($value) {
            'address_data.expected_sha256' => str_repeat('a', 64),
            'address_data.source_url' => 'https://release.invalid/approved.csv',
            'address_data.country' => 'DE',
        };
    }
    class Application {
        function make($type) {
            if ($type === \Illuminate\Contracts\Console\Kernel::class) {
                return new class { function bootstrap() { event('bootstrap'); } };
            }
            return new $type;
        }
    }
}
'''


class Reconciliation(unittest.TestCase):
    def execute(self, *, case='', import_result=0):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'vendor').mkdir()
            (root / 'bootstrap').mkdir()
            (root / 'vendor/autoload.php').write_text(COLLABORATORS)
            (root / 'bootstrap/app.php').write_text('<?php return new Application;')
            source = (ROOT / 'scripts/production-migrate.php').read_text()
            (root / 'oneshot.php').write_text(source.replace('/app/', f'{root}/'))
            trace = root / 'trace'
            result = subprocess.run(['php', str(root / 'oneshot.php')], text=True,
                                    capture_output=True, timeout=10,
                                    env={**os.environ, 'CASE': case,
                                         'IMPORT_RESULT': str(import_result), 'TRACE': str(trace)})
            events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            return result, events

    def test_each_explicit_invocation_reconciles_after_migration_with_runtime_authority(self):
        # Covers the shared install/update/rollback caller seam. This is not
        # evidence that the unimplemented update owner restarts systemd units.
        for _ in range(2):
            result, events = self.execute()
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = [e for e in events if isinstance(e, list) and e[0] != 'http-options']
            self.assertEqual(commands, [['migrate', {'--force': True}],
                                       ['addresses:import', {'--no-interaction': True}],
                                       ['addresses:check', {'--no-interaction': True}]])
            self.assertLess(events.index(commands[0]), events.index('disconnect-owner'))
            self.assertLess(events.index('disconnect-owner'), events.index('import-credentials'))
            self.assertLess(events.index('runtime-configuration'), events.index(commands[1]))
            self.assertIn('active:DE', events)
            self.assertLess(events.index(['http-options', {'allow_redirects': False}]),
                            events.index(commands[1]))

    def test_import_credential_files_use_the_real_bootstrap_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for subdir, username in (('database', 'issued_migration'), ('import', 'issued_runtime')):
                delivery = root / subdir
                delivery.mkdir(mode=0o700)
                for name, content in {
                    'postgres-username': username + '\n',
                    'postgres-password': 'a' * 64 + '\n',
                    'postgres-ca.crt': '-----BEGIN CERTIFICATE-----\nfixture\n',
                }.items():
                    path = delivery / name
                    path.write_text(content)
                    path.chmod(0o400)
            for name, content, mode in (
                ('app-key', 'base64:' + 'A' * 43 + '=\n', 0o400),
                ('app-previous-keys', '', 0o400), ('tenant-kek', 'K' * 32, 0o600),
            ):
                path = root / name
                path.write_text(content)
                path.chmod(mode)
            probe = root / 'probe.php'
            probe.write_text(
                "<?php define('SECPAL_TEST_SECRET_ROOT', $argv[1]); require $argv[2]; "
                "$import = secpalDatabaseCredentials($argv[1].'/import'); "
                "exit($import['username'] === 'issued_runtime' "
                "&& $_ENV['DB_USERNAME'] === 'issued_migration' "
                "&& getenv('DB_PASSWORD') === false ? 0 : 1);")
            command = ['php', str(probe), str(root), str(ROOT / 'scripts/production-secret-bootstrap.php')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            # The extra import mount must not become a weaker credential path.
            (root / 'import/postgres-password').chmod(0o644)
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 78)
            self.assertNotIn('a' * 64, result.stderr)

    def test_nonzero_stops_the_activation_gate_and_explicit_retry_is_possible(self):
        for code in (1, 73):
            with self.subTest(import_exit=code):
                result, events = self.execute(import_result=code)
                self.assertEqual(result.returncode, code)
                self.assertNotIn('active:DE', events)
                self.assertNotIn(['addresses:check', {'--no-interaction': True}], events)
        self.assertEqual(self.execute()[0].returncode, 0)

    def test_migration_failure_does_not_import(self):
        result, events = self.execute(case='migration-failure')
        self.assertEqual(result.returncode, 7)
        self.assertFalse(any(isinstance(e, list) and e[0] == 'addresses:import' for e in events))

    def test_check_success_alone_cannot_admit_missing_or_wrong_release(self):
        for case in ('no-active', 'wrong-hash'):
            with self.subTest(case=case):
                result, _ = self.execute(case=case)
                self.assertNotEqual(result.returncode, 0)

    def test_session_loss_fails_instead_of_reconnecting_without_the_lock(self):
        result, events = self.execute(case='lost-session')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('active:DE', events)

    def test_incompatible_artifact_fails_before_migration(self):
        result, events = self.execute(case='incompatible-release')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('private detail', result.stderr)
        self.assertNotIn('SET ROLE secpal_owner', events)

    def test_rendered_resource_transport_and_secret_boundaries(self):
        units = renderer.build_units(renderer.load_contract())
        migrate = units['secpal-migrate.container']
        self.assertIn('TimeoutStartSec=3600', migrate)
        self.assertIn('destination=/app/storage/app/private/address-data/tmp,tmpfs-size=128m,tmpfs-mode=0700', migrate)
        self.assertIn('source=/run/secpal/secrets/runtime/postgres-password,target=/run/secpal/secrets/import/postgres-password,ro=true', migrate)
        for role in ('api', 'worker-general', 'worker-hash-chain', 'scheduler'):
            self.assertNotIn('/secrets/import/', units[f'secpal-{role}.container'])
            self.assertNotIn('/secrets/migration/', units[f'secpal-{role}.container'])
        self.assertIn('Environment=DB_HOST=db.secpal.internal', migrate)
        self.assertIn('AddHost=db.secpal.internal:169.254.81.1', migrate)
        self.assertIn('source=/srv/secpal/private-storage,target=/app/storage/app/private,rw=true', migrate)
        # The API's existing setup_source_path is the offline input interface;
        # the caller forwards no source/checksum override of its own.
        self.assertNotIn('ADDRESS_DATA_EXPECTED_SHA256', migrate)

    def test_offline_render_uses_existing_api_input_without_changing_release_identity(self):
        normal = renderer.build_units(renderer.load_contract())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                ['python3', str(ROOT / 'scripts/render-production-quadlets.py'),
                 '--quadlet-output', str(root / 'quadlet'),
                 '--systemd-output', str(root / 'systemd'), '--offline-address-data'],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            offline = (root / 'quadlet/secpal-migrate.container').read_text()
            line = ('Environment=ADDRESS_DATA_SETUP_SOURCE_PATH='
                    '/app/storage/app/private/address-data/release.csv\n')
            self.assertIn(line, offline)
            self.assertEqual(offline.replace(line, ''), normal['secpal-migrate.container'])
            for name, content in normal.items():
                if name != 'secpal-migrate.container':
                    parent = 'quadlet' if name.endswith(('.container', '.network')) else 'systemd'
                    self.assertEqual((root / parent / name).read_text(), content)


if __name__ == '__main__':
    unittest.main()
