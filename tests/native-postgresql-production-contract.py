#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Production consumption of accepted native PostgreSQL authority."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import postgresql_qualification_contract as pg

spec = importlib.util.spec_from_file_location('production_renderer', ROOT / 'scripts/render-production-quadlets.py')
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

class NativeProduction(unittest.TestCase):
    def test_candidate_consumes_exact_accepted_configuration(self):
        path = ROOT / pg.CANDIDATE_PATH
        self.assertTrue(path.is_file())
        declaration = pg.parse_declaration(path.read_text())
        self.assertEqual(declaration, pg.DECLARATION)
        self.assertNotIn('@RUNTIME_UID@', json.dumps(pg.render_configuration(declaration, 20000)))

    def test_application_roles_use_native_tcp_and_database_state(self):
        units = renderer.build_units(renderer.load_contract())
        self.assertNotIn('secpal-valkey.container', units)
        self.assertFalse((ROOT / 'scripts/production-valkey-entrypoint.sh').exists())
        for role in renderer.API_ROLES:
            content = units[f'secpal-{role}.container']
            for line in ('Environment=DB_HOST=db.secpal.internal', 'Environment=DB_SSLMODE=verify-full',
                         'Environment=CACHE_STORE=database', 'Environment=QUEUE_CONNECTION=database',
                         'Environment=SESSION_DRIVER=database',
                         'Network=pasta:--no-map-gw,--map-guest-addr,none,--map-host-loopback,169.254.81.1',
                         'AddHost=db.secpal.internal:169.254.81.1', f'Image={pg.APPLICATION_RUNTIME["image"]}'):
                self.assertIn(line, content)
            self.assertNotIn('REDIS_', content)
            self.assertNotIn('Network=host', content)
            self.assertNotIn('postgresql.sock', content)
        runtime = units['secpal-api.container']
        migration = units['secpal-migrate.container']
        self.assertIn('/secrets/runtime/postgres-password', runtime)
        self.assertNotIn('/secrets/migration/', runtime)
        self.assertIn('/secrets/migration/postgres-password', migration)
        self.assertIn('production-migrate.php', migration)
        self.assertNotIn('postgres-password', units['secpal-frontend.container'])

    def test_firewall_lifetime_guards_user_manager_without_coupling_db_liveness(self):
        units = renderer.build_host_units(renderer.load_contract())
        firewall = units['secpal-postgresql-loopback.service']
        manager = units['user@20000.service.d/secpal-postgresql.conf']
        self.assertIn('ExecStartPre=/usr/sbin/nft --check -f /etc/nftables/secpal-postgresql.nft', firewall)
        self.assertIn('ExecStart=/usr/sbin/nft -f /etc/nftables/secpal-postgresql.nft', firewall)
        self.assertIn('ExecStop=/usr/sbin/nft delete table inet secpal_postgresql', firewall)
        self.assertNotIn('flush ruleset', firewall)
        self.assertIn('BindsTo=secpal-postgresql-loopback.service', manager)
        self.assertIn('After=secpal-postgresql-loopback.service postgresql.service', manager)
        self.assertNotIn('Requires=postgresql.service', manager)
        self.assertNotIn('BindsTo=postgresql.service', manager)
        for name, content in units.items():
            self.assertEqual((ROOT / 'config/production/host-systemd' / name).read_text(), content)

    def test_native_data_is_outside_rootless_state_preparation(self):
        contract = renderer.load_contract()
        row = contract['objects']['postgresql_data']
        self.assertEqual(row['location'], '/var/lib/pgsql/data')
        self.assertEqual(row['owner'], 'postgres')
        self.assertEqual(row['container_identity'], 'none-host-native')
        self.assertNotIn('postgresql_data', renderer._STATE.ACTIVE_STATE_OBJECTS)
        self.assertNotIn('valkey_state', contract['objects'])
        self.assertNotIn('valkey_credentials', contract['objects'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            renderer._STATE.initialize_fixture(contract, root)
            self.assertFalse((root / 'var/lib/pgsql/data').exists())
            legacy = root / 'srv/secpal/postgresql'
            legacy.mkdir(mode=0o700)
            marker = legacy / 'data'
            marker.write_bytes(b'preserve legacy database')
            inode = marker.stat().st_ino
            with self.assertRaises(renderer._STATE.ContractError):
                renderer._STATE.initialize_fixture(contract, root)
            self.assertEqual(marker.stat().st_ino, inode)
            self.assertEqual(marker.read_bytes(), b'preserve legacy database')

if __name__ == '__main__':
    unittest.main()
