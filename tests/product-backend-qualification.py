#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Accepted-main root authority and independent backend proof admission."""

import ast
import base64
import os
import shutil
import subprocess
import tempfile
from unittest import mock
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
sys.path.insert(0, str(ROOT / 'scripts'))


def observation_fixture(contract):
    """Supporting representation fixture; never provider or privileged proof."""
    cleanup = dict(remaining_paths=[], remaining_containers=[], remaining_networks=[], remaining_images=[],
        service_states=['inactive'] * 2, runtime_unit_states=['inactive'] * 4,
        fixture_unit_states=['inactive'] * 3, nft_table_status=1,
        module_names=[], netns_names=[], link_names=[], listeners=[], haproxy_config_sha256='d' * 64,
        original_haproxy_config_sha256='d' * 64, pasta_boolean='pasta_bind_all_ports --> off', original_pasta_boolean='pasta_bind_all_ports --> off', nftables_state='active',
        host_baseline=dict(rpm_sha256='a'*64,passwd_sha256='b'*64,group_sha256='c'*64),
        original_host_baseline=dict(rpm_sha256='a'*64,passwd_sha256='b'*64,group_sha256='c'*64))
    raw = dict(enforcing='Enforcing', booleans=['haproxy_connect_any --> off', 'pasta_bind_all_ports --> off'],
        portcons={role: f'portcon tcp {backend.host_port} system_u:object_r:secpal_backend_port_t:s0' for role, backend in contract.BACKENDS.items()},
        av=[], nftables={'nftables': contract.nft_projection(993)}, recreations=[],
        accounts=dict(haproxy=dict(name='haproxy',uid=993,gid=993,shell='/usr/sbin/nologin'),
                      runtime=dict(name='secpal-runtime',uid=992), unrelated=dict(name='secpal-cloud',uid=991)),
        haproxy=dict(unit='FragmentPath=/usr/lib/systemd/system/haproxy.service\nDropInPaths=\nExecStart={ path=/usr/sbin/haproxy ; argv[]=/usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg ; }\nControlGroup=/system.slice/haproxy.service\nActiveState=active\nResult=success',
            package_owners=['haproxy','haproxy'], processes=[dict(pid=123,uids=[993]*4,context='system_u:system_r:haproxy_t:s0',exe='/usr/sbin/haproxy',cgroup='0::/system.slice/haproxy.service')],
            all_pids=[123], stats_inode=456, stats_holders=[123]),
        unrelated=dict(local_statuses=[7,7],ipv6_statuses=[7,7],positive_http_code='200',
            avc='type=AVC pid=123 avc: denied { name_connect } dest=18082 scontext=system_u:system_r:haproxy_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0'),
        external={role:dict(positive_http_code='200',ingress_status=7) for role in contract.BACKENDS},
        withdrawal=dict(unit_states=['inactive','inactive'],listeners=[],marker_exists=False,nft_table_status=1,nftables_state='active',policy_state='inactive'),
        barrier=dict(missing_start_status=1,stale_start_status=1,missing_pre_status=1,stale_pre_status=1),cleanup=cleanup)
    for source,target,permission,allowed in (('haproxy_t','secpal_backend_port_t','name_connect',True),('container_runtime_t','secpal_backend_port_t','name_bind',True),('haproxy_t','unreserved_port_t','name_connect',False)):
        raw['av'].append(dict(source=source,target=target,permission=permission,decision=dict(result=0,flags=0,**{'class':3},requested=1,decided=1,allowed=int(allowed))))
    for iteration in range(3):
        products={}
        for role,backend in contract.BACKENDS.items():
            products[role]=dict(listeners=[backend.endpoint],forwarder_context='system_u:system_r:container_runtime_t:s0',container_context='system_u:system_r:container_t:s0:c1,c2',
                network_mode='bridge',networks=['secpal-backend101-edge'],environment_keys=['PATH'],mount_types=['tmpfs'],
                unit=f'FragmentPath=/run/user/992/systemd/generator/secpal-{role}.service\nSourcePath=/etc/containers/systemd/users/992/secpal-{role}.container\nDropInPaths=\nExecStart={{ path=/usr/bin/podman ; argv[]=/usr/bin/podman run --publish {backend.endpoint}:8080/tcp ; }}\nExecStartPre={{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I /usr/local/libexec/secpal/product-backend-policy --check ; }}')
        raw['recreations'].append(dict(products=products,runtime=dict(host={'security':{'rootless':True},'serviceIsRemote':False},unit_states=['inactive']*4,manager_override_keys=[],enforcing='Enforcing',booleans=['haproxy_connect_any --> off','pasta_bind_all_ports --> off']),
            http_stats='# pxname,svname,status,check_status,check_code\nsecpal_frontend,frontend,UP,L7OK,200\nsecpal_api,api,UP,L7OK,200\n'))
    return raw


class QualificationContract(unittest.TestCase):
    def test_http_qualification_survives_production_application_network_retirement(self):
        """Real renderer -> source closure -> fixture, with DB authority removed.

        #81 owns the production TCP mapping. This transport-only successor
        projection retires its old bridge without implementing that mapping.
        """
        import product_backend_qualification_contract as contract
        spec = importlib.util.spec_from_file_location('renderer', ROOT / 'scripts/render-production-quadlets.py')
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        units = renderer.build_units(renderer.load_contract(renderer.DEFAULT_CONTRACT))
        guard_spec = importlib.util.spec_from_file_location('guard', ROOT / 'scripts/validate-product-backend-qualification.py')
        guard = importlib.util.module_from_spec(guard_spec)
        guard_spec.loader.exec_module(guard)
        for retired in (False, True):
            with self.subTest(retired=retired), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                paths = set(contract.SOURCES.values()) | {
                    '.github/workflows/rocky-cloud-qualification.yml',
                    'infra/ci-cloud/gcp-rocky/metadata.tf',
                    'scripts/ci-cloud/bootstrap-rocky-host.tftpl',
                }
                for relative in paths:
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / relative, target)
                for name, text in units.items():
                    if retired and name == 'secpal-application.network':
                        continue
                    if retired:
                        text = text.replace('Network=secpal-application.network\n', '')
                    (root / 'config/production/quadlet' / name).write_text(text)
                if retired:
                    (root / 'config/production/quadlet/secpal-application.network').unlink(missing_ok=True)
                guard.validate(root)
                sources = {name: (root / relative).read_bytes() for name, relative in contract.SOURCES.items()}
                manifest = contract.manifest('a' * 40, 'gcp-rocky-10-2-x86-64', '123', '1', sources)
                contract.admit_manifest(manifest, sources)
                self.assertNotIn('backend_application_network', set(sources))
                for role, backend in contract.BACKENDS.items():
                    fixture = contract.fixture_unit(sources['backend_' + role].decode(), role)
                    self.assertEqual([line for line in fixture.splitlines() if line.startswith('Network=')],
                                     ['Network=secpal-backend101-edge.network'])
                    self.assertEqual([line for line in fixture.splitlines() if line.startswith('PublishPort=')],
                                     [backend.publication])
                    self.assertNotIn('application', fixture)
                    self.assertNotIn('Mount=type=bind,', fixture)
                    self.assertNotIn('Environment=DB_', fixture)
                raw = observation_fixture(contract)
                contract.normalize_observations(raw, 993, 992, 991)
                qualifier_spec = importlib.util.spec_from_file_location('qualifier', ROOT / 'scripts/ci-cloud/qualify-product-backends.py')
                qualifier = importlib.util.module_from_spec(qualifier_spec)
                qualifier_spec.loader.exec_module(qualifier)
                observer = qualifier.Observer('123', '1')
                observer.runtime = SimpleNamespace(pw_name='secpal-runtime', pw_uid=992)
                observer.quadlets = root / 'fixture'
                observer.quadlets.mkdir()
                calls = []
                def run(operation, arguments, **options):
                    calls.append(arguments)
                    if 'info' in arguments:
                        return 0, json.dumps({'security': {'rootless': True}, 'serviceIsRemote': False})
                    if 'is-active' in arguments:
                        return 3, ''
                    if arguments[:3] == ['nft', 'list', 'table']:
                        return 1, ''
                    return 0, ''
                def path(value):
                    return root / 'auth.json' if value == '/etc/containers/secpal-backend101-auth.json' else Path(value)
                with mock.patch.object(qualifier, 'ROOT', root), mock.patch.object(qualifier, 'Path', side_effect=path), \
                        mock.patch.object(qualifier, 'write', side_effect=lambda target, data, **kw: target.write_bytes(data)), \
                        mock.patch.object(qualifier, 'READY', root / 'ready'), mock.patch.object(qualifier, 'STATS', root / 'stats'), \
                        mock.patch.object(observer, 'run', side_effect=run), \
                        mock.patch.object(observer, 'observe_cleanup', return_value=raw['cleanup']):
                    # Simulate external commands only; exercise actual source
                    # reads, installation and bounded cleanup, never host proof.
                    observer.products()
                    self.assertEqual(sorted(p.name for p in observer.quadlets.glob('*.network')),
                                     ['secpal-backend101-edge.network'])
                    observer.mutated = True
                    self.assertTrue(observer.cleanup())
                    self.assertEqual(list(observer.quadlets.iterdir()), [])
                self.assertEqual([args for args in calls if args[:4] == ['podman', '--remote=false', 'network', 'rm']],
                                 [['podman', '--remote=false', 'network', 'rm', 'secpal-backend101-edge']])
                for action in ('stop', 'reset-failed'):
                    self.assertIn(['systemctl', '--user', action, 'secpal-backend101-edge-network.service'], calls)

    def test_transport_projection_rejects_host_and_frontend_network_expansion(self):
        import product_backend_qualification_contract as contract
        for role in contract.BACKENDS:
            source = (ROOT / contract.SOURCES['backend_' + role]).read_text()
            with self.subTest(role=role), self.assertRaises(ValueError):
                contract.fixture_unit(source + 'Network=host\n', role)
        source = (ROOT / contract.SOURCES['backend_frontend']).read_text()
        with self.assertRaises(ValueError):
            contract.fixture_unit(source + 'Network=database.network\n', 'frontend')

    def test_fixture_rejects_additional_or_random_publications(self):
        import product_backend_qualification_contract as contract
        for role in contract.BACKENDS:
            source = (ROOT / contract.SOURCES['backend_' + role]).read_text()
            for publication in ('0.0.0.0:19000:8080/tcp', '8080', '127.0.0.1:18082:8080/tcp'):
                with self.subTest(role=role, publication=publication), self.assertRaises(ValueError):
                    contract.fixture_unit(source + 'PublishPort=' + publication + '\n', role)

    def test_admission_rejects_extra_effective_publications_and_surviving_fixture_units(self):
        import product_backend_qualification_contract as contract
        original = observation_fixture(contract)
        for flag in ('--publish 0.0.0.0:19000:8080/tcp', '--publish=8080', '-p 8080', '--publish-all', '-P'):
            raw = copy.deepcopy(original)
            product = raw['recreations'][0]['products']['api']
            product['unit'] = product['unit'].replace('--publish 127.0.0.1:18081:8080/tcp',
                '--publish 127.0.0.1:18081:8080/tcp ' + flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                contract.normalize_observations(raw, 993, 992, 991)
        raw = copy.deepcopy(original)
        raw['cleanup']['fixture_unit_states'] = ['inactive', 'inactive', 'active']
        with self.assertRaises(ValueError):
            contract.admit_cleanup(raw['cleanup'])

    def test_closed_selector_is_dispatchable_only_from_main(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text())
        inputs = workflow.get('on', workflow.get(True))['workflow_dispatch']['inputs']
        self.assertIn('product-backend-policy', inputs['qualification']['options'])
        text = (ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text()
        self.assertIn('[[ "$IS_DEFAULT_BRANCH" == true ]]', text)
        self.assertIn('sudo /usr/local/sbin/secpal-qualify-product-backends', text)
        self.assertIn('product-backend-qualification-control.py "$operation"', text)

    def test_closed_manifest_authenticates_exact_policy_closure(self):
        import product_backend_qualification_contract as contract
        sources = {name: (ROOT / relative).read_bytes() for name, relative in contract.SOURCES.items()}
        manifest = contract.manifest('a' * 40, 'gcp-rocky-10-2-x86-64', '123', '1', sources)
        contract.admit_manifest(manifest, sources)
        for name in sources:
            changed = dict(sources, **{name: sources[name] + b'\n'})
            with self.assertRaises(ValueError):
                contract.admit_manifest(manifest, changed)
        for key, value in (('control_sha', 'refs/pull/293/head'), ('profile', '../../evil'), ('command', 'id')):
            changed = dict(manifest, **{key: value})
            with self.assertRaises(ValueError):
                contract.admit_manifest(changed, sources)

    def test_admission_rejects_self_assertion_and_wrong_service_path(self):
        import product_backend_qualification_contract as contract
        self.assertRaises(ValueError, contract.admit_evidence, {'result': 'PASS'}, {}, {})
        expected = contract.required_observations()
        binding = dict(control_sha='a' * 40, profile='gcp-rocky-10-2-x86-64',
                       run_id='123', run_attempt='1', instance_id='456', instance_name='sprk-123-1-instance')
        source = {'policy': 'b' * 64}
        raw = dict(schema_version=1, selector=contract.SELECTOR, binding=binding,
                   source_sha256=source, observations=expected,
                   haproxy_uid=993, runtime_uid=992, unrelated_uid=991)
        raw.update(records=observation_fixture(contract),host_evidence_sha256='c' * 64,
                   rocky_signing_key='6fedfc85\n' + base64.b64encode(b'reviewed package-key test packet').decode(),
                   packages=[])
        for name in contract.PACKAGES:
            nevra = f'{name}-1.0-1.el10_2.x86_64'
            raw['packages'].append(dict(name=name, epoch='0', version='1.0', release='1.el10_2', architecture='x86_64', nevra=nevra,
                repositories=['appstream'], signed_header='\n'.join((name, '0', '1.0', '1.el10_2', 'x86_64', nevra, 'd' * 64, '8', 'e' * 64,
                'RSA/SHA256, Wed May 21 13:19:52 2025, Key ID 5b106c736fedfc85')), verification='\n'.join(sorted(contract.rpm.VERIFIED_HEADER_LINES))))
        patch = mock.patch.object(contract.rpm, 'ROCKY_KEY_PACKET_SHA256', hashlib.sha256(b'reviewed package-key test packet').hexdigest())
        patch.start()
        self.addCleanup(patch.stop)
        contract.admit_evidence(raw, binding, source)
        for key in expected:
            changed = copy.deepcopy(raw)
            changed['observations'][key] = not expected[key] if isinstance(expected[key], bool) else 'spoofed'
            with self.assertRaises(ValueError, msg=key):
                contract.admit_evidence(changed, binding, source)
        changed = dict(raw, haproxy_uid=raw['runtime_uid'])
        self.assertRaises(ValueError, contract.admit_evidence, changed, binding, source)
        changed = dict(raw, result='PASS')
        self.assertRaises(ValueError, contract.admit_evidence, changed, binding, source)

    def test_independent_raw_admission_rejects_effective_boundary_regressions(self):
        import product_backend_qualification_contract as contract
        original=observation_fixture(contract)
        contract.normalize_observations(original,993,992,991)
        variants=[]
        def change(mutator):
            raw=copy.deepcopy(original);mutator(raw);variants.append(raw)
        change(lambda r:r['av'][0]['decision'].update(flags=1))
        change(lambda r:r['av'][2]['decision'].update(allowed=1))
        change(lambda r:r['nftables']['nftables'].pop())
        change(lambda r:r['haproxy']['processes'][0].update(cgroup='0::/user.slice'))
        change(lambda r:r['haproxy'].update(stats_holders=[]))
        change(lambda r:r['haproxy'].update(all_pids=[123,789]))
        change(lambda r:r['accounts']['haproxy'].update(shell='/bin/bash'))
        change(lambda r:r['recreations'][2]['runtime'].update(unit_states=['active']*4))
        change(lambda r:r['recreations'][2]['runtime'].update(manager_override_keys=['CONTAINER_HOST']))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(listeners=['0.0.0.0:18080']))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(network_mode='host'))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(environment_keys=['DB_PASSWORD']))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(networks=['secpal-backend101-edge', 'database']))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(environment_keys=['SECPAL_SECRET_MIGRATION']))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(environment_keys=['FILESYSTEM_DISK']))
        change(lambda r:r['recreations'][1]['products']['frontend'].update(mount_types=['bind']))
        change(lambda r:r['recreations'][1]['products']['api'].update(networks=['secpal-backend101-application']))
        change(lambda r:r['recreations'][1].update(http_stats=r['recreations'][1]['http_stats'].replace('UP','DOWN')))
        change(lambda r:r['unrelated'].update(avc=r['unrelated']['avc'].replace('pid=123','pid=789')))
        change(lambda r:r['external']['api'].update(positive_http_code='000'))
        change(lambda r:r['external']['api'].update(ingress_status=0))
        change(lambda r:r['barrier'].update(stale_pre_status=0))
        change(lambda r:r['cleanup'].update(remaining_containers=['secpal-backend101-api']))
        change(lambda r:r['cleanup'].update(remaining_images=['sha256:'+'a'*64]))
        change(lambda r:r['cleanup'].update(pasta_boolean='pasta_bind_all_ports --> on'))
        change(lambda r:r['withdrawal'].update(unit_states=['active','active']))
        change(lambda r:r['withdrawal'].update(listeners=['127.0.0.1:18080']))
        change(lambda r:r['cleanup']['host_baseline'].update(rpm_sha256='e'*64))
        change(lambda r:r['cleanup']['host_baseline'].update(passwd_sha256='e'*64))
        for raw in variants:
            with self.assertRaises((ValueError,KeyError,TypeError)):
                contract.normalize_observations(raw,993,992,991)
        for key in original:
            changed=dict(original);del changed[key]
            self.assertRaises(ValueError,contract.normalize_observations,changed,993,992,991)

    def test_owner_and_live_nft_representation_agree_and_mutations_fail(self):
        import product_backend_qualification_contract as contract
        from product_backend_contract import host_policy
        with tempfile.TemporaryDirectory() as temporary:
            rules = Path(temporary) / 'backend.nft'
            rules.write_text(host_policy(993)['product-backends.nft'])
            result = subprocess.run(['unshare', '--user', '--map-auto', '--map-root-user', '--net',
                'sh', '-c', 'nft -f "$1" && nft -j list table inet secpal_product_backends', 'sh', str(rules)],
                capture_output=True, text=True)
            if result.returncode:
                self.skipTest('real nft JSON agreement requires disposable namespace capability')
            observed = json.loads(result.stdout)
            contract.admit_nftables(observed, 993)
            with self.assertRaises(ValueError):
                contract.admit_nftables(observed, 992)
            for index, entry in enumerate(observed['nftables']):
                if 'rule' in entry:
                    changed = copy.deepcopy(observed)
                    del changed['nftables'][index]
                    self.assertRaises(ValueError, contract.admit_nftables, changed, 993)

    def test_closed_workflow_selection_rejects_candidate_control(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text())
        step = next(s for s in workflow['jobs']['validate']['steps'] if s.get('id') == 'closed')
        script = step['run']
        for target, profile, main, expected in (
                ('', 'gcp-rocky-10-2-arm64', 'true', 0),
                ('', 'gcp-rocky-10-2-x86-64', 'true', 0),
                ('ef05207311e55b17c9b777e74f867efb5fb5d6b3', 'gcp-rocky-10-2-arm64', 'true', 1),
                ('', '../../evil', 'true', 1), ('', 'gcp-rocky-10-2-arm64', 'false', 1)):
            with tempfile.TemporaryDirectory() as temporary:
                env = dict(os.environ, RAW_QUALIFICATION='product-backend-policy', RAW_OPERATION='provision-and-prepare',
                    RAW_TARGET_SHA=target, RAW_PROFILE=profile, RAW_SOURCE_RUN_ID='', RAW_SOURCE_RUN_ATTEMPT='',
                    IS_DEFAULT_BRANCH=main, GITHUB_OUTPUT=str(Path(temporary)/'output'))
                result = subprocess.run(['bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                    cwd=ROOT, env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, expected == 0)
        for job in ('validate', 'qualify_target'):
            self.assertNotIn('id-token', workflow['jobs'][job].get('permissions', {}))
            self.assertNotIn('environment', workflow['jobs'][job])
        provision = workflow['jobs']['provision']['steps']
        confirm = next(i for i, s in enumerate(provision) if s['name'] == 'Reconfirm backend bytes before provider credentials')
        oidc = next(i for i, s in enumerate(provision) if str(s.get('uses','')).startswith('google-github-actions/auth@'))
        self.assertLess(confirm, oidc)
        self.assertIn('always()', workflow['jobs']['cleanup']['if'])

    def test_dispatch_architecture_guard_rejects_impure_and_unclassified_operations(self):
        spec=importlib.util.spec_from_file_location('backend_guard',ROOT/'scripts/validate-product-backend-qualification.py')
        guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
        guard.validate(ROOT)
        import product_backend_qualification_contract as contract
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            relative_paths=set(contract.SOURCES.values())|{'.github/workflows/rocky-cloud-qualification.yml','infra/ci-cloud/gcp-rocky/metadata.tf','scripts/ci-cloud/bootstrap-rocky-host.tftpl'}
            for relative in relative_paths:
                target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
            cases=(('scripts/ci-cloud/product_backend_qualification_contract.py','\nimport subprocess\n'),
                   ('scripts/ci-cloud/qualify-product-backends.py','\nos.system("id")\n'),
                   ('scripts/ci-cloud/qualify-product-backends.py','\nobserver.run("unclassified", ["id"])\n'),
                   ('scripts/ci-cloud/qualify-product-backends.py','\nsubprocess.Popen(["/bin/sh", "-c", "id"])\n'),
                   ('scripts/ci-cloud/qualify-product-backends.py','\nprocess(["/bin/sh", "-c", "id"])\n'),
                   ('scripts/ci-cloud/qualify-product-backends.py','\nsubprocess = fake\n'),
                   ('scripts/ci-cloud/qualify-product-backends.py','\ngetattr(subprocess, "Popen")(["id"])\n'))
            for relative,appendix in cases:
                target=root/relative;original=target.read_text();target.write_text(original+appendix)
                self.assertRaises(ValueError,guard.validate,root);target.write_text(original)

    def test_qualification_does_not_install_packages(self):
        text = (ROOT / 'scripts/ci-cloud/qualify-product-backends.py').read_text()
        self.assertNotIn("['dnf4'", text)
        preparation = (ROOT / 'scripts/ci-cloud/prepare-rocky-host.sh').read_text()
        self.assertIn('product-backend-policy', preparation)
        self.assertIn('haproxy setools-console', preparation)

    def test_pure_admission_has_no_external_authority(self):
        path = ROOT / 'scripts/ci-cloud/product_backend_qualification_contract.py'
        tree = ast.parse(path.read_text())
        allowed = {'hashlib', 'json', 're', 'product_backend_contract', 'rocky_preparation_contract', 'csv', 'io', 'types'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue({a.name for a in node.names} <= allowed)
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, allowed)
        text = (ROOT / 'scripts/ci-cloud/qualify-product-backends.py').read_text()
        self.assertNotIn('eval(', text)
        self.assertNotIn('shell=True', text)
        self.assertIn('check_effective_policy()', text)
        self.assertIn('/sys/fs/selinux/policy', text)
        self.assertIn('container_runtime_t', text)
        self.assertIn('haproxy_t', text)


if __name__ == '__main__':
    unittest.main()
