#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""DIRECT TLS boundary and durable publication contract regressions."""

import sys
from contextlib import contextmanager
import getopt
import hashlib
import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import haproxy_direct_contract as direct
import haproxy_config_lifecycle as publication
import haproxy_composition_contract as composition
from viewer_tls_contract import admit_file, admit_activation, admit_hsts, health, policy
import viewer_tls_runtime as runtime


class TLSContract(unittest.TestCase):
    @contextmanager
    def policy_installer(self):
        spec=importlib.util.spec_from_file_location('tls_install_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with mock.patch.object(controller,'RUNTIME',root), \
                    mock.patch.object(controller,'ACME',root/'acme'), \
                    mock.patch.object(controller,'POLICY_READY',root/'ready.json'), \
                    mock.patch.object(controller.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=188)), \
                    mock.patch.object(controller,'trusted'), mock.patch.object(controller,'policy_check') as check:
                yield controller,check

    def test_policy_install_explicit_modes_survive_regeneration(self):
        # GNU option permutation and semodule 3.10's trailing-argument rule:
        # https://github.com/SELinuxProject/selinux/blob/3.10/policycoreutils/semodule/semodule.c
        # This source contract is distinct from native compilation/store evidence.
        def modes(arguments):
            options,paths=getopt.gnu_getopt(arguments[1:],'i:e:r:d:')
            return options+[(options[-1][0],path) for path in paths],paths
        legacy=['/usr/sbin/semodule','-i','STATE_CIL','TRANSPORT_CIL',
                '-e','secpal_acme_state','-e','secpal_acme']
        self.assertEqual(modes(legacy)[0],[('-i','STATE_CIL'),('-e','secpal_acme_state'),
            ('-e','secpal_acme'),('-e','TRANSPORT_CIL')])
        installed=[]
        def observe(operation,arguments,**kwargs):
            if operation=='observe-inactive-policy-construction': return b'inactive'
            if operation=='observe-existing-acme-table': return b'{"nftables":[]}'
            if operation=='install-acme-selinux-policy':
                options,paths=modes(arguments)
                self.assertEqual(paths,[],'CIL pathname inherits the final semodule mode')
                self.assertEqual([option for option,_ in options],['-i','-i','-e','-e'])
                state,transport=Path(options[0][1]),Path(options[1][1])
                self.assertEqual(arguments,['/usr/sbin/semodule','-i',str(state),'-i',str(transport),
                    '-e','secpal_acme_state','-e','secpal_acme'])
                self.assertEqual((state.name,transport.name),('secpal_acme_state.cil','secpal_acme.cil'))
                installed.append((state.read_text(),transport.read_text()))
            return b''
        with self.policy_installer() as (controller,check), \
                mock.patch('viewer_tls_runtime.subprocess.run') as native, \
                mock.patch.object(controller,'run',side_effect=observe):
            for _ in range(2):
                before=len(installed)
                controller.policy_install()
                self.assertEqual(len(installed),before+1,'installation split into multiple transactions')
                self.assertEqual(json.loads(controller.POLICY_READY.read_bytes()),
                    {'policy_sha256':controller.policy_digest(188)})
            self.assertEqual(check.call_count,2)
            native.assert_not_called()
        generated=policy(188)
        self.assertEqual(installed,[(generated['state_cil'],generated['cil'])]*2)

    def test_failed_policy_install_has_no_readiness_or_transport_authority(self):
        mutations=[]
        def observe(operation,arguments,**kwargs):
            if operation=='observe-inactive-policy-construction': return b'inactive'
            if operation=='observe-existing-acme-table': return b'{"nftables":[]}'
            if operation=='install-acme-selinux-policy':
                # Exercise the shared bounded failure primitive, not a mocked
                # successful exit standing in for native policy compilation.
                return runtime.run(operation,arguments,**kwargs)
            mutations.append(operation)
            return b''
        with self.policy_installer() as (controller,check), \
                mock.patch.object(controller,'run',side_effect=observe), \
                mock.patch.object(runtime.subprocess,'run',return_value=SimpleNamespace(
                    returncode=1,stdout=b'',stderr=b'Failed on secpal_acme!')) as native, \
                mock.patch.object(controller,'atomic_json') as marker:
            with self.assertRaisesRegex(ValueError,'install-acme-selinux-policy'):
                controller.policy_install()
            self.assertFalse(controller.POLICY_READY.exists())
            marker.assert_not_called()
            check.assert_not_called()
            self.assertEqual(mutations,[],'failed installation granted transport authority')
            native.assert_called_once()
            self.assertEqual(native.call_args.kwargs['timeout'],15)


    def test_systemd_package_prerequisite_is_current_exact_and_successful(self):
        spec=importlib.util.spec_from_file_location('tls_systemd_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        command=['/usr/bin/python3','-I','-S',str(controller.HELPER),'--verify-packages']
        # Actual systemd 257 busctl JSON representation, with synthetic times.
        values={
            'InvocationID':{'type':'ay','data':list(range(16))},
            'ExecStartPre':{'type':'a(sasbttttuii)','data':[
                ['/usr/bin/python3',command,False,100000,100,100500,500,42,1,0]]},
            'ExecMainStartTimestampMonotonic':{'type':'t','data':501},
            'InactiveExitTimestampMonotonic':{'type':'t','data':101},
            'ActiveState':{'type':'s','data':'activating'},
        }
        def observe(operation,arguments,**_):
            self.assertEqual(operation,'observe-systemd-package-prerequisite')
            self.assertEqual(arguments[:5],['/usr/bin/busctl','--system','--json=short',
                                           '--timeout=5','get-property'])
            return json.dumps(values[arguments[-1]]).encode()
        with mock.patch.object(Path,'read_text',return_value='0::/system.slice/secpal-viewer-renew.service\n'), \
                mock.patch.object(controller,'run',side_effect=observe):
            self.assertTrue(controller.systemd_package_admission())
            for field,bad in [('ExecStartPre',[]),('ExecStartPre',[
                    ['/usr/bin/python3',command,False,100000,100,100500,500,42,1,1]]),
                    ('ExecStartPre',[
                    ['/usr/bin/python3',command,True,100000,100,100500,500,42,1,0]]),
                    ('ExecStartPre',[
                    ['/usr/bin/python3',command[:-1]+['--health'],False,100000,100,100500,500,42,1,0]]),
                    ('InactiveExitTimestampMonotonic',502),
                    ('ExecMainStartTimestampMonotonic',499),
                    ('ActiveState','failed'),('InvocationID',[0]*16)]:
                with self.subTest(field=field,bad=bad):
                    previous=values[field]['data']
                    values[field]['data']=bad
                    try:
                        with self.assertRaisesRegex(ValueError,'admit-systemd-package-prerequisite'):
                            controller.systemd_package_admission()
                    finally: values[field]['data']=previous
            with mock.patch.object(controller,'run',side_effect=ValueError('dbus-unavailable')):
                with self.assertRaises(ValueError): controller.systemd_package_admission()
            original_type=values['ExecStartPre']['type']
            values['ExecStartPre']['type']='s'
            with self.assertRaisesRegex(ValueError,'admit-systemd-package-prerequisite'):
                controller.systemd_package_admission()
            values['ExecStartPre']['type']=original_type
            calls=0
            def changed_invocation(operation,arguments,**kwargs):
                nonlocal calls
                if arguments[-1]=='InvocationID':
                    calls+=1
                    return json.dumps({'type':'ay','data':[calls]*16}).encode()
                return observe(operation,arguments,**kwargs)
            with mock.patch.object(controller,'run',side_effect=changed_invocation):
                with self.assertRaisesRegex(ValueError,'admit-systemd-package-prerequisite'):
                    controller.systemd_package_admission()
        with mock.patch.object(Path,'read_text',return_value='0::/system.slice/unrelated.service\n'), \
                mock.patch.object(controller,'run') as native:
            self.assertFalse(controller.systemd_package_admission())
            native.assert_not_called()

    def test_host_prerequisite_always_runs_full_package_observer(self):
        spec=importlib.util.spec_from_file_location('tls_host_observer',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        class PackageMismatch(RuntimeError):
            operation='verify-installed-package-payload'
            reason='command-failed'
        observer=mock.Mock()
        actual_stat=Path.stat
        def namespace_metadata(path,*args,**kwargs):
            if str(path) in ('/proc/1/ns/mnt','/proc/self/ns/mnt'):
                return SimpleNamespace(st_dev=1,st_ino=10 if str(path).startswith('/proc/1/') else 11)
            return actual_stat(path,*args,**kwargs)
        module=SimpleNamespace(observe_installed=observer,QualificationError=PackageMismatch)
        with mock.patch.object(Path,'stat',namespace_metadata), \
                mock.patch.object(controller,'SOURCE',ROOT), mock.patch.object(controller,'trusted'), \
                mock.patch.object(controller.importlib.util,'module_from_spec',return_value=module), \
                mock.patch.object(controller.importlib.util,'spec_from_file_location',
                                  return_value=SimpleNamespace(loader=mock.Mock())), \
                mock.patch.object(controller,'systemd_package_admission',return_value=True) as bypass, \
                mock.patch('sysconfig.get_path',return_value='/unused'), \
                mock.patch.object(sys,'path',sys.path.copy()), \
                mock.patch.object(controller,'run',return_value=b'ActiveState=inactive\nUnitFileState=disabled'):
            controller.package_authority(host_view=True)
            observer.assert_called_once_with(controller.BUNDLE,controller.platform.machine(),
                json.loads((ROOT/'config/production/certbot-package-policy.json').read_bytes()))
            bypass.assert_not_called()
            observer.side_effect=PackageMismatch()
            with self.assertRaisesRegex(ValueError,'certbot-supply-verify-installed-package-payload-command-failed'):
                controller.package_authority(host_view=True)
        for group in ['0::/system.slice/unrelated.service\n',
                      '0::/system.slice/secpal-viewer-renew.service-attacker\n']:
            with mock.patch.object(Path,'read_text',return_value=group), \
                    mock.patch.dict(controller.os.environ,{'INVOCATION_ID':'a'*32}), \
                    mock.patch.object(controller,'run') as native:
                self.assertFalse(controller.systemd_package_admission())
                native.assert_not_called()

    def test_package_prerequisite_retains_host_verification_and_runtime_sandbox(self):
        for name in ('renew','health'):
            text=(ROOT/f'config/production/host-systemd/secpal-viewer-{name}.service').read_text()
            self.assertIn('ExecStartPre=+/usr/bin/python3 -I -S '
                          '/usr/local/libexec/secpal/viewer-tls-source/scripts/direct-viewer-tls.py --verify-packages',text)
            self.assertIn('ExecStart=/usr/bin/python3 -I -S ',text)
            for restriction in ('NoNewPrivileges=true','ProtectSystem=strict','ProtectHome=true',
                                'PrivateTmp=true','PrivateDevices=true','ProtectKernelTunables=true',
                                'ProtectKernelModules=true','ProtectControlGroups=true','SocketBindDeny=any'):
                self.assertIn(restriction,text)
        state=policy(188)['state_cil']
        self.assertIn('(allow init_t secpal_acme_state_t (dir (mounton)))',state)
        self.assertNotIn('(allow container_t',state)
        self.assertNotIn('(allow haproxy_t',state)
        self.assertNotIn('(allow init_t file_type',state)

    def test_failed_package_prerequisite_cannot_publish_or_execute_acme(self):
        spec=importlib.util.spec_from_file_location('tls_failed_package_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        with mock.patch.object(sys,'argv',['direct-viewer-tls.py','--renew']), \
                mock.patch.object(controller,'package_authority',side_effect=ValueError('package-tampered')), \
                mock.patch.object(controller,'renew') as renew, mock.patch.object(controller,'deploy') as deploy:
            with self.assertRaisesRegex(ValueError,'package-tampered'): controller.main()
            renew.assert_not_called()
            deploy.assert_not_called()

    def spec(self, lifecycle='http01'):
        return direct.from_document({'topology':'single','frontend_host':'app.example.test',
            'api_host':'api.example.test','tls_lifecycle':lifecycle,
            'listeners':[{'address':'127.0.0.1','port':18443,'transport':'https'},
                         {'address':'::1','port':18085,'transport':'http'}]})

    def test_closed_tls_composition_and_regeneration(self):
        spec=self.spec()
        text=direct.render(spec)
        self.assertEqual(direct.from_config(text.encode()),spec)
        self.assertIn('127.0.0.1:18084',text)
        self.assertIn('url -m reg ^/\\.well-known/acme-challenge/[A-Za-z0-9_-]{43}$',text)
        self.assertIn('acl acme_method method GET',text)
        self.assertIn('redirect',text)
        self.assertNotIn('Strict-Transport-Security',text)
        self.assertIn('BindsTo=secpal-acme-policy.service',composition.listener_constraints(spec.listeners))
        for mode in ('dns01','protected',True,'preload'):
            with self.assertRaises(ValueError): self.spec(mode)

    def test_private_publication_and_interrupted_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'serving'
            path.write_bytes(b'old')
            path.chmod(0o600)
            journal=Path(directory)/'pending'
            publication.publish(path,b'new',lambda _:None,lambda:None,
                                mode=0o600,journal=journal)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertFalse(journal.exists())
            with self.assertRaises(ValueError):
                publication.publish(path,b'rejected',lambda _:None,
                    lambda: (_ for _ in ()).throw(ValueError('reload-failed')),
                    mode=0o600,journal=journal)
            self.assertEqual(path.read_bytes(),b'new')

    def test_initial_preparation_never_claims_activation_or_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            path,journal=Path(directory)/'serving',Path(directory)/'pending'
            called=[]
            accepted=publication.publish(path,b'initial',lambda _:None,lambda:called.append('reload'),
                mode=0o600,journal=journal,prepare_initial=True)
            self.assertFalse(accepted)
            self.assertEqual(called,[])
            self.assertTrue(journal.exists())
            with self.assertRaises(ValueError):
                publication.publish(path,b'next',lambda _:None,lambda:None,mode=0o600,journal=journal)
            publication.recover_publication(path,journal,lambda _:None,lambda:called.append('recover'))
            self.assertEqual(called,['recover'])
            self.assertFalse(path.exists())

    def test_secret_file_and_hsts_admission(self):
        info=dict(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_uid=0,st_gid=0,st_size=1024)
        admit_file(SimpleNamespace(**info),private=True,label='etc_t')
        for override in ({'st_mode':stat.S_IFREG|0o644},{'st_uid':1000},{'st_gid':1000},
                         {'st_nlink':2},{'st_size':0},{'st_mode':stat.S_IFLNK|0o600}):
            with self.assertRaises(ValueError): admit_file(SimpleNamespace(**(info|override)),private=True,label='etc_t')
        with self.assertRaises(ValueError): admit_file(SimpleNamespace(**info),private=True,label='container_file_t')
        receipt={'fingerprint':'a'*64,'names':['api.example.test','app.example.test'],'initial_at':10,'renewed_at':None}
        admit_activation(receipt,receipt['names'],100)
        with self.assertRaises(ValueError): admit_activation(dict(receipt,initial_at=101),receipt['names'],100)
        with self.assertRaises(ValueError): admit_activation(receipt,receipt['names'],100,fingerprint='b'*64)
        with self.assertRaises(ValueError): admit_hsts(receipt,{'status':'SUCCESS','at':100},100)
        admitted=dict(receipt,renewed_at=50)
        admit_hsts(admitted,{'status':'SUCCESS','at':100},100)
        for status in ('UNKNOWN','FAILURE'):
            with self.assertRaises(ValueError): admit_hsts(admitted,{'status':status,'at':100},100)
        with self.assertRaises(ValueError): admit_hsts(admitted,{'status':'SUCCESS','at':49},100)

    def test_health_missing_stale_failed_and_expired(self):
        now=1000000
        observation={'observed_at':now,'not_after':now+90*86400,'served':'MATCH','renewal':'SUCCESS','renewal_at':now}
        self.assertEqual(health(observation,now)['state'],'HEALTHY')
        for changes,state in [({'observed_at':None},'UNKNOWN'),({'observed_at':now-86401},'UNKNOWN'),
            ({'renewal':'UNKNOWN'},'UNKNOWN'),({'renewal':'FAILURE'},'DEGRADED'),
            ({'served':'MISMATCH'},'FAILED'),({'not_after':now+86400},'DEGRADED'),
            ({'not_after':now-1,'observed_at':None},'FAILED')]:
            self.assertEqual(health(observation|changes,now)['state'],state)
        with self.assertRaises(ValueError): health(observation|{'renewal':'PASS'},now)
        isolation=policy(188)
        self.assertIn('meta skuid != { 0, 188 } reject',isolation['nft'])
        self.assertIn('iifname != "lo"',isolation['nft'])

    def test_uncertain_journal_removal_keeps_recovery_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            path,journal=Path(directory)/'serving',Path(directory)/'pending'
            path.write_bytes(b'old'); path.chmod(0o600)
            calls=[]
            original=publication.sync_directory
            def sync(parent):
                calls.append(parent)
                if len(calls)==3: raise OSError('fixture uncertain journal removal')
                original(parent)
            with mock.patch.object(publication,'sync_directory',sync):
                with self.assertRaises(ValueError):
                    publication.publish(path,b'new',lambda _:None,lambda:None,
                        recover=lambda:(_ for _ in ()).throw(ValueError('recovery-failed')),
                        mode=0o600,journal=journal)
            self.assertEqual(path.read_bytes(),b'old')
            self.assertTrue(journal.exists(),'uncertain recovery discarded its durable authority')
            publication.recover_publication(path,journal,lambda _:None,lambda:None)
            self.assertEqual(path.read_bytes(),b'old')

    def test_pending_first_renewal_cannot_activate_hsts(self):
        # Isolate the boot gate from already-admitted root filesystem, native
        # parser and live publication-lock observations. No secret fixture.
        pem=b'-----BEGIN CERTIFICATE-----\nmock-public-observation\n-----END CERTIFICATE-----\n'
        receipt={'fingerprint':hashlib.sha256(b'old-leaf').hexdigest(),
            'names':['api.example.test','app.example.test'],'initial_at':10,'renewed_at':None}
        files={'/etc/haproxy/secpal-viewer.pem':pem,'/trust':b'mock-trust',
            '/etc/haproxy/.secpal-viewer-pending.json':json.dumps({'previous_sha256':'a'*64,
                'candidate_sha256':hashlib.sha256(pem).hexdigest()}).encode(),
            '/srv/secpal/acme/activation.json':json.dumps(receipt).encode()}
        files['/etc/haproxy/secpal.cfg']=direct.render(self.spec('hsts')).encode()
        nodes={}
        info=SimpleNamespace(st_uid=0,st_gid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=len(pem))
        def observed(value):
            name=str(value)
            if name not in nodes:
                node=mock.MagicMock(spec=Path)
                node.__str__.return_value=name
                node.parents=()
                node.lstat.return_value=info
                node.read_bytes.side_effect=lambda:files[name]
                node.exists.side_effect=lambda:name in files
                node.with_name.side_effect=lambda child:observed(str(Path(name).with_name(child)))
                node.__truediv__.side_effect=lambda child:observed(name+'/'+child)
                nodes[name]=node
            return nodes[name]
        with mock.patch.object(runtime,'Path',observed), mock.patch.object(runtime,'TRUST',observed('/trust')), \
                mock.patch.object(runtime.os,'getxattr',return_value=b'system_u:object_r:etc_t:s0'), \
                mock.patch.object(runtime.os,'open',return_value=7), mock.patch.object(runtime.os,'fstat',return_value=info), \
                mock.patch.object(runtime.os,'close'), mock.patch('fcntl.flock',side_effect=BlockingIOError), \
                mock.patch.object(runtime.ssl,'PEM_cert_to_DER_cert',return_value=b'new-leaf'), \
                mock.patch.object(runtime.ssl,'SSLContext'), mock.patch.object(runtime,'run'):
            with self.assertRaisesRegex(ValueError,'admit-hsts-accepted-renewal'):
                runtime.boot_admission(self.spec('hsts'),allow_pending_reload=True)
            files['/srv/secpal/acme/activation.json']=json.dumps(dict(receipt,renewed_at=50)).encode()
            runtime.boot_admission(self.spec('hsts'),allow_pending_reload=True)
            files['/etc/haproxy/secpal.cfg']=direct.render(self.spec()).encode()
            with self.assertRaisesRegex(ValueError,'admit-certificate-only-reload'):
                runtime.boot_admission(self.spec('hsts'),allow_pending_reload=True)
            files['/etc/haproxy/secpal.cfg']=direct.render(self.spec('hsts')).encode()
            files['/etc/haproxy/.secpal-viewer-pending.json']=json.dumps({
                'previous_sha256':hashlib.sha256(pem).hexdigest(),'candidate_sha256':'b'*64}).encode()
            with mock.patch.object(runtime,'run') as trust:
                runtime.boot_admission(self.spec('hsts'),allow_pending_reload=True)
                self.assertTrue(all('-no_check_time' in call.args[1] for call in trust.call_args_list),
                    'digest-bound predecessor compensation must preserve an expired serving generation')

    def test_read_only_health_never_authorizes_pending_publication(self):
        spec=importlib.util.spec_from_file_location('tls_health_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        with mock.patch.object(sys,'argv',['direct-viewer-tls.py','--health']), \
                mock.patch.object(controller,'package_authority'), mock.patch.object(controller,'infrastructure'), \
                mock.patch.object(controller,'status',return_value=1), \
                mock.patch.object(controller,'serialized',side_effect=AssertionError('health acquired publication authority')):
            self.assertEqual(controller.main(),1)
        admitted=[]
        @contextmanager
        def lock(_):
            admitted.append('locked')
            yield
        def infrastructure():
            self.assertEqual(admitted,['locked'],'policy observation preceded serialization')
            admitted.append('policy')
        with mock.patch.object(sys,'argv',['direct-viewer-tls.py','--renew']), \
                mock.patch.object(controller,'package_authority'), \
                mock.patch.object(controller,'infrastructure',side_effect=infrastructure), \
                mock.patch.object(controller,'serialized',side_effect=lock), \
                mock.patch.object(controller,'renew'):
            self.assertEqual(controller.main(),0)

    def test_renewal_reconciles_unactivated_lineage_and_records_admission_failure(self):
        spec=importlib.util.spec_from_file_location('tls_renew_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        old=SimpleNamespace(fingerprint='a'*64,not_after=2000000)
        new=SimpleNamespace(fingerprint='b'*64,not_after=2000000)
        state={'active':old,'result':None}
        def deploy(): state['active']=new
        with mock.patch.object(controller,'configuration',return_value=self.spec()), \
                mock.patch.object(controller,'acme_config',return_value={'email':'fixture@example.test','directory':'staging'}), \
                mock.patch.object(controller,'renewal_config'), mock.patch.object(controller,'trusted'), \
                mock.patch.object(controller,'current_certificate',side_effect=lambda *a,**k:state['active']), \
                mock.patch.object(controller,'source_material',return_value=new), \
                mock.patch.object(controller,'accepted_receipt',side_effect=lambda _: {'fingerprint':state['active'].fingerprint}), \
                mock.patch.object(controller,'verify_served'), mock.patch.object(controller,'JOURNAL',mock.Mock(exists=mock.Mock(return_value=False))), \
                mock.patch.object(controller,'run'), mock.patch.object(controller,'deploy',side_effect=deploy) as publication, \
                mock.patch.object(controller,'serialized',return_value=mock.MagicMock()), \
                mock.patch.object(controller.time,'time',return_value=1000000), \
                mock.patch.object(controller,'atomic_json',side_effect=lambda p,v:state.update(result=v)):
            controller.renew()
            publication.assert_called_once_with()
            self.assertEqual(state['result'],{'status':'SUCCESS','at':1000000})
            state['result']=None
            with mock.patch.object(controller,'renewal_config',side_effect=ValueError('fixture-admission-failed')):
                with self.assertRaises(ValueError): controller.renew()
            self.assertEqual(state['result'],{'status':'FAILURE','at':1000000})
            bootstrap=direct.Direct(self.spec().routing,tuple(row for row in self.spec().listeners if row.transport=='http'))
            with mock.patch.object(controller,'configuration',return_value=bootstrap), \
                    mock.patch.object(controller,'RECEIPT',mock.Mock(exists=mock.Mock(return_value=False))), \
                    mock.patch.object(controller,'PEM',mock.Mock(exists=mock.Mock(return_value=False))):
                controller.renew(obtain=True)
            self.assertEqual(state['result'],{'status':'UNKNOWN','at':1000000},
                'initial obtain cannot claim a verified serving renewal')

    def test_transport_prerequisites_and_stale_failure(self):
        document=direct.document(self.spec())
        document['listeners']=[row for row in document['listeners'] if row['transport']=='https']
        with self.subTest(boundary='listener'):
            with self.assertRaisesRegex(ValueError,'admit-http01-listener'):
                direct.from_document(document)
        for unit in ('secpal-viewer-renew.service','secpal-viewer-health.service'):
            text=(ROOT/'config/production/host-systemd'/unit).read_text()
            capabilities=next(line for line in text.splitlines() if line.startswith('CapabilityBoundingSet=')).split('=',1)[1].split()
            with self.subTest(boundary=unit):
                self.assertIn('CAP_NET_ADMIN',capabilities,'native nft read requires CAP_NET_ADMIN')
        unit=(ROOT/'config/production/host-systemd/secpal-acme-policy.service').read_text()
        with self.subTest(boundary='withdrawal'): self.assertIn(' --policy-withdraw',unit)
        observation={'observed_at':1000000,'not_after':10000000,'served':'MATCH','renewal':'FAILURE','renewal_at':0}
        with self.subTest(boundary='stale'): self.assertEqual(health(observation,1000000)['state'],'UNKNOWN')

    def test_withdrawal_rejects_active_or_drifted_authority_and_retains_secret_labels(self):
        from viewer_tls_contract import policy_projection
        spec=importlib.util.spec_from_file_location('tls_policy_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        mutations=[]
        state={'active':False,'drift':False,'present':True}
        def observe(operation,arguments,**kwargs):
            if operation=='observe-acme-withdrawal-stopped-unit':
                return b'active' if state['active'] else b'inactive'
            if 'tables' in operation:
                return json.dumps({'nftables':[{'table':{'name':'secpal_acme','family':'inet'}}] if state['present'] else []}).encode()
            if operation=='observe-owned-acme-withdrawal-table':
                return json.dumps({'nftables':policy_projection(188)+([{'chain':{'name':'foreign'}}] if state['drift'] else [])}).encode()
            if 'modules' in operation:
                return (('400 secpal_acme cil\n' if state['present'] else '')+'400 secpal_acme_state cil\n').encode()
            if operation.startswith('withdraw-'):
                mutations.append(arguments)
                if operation=='withdraw-acme-transport-policy': state['present']=False
            return b''
        with mock.patch.object(controller,'run',side_effect=observe), \
                mock.patch.object(controller.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=188)), \
                mock.patch.object(controller,'POLICY_READY',mock.Mock(exists=mock.Mock(return_value=False))), \
                mock.patch.object(controller,'sync_directory'):
            state['active']=True
            with self.assertRaises(ValueError): controller.policy_withdraw()
            self.assertEqual(mutations,[])
            state['active']=False; state['drift']=True
            with self.assertRaises(ValueError): controller.policy_withdraw()
            self.assertEqual(mutations,[])
            state['drift']=False
            controller.policy_withdraw()
            self.assertEqual(mutations,[['/usr/sbin/nft','delete','table','inet','secpal_acme'],
                ['/usr/sbin/semodule','-r','secpal_acme']])
            compiled=policy(188)
            self.assertNotIn('secpal_acme_state_t',compiled['cil'])
            self.assertIn('secpal_acme_state_t',compiled['state_cil'])


if __name__=='__main__': unittest.main()
