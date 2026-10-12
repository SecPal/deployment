#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real private Certbot/HAProxy fixture. Run in a fresh user/network namespace.

All private test keys/account state are generated in a temporary directory and
removed. No public endpoint, systemd mutation, DNS mutation, or production keys.
"""

import hashlib
import http.client
import importlib.util
import json
import os
import re
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'tests'))
from viewer_tls_fixture import Authority, AcmeFixture
import haproxy_direct_contract as direct
from haproxy_config_lifecycle import publish, recover_publication, sync_directory
from viewer_tls_contract import admit_certificate, health, policy, policy_projection
from haproxy_direct_policy import normalize_table
from viewer_tls_runtime import validate_candidate, verify_chain, verify_served, read_certificate
controller_spec=importlib.util.spec_from_file_location('tls_controller',ROOT/'scripts/direct-viewer-tls.py')
controller=importlib.util.module_from_spec(controller_spec)
controller_spec.loader.exec_module(controller)


def free_port(family=socket.AF_INET):
    with socket.socket(family) as sock:
        sock.bind(('::1' if family==socket.AF_INET6 else '127.0.0.1',0))
        return sock.getsockname()[1]


class TLSRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fail closed rather than binding test servers on the Polyscope host.
        outer = os.environ.get('SECPAL_FIXTURE_OUTER_NETNS')
        if (outer is None or not outer.isdecimal() or os.geteuid()!=0
                or os.stat('/proc/self/ns/net').st_ino==int(outer)):
            raise RuntimeError('isolated user/network namespace required')
        from importlib.metadata import version
        if version('certbot')!='4.2.0':
            raise RuntimeError('reviewed Certbot fixture version required')
        os.umask(0o077)
        result=subprocess.run(['/usr/sbin/nft','-f','-'],input=policy(188)['nft'].encode(),capture_output=True)
        if result.returncode: raise RuntimeError('isolated native ACME policy rejected')
        table=json.loads(subprocess.check_output(['/usr/sbin/nft','--json','list','table','inet','secpal_acme']))
        if normalize_table(table)!=policy_projection(188):
            raise RuntimeError('isolated native ACME policy drift')
        cls.temporary=tempfile.TemporaryDirectory(prefix='secpal-private-acme-')
        cls.directory=Path(cls.temporary.name)
        cls.authority=Authority(cls.directory)
        cls.names=('app.example.test','api.example.test')
        cls.http,cls.https,cls.http6,cls.https6=free_port(),free_port(),free_port(socket.AF_INET6),free_port(socket.AF_INET6)
        cls.spec=direct.from_document({'topology':'single','tls_lifecycle':'http01',
            'frontend_host':cls.names[0],'api_host':cls.names[1],'listeners':[
                {'address':'127.0.0.1','port':cls.http,'transport':'http'},
                {'address':'127.0.0.1','port':cls.https,'transport':'https'},
                {'address':'::1','port':cls.http6,'transport':'http'},
                {'address':'::1','port':cls.https6,'transport':'https'}]})
        module=importlib.util.spec_from_file_location('backend_fixture',ROOT/'tests/haproxy-base-runtime.py')
        base=importlib.util.module_from_spec(module)
        module.loader.exec_module(base)
        cls.backends={role:base.Backend(role) for role in ('frontend','api')}
        cls.pem=cls.directory/'viewer.pem'
        cls.config=cls.directory/'haproxy.cfg'
        bootstrap=direct.Direct(cls.spec.routing,tuple(row for row in cls.spec.listeners if row.transport=='http'))
        text=direct.render(bootstrap).replace('    user haproxy\n    group haproxy\n','')
        cls.config.write_text(text)
        result=subprocess.run(['/usr/sbin/haproxy','-c','-q','-f',str(cls.config)],capture_output=True)
        if result.returncode: raise RuntimeError('fixture HAProxy syntax rejected')
        cls.log=(cls.directory/'proxy.log').open('wb')
        cls.process=subprocess.Popen(['/usr/sbin/haproxy','-W','-db','-f',str(cls.config)],stdout=cls.log,stderr=cls.log)
        cls.fixture=AcmeFixture(cls.authority,cls.http,cls.names,challenge_port6=cls.http6)
        cls.client=cls.directory/'acme'
        cls.client.mkdir(mode=0o700)
        (cls.client/'client.ini').write_text('# Private fixture configuration\n')
        cls.journal=cls.directory/'pending'
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            try:
                connection=http.client.HTTPConnection('127.0.0.1',cls.http,timeout=.1)
                connection.request('GET','/',headers={'Host':cls.names[0]})
                assert connection.getresponse().status==308
                connection.close()
                break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('fixture HAProxy startup rejected')
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'fixture'): cls.fixture.stop()
        if hasattr(cls,'process'):
            cls.process.terminate()
            try: cls.process.wait(5)
            except subprocess.TimeoutExpired: cls.process.kill(); cls.process.wait(5)
        if hasattr(cls,'log'): cls.log.close()
        if hasattr(cls,'backends'):
            for backend in cls.backends.values(): backend.stop()
        if hasattr(cls,'temporary'): cls.temporary.cleanup()
    def client_arguments(self,*,obtain=False,force=False):
        code=('import sys,sysconfig; sys.path.extend([sysconfig.get_path("purelib",scheme="rpm_prefix"),'
              'sysconfig.get_path("platlib",scheme="rpm_prefix")]); from certbot.main import main; sys.exit(main(sys.argv[1:]))')
        args=['/usr/bin/python3','-I','-S','-c',code,'certonly' if obtain else 'renew',
            '--non-interactive','--authenticator','standalone','--preferred-challenges','http',
            '--http-01-address','127.0.0.1','--http-01-port','18084','--cert-name','secpal-viewer',
            '--server',self.fixture.base+'/directory','--no-verify-ssl',
            '--config',str(self.client/'client.ini'),
            '--config-dir',str(self.client/'config'),'--work-dir',str(self.client/'work'),
            '--logs-dir',str(self.client/'logs'),'--no-directory-hooks',
            '--key-type','ecdsa','--elliptic-curve','secp256r1']
        if obtain: args+=['--agree-tos','--register-unsafely-without-email','-d',','.join(self.names)]
        else: args+=['--no-random-sleep-on-renew','--deploy-hook','/usr/bin/true','--pre-hook','/usr/bin/true','--post-hook','/usr/bin/true']
        if force: args+=['--force-renewal']
        return args
    def client_run(self,**kwargs):
        result=subprocess.run(self.client_arguments(**kwargs),capture_output=True,timeout=45,
            env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C','LANG':'C','HOME':str(self.directory)})
        if result.returncode:
            # Keep private local diagnostic output ephemeral, never render it.
            (self.directory/'client-failure.log').write_bytes(result.stderr)
        kinds=sorted(set(re.findall(r'\b[A-Z][A-Za-z]*(?:Error|Exception)\b',result.stderr.decode(errors='replace'))))
        self.assertEqual(result.returncode,0,'private Certbot fixture rejected: '+str((self.fixture.failure,kinds,self.fixture.requests)))
    def issued(self):
        lineage=self.client/'config/live/secpal-viewer'
        return admit_certificate((lineage/'fullchain.pem').read_bytes(),(lineage/'privkey.pem').read_bytes(),self.names,int(time.time()))
    def admit_client_config(self):
        with mock.patch.object(controller,'ACME',self.client), mock.patch.object(controller,'HOOK','/usr/bin/true'), \
                mock.patch.object(controller,'trusted',lambda path,**_:path.lstat()), \
                mock.patch.dict(controller.DIRECTORIES,{'staging':self.fixture.base+'/directory'}):
            controller.renewal_config({'directory':'staging'})
    def reload(self):
        os.kill(self.process.pid,signal.SIGUSR2)
    def install(self,certificate,*,reload=None,verify=None):
        verify_chain(certificate,self.authority.path)
        def validate(path):
            # Source-owned projection; remove UID drop only for the isolated
            # fixture, while retaining every routing and TLS directive.
            config=direct.render(self.spec).encode()
            validate_candidate(path,config)
        def activate():
            (reload or self.reload)()
            (verify or (lambda:verify_served(certificate,self.spec,self.authority.path,timeout=3)))()
        previous=read_certificate(self.pem,self.names,int(time.time()))
        def recover():
            self.reload()
            verify_served(previous,self.spec,self.authority.path,timeout=3)
        publish(self.pem,certificate.pem,validate,activate,recover=recover,mode=0o600,journal=self.journal)
    def request(self,path,*,method='GET',host=None,ipv6=False):
        connection=http.client.HTTPConnection('::1' if ipv6 else '127.0.0.1',self.http6 if ipv6 else self.http,timeout=5)
        try:
            connection.request(method,path,headers={'Host':host or self.names[0],'X-Forwarded-Host':'evil.example.test','X-Forwarded-Proto':'http'})
            response=connection.getresponse()
            return response.status,dict(response.getheaders()),response.read()
        finally: connection.close()
    def test_complete_local_acme_and_tls_lifecycle(self):
        self.assertFalse(self.pem.exists())
        self.client_run(obtain=True)
        self.assertEqual(self.fixture.challenge_families,{'IPv4','IPv6'})
        self.admit_client_config()
        initial=self.issued()
        verify_chain(initial,self.authority.path)
        accepted=publish(self.pem,initial.pem,
            lambda path:validate_candidate(path,direct.render(self.spec).encode()),
            lambda:self.fail('initial preparation attempted renewal reload'),
            mode=0o600,journal=self.journal,prepare_initial=True)
        self.assertFalse(accepted)
        self.assertTrue(self.journal.exists())
        # Socket addition belongs to the existing host construction authority,
        # projected here onto disposable processes in this private namespace.
        self.process.terminate(); self.process.wait(5)
        text=direct.render(self.spec).replace(direct.VIEWER_PEM,str(self.pem)).replace('    user haproxy\n    group haproxy\n','')
        self.config.write_text(text)
        type(self).process=subprocess.Popen(['/usr/sbin/haproxy','-W','-db','-f',str(self.config)],stdout=self.log,stderr=self.log)
        verify_served(initial,self.spec,self.authority.path)
        self.journal.unlink(); sync_directory(self.journal.parent)
        self.assertEqual(self.pem.stat().st_mode & 0o777,0o600)
        self.assertFalse(self.journal.exists())
        verify_served(initial,self.spec,self.authority.path)
        orders=len(self.fixture.orders)
        self.client_run()
        self.assertEqual(len(self.fixture.orders),orders,'no-op renewal unexpectedly issued')
        self.assertEqual(self.issued().fingerprint,initial.fingerprint)
        self.client_run(force=True)
        self.assertEqual(self.fixture.challenge_families,{'IPv4','IPv6'})
        self.admit_client_config()
        renewed=self.issued()
        self.assertNotEqual(renewed.fingerprint,initial.fingerprint)
        self.install(renewed)
        verify_served(renewed,self.spec,self.authority.path)
        # Certbot has already renewed, but a prior hook never activated its
        # generation. A genuine no-op must reconcile it through the controller.
        self.client_run(force=True)
        reconciled=self.issued()
        orders=len(self.fixture.orders)
        source=self.directory/'source'
        (source/'config/production').mkdir(parents=True,mode=0o700)
        (source/'config/production/certbot-client.ini').write_text('# Private fixture\n')
        receipt=self.directory/'activation.json'
        controller.atomic_json(receipt,{'fingerprint':renewed.fingerprint,'names':sorted(self.names),
            'initial_at':int(time.time()),'renewed_at':None})
        def label(path): return 'etc_t' if path==self.pem else 'secpal_acme_state_t'
        with mock.patch.object(controller,'ACME',self.client), mock.patch.object(controller,'PEM',self.pem), \
                mock.patch.object(controller,'JOURNAL',self.journal), mock.patch.object(controller,'RECEIPT',receipt), \
                mock.patch.object(controller,'RENEWAL',self.directory/'renewal.json'), \
                mock.patch.object(controller,'PREVIOUS_RECEIPT',self.directory/'previous-receipt.json'), \
                mock.patch.object(controller,'RUNTIME',self.directory), mock.patch.object(controller,'SOURCE',source), \
                mock.patch.object(controller,'HOOK','/usr/bin/true'), mock.patch.object(controller,'label',side_effect=label), \
                mock.patch.object(controller,'trusted',side_effect=lambda path,**_:path.lstat()), \
                mock.patch.object(controller,'configuration',return_value=self.spec), \
                mock.patch.object(controller,'acme_config',return_value={'directory':'staging','email':'fixture@example.test'}), \
                mock.patch.dict(controller.DIRECTORIES,{'staging':self.fixture.base+'/directory'}), \
                mock.patch.object(controller,'certbot_arguments',return_value=self.client_arguments()[5:]), \
                mock.patch.object(controller,'prepare'), mock.patch.object(controller,'reload_shared',side_effect=self.reload), \
                mock.patch.object(controller,'verify_chain',side_effect=lambda certificate:verify_chain(certificate,self.authority.path)), \
                mock.patch.object(controller,'verify_served',side_effect=lambda certificate,spec:verify_served(certificate,spec,self.authority.path)):
            controller.renew()
        self.assertEqual(len(self.fixture.orders),orders,'reconciliation unexpectedly issued another certificate')
        self.assertEqual(json.loads(receipt.read_bytes())['fingerprint'],reconciled.fingerprint)
        verify_served(reconciled,self.spec,self.authority.path)
        renewed=reconciled
        # The HTTPS application seam still routes by the two fixed origins and
        # emits only #220's canonical forwarding facts, after sanitization.
        for hostname,role in zip(self.names,('frontend','api')):
            context=ssl.create_default_context(cafile=str(self.authority.path))
            connection=http.client.HTTPSConnection(hostname,self.https,context=context,timeout=5)
            connection._create_connection=lambda target,*args,**kwargs:socket.create_connection(('127.0.0.1',target[1]),*args,**kwargs)
            connection.request('GET','/ordinary',headers={'Host':hostname,'Origin':'https://app.example.test',
                'Cookie':'synthetic=session','X-Forwarded-For':'203.0.113.99','Forwarded':'for=evil',
                'X-SecPal-Role':'root','X-Forwarded-Proto':'http'})
            response=connection.getresponse()
            self.assertEqual((response.status,response.read()),(200,role.encode()))
            connection.close()
            seen={key.lower():value for key,value in self.backends[role].seen[-1].items()}
            self.assertEqual(seen['x-forwarded-for'],'127.0.0.1')
            self.assertEqual(seen['x-forwarded-proto'],'https')
            self.assertEqual(seen['x-forwarded-host'],hostname)
            self.assertEqual(seen['x-forwarded-port'],'443')
            self.assertEqual(seen['origin'],'https://app.example.test')
            self.assertEqual(seen['cookie'],'synthetic=session')
            self.assertNotIn('forwarded',seen)
            self.assertNotIn('x-secpal-role',seen)
        candidate_chain,candidate_key=self.authority.material(self.names)
        rejected=admit_certificate(candidate_chain,candidate_key,self.names,int(time.time()))
        for failure in ('reload','served'):
            with self.subTest(failure=failure):
                with self.assertRaises(ValueError):
                    if failure=='reload': self.install(rejected,reload=lambda:(_ for _ in ()).throw(ValueError('fixture-reload-failed')))
                    else: self.install(rejected,reload=lambda:None)
                self.assertTrue(self.pem.read_bytes()==renewed.pem,'last-known-good material changed')
                verify_served(renewed,self.spec,self.authority.path)
        token='A'*43
        for ipv6 in (False,True):
            for host in self.names:
                status,headers,_=self.request('/ordinary?x=1',host=host,ipv6=ipv6)
                self.assertEqual(status,308)
                self.assertEqual(headers['location'],'https://'+host+'/ordinary?x=1')
                status,headers,_=self.request('*',method='OPTIONS',host=host,ipv6=ipv6)
                self.assertEqual(status,308)
                self.assertEqual(headers['location'],'https://'+host+'/')
            for path,method,status in [('/.well-known/acme-challenge/'+token,'GET',503),
                ('/.well-known/acme-challenge/'+token,'POST',405),
                ('/.well-known/acme-challenge/'+token,'HEAD',405),
                ('/.well-known/acme-challenge/../private','GET',400),
                ('/.well-known/acme-challenge/'+token+'?x=1','GET',400),
                ('/.well-known/acme-challenge/%41'+token,'GET',400),
                ('//.well-known/acme-challenge/'+token,'GET',400),
                ('/%2ewell-known/acme-challenge/'+token,'GET',400),
                ('/.well-known%2facme-challenge/'+token,'GET',400),
                ('/.w%65ll-known/acme-challenge/'+token,'GET',400),
                ('/.well-known/acme-challenge/','GET',400)]:
                self.assertEqual(self.request(path,method=method,ipv6=ipv6)[0],status)
            self.assertEqual(self.request('/ordinary',host='evil.example.test',ipv6=ipv6)[0],421)
        # Real HTTP/2 and HTTP/1.1 requests over both TLS versions and origins.
        generation=direct.generation_id(self.spec)
        for address,port in [('127.0.0.1',self.https),('[::1]',self.https6)]:
            for hostname in self.names:
                for protocol in ('--http1.1','--http2'):
                    for version,maximum in [('--tlsv1.2','1.2'),('--tlsv1.3','1.3')]:
                        result=subprocess.run(['/usr/bin/curl','--silent','--show-error','--noproxy','*',
                            '--cacert',str(self.authority.path),'--resolve',f'{hostname}:{port}:{address}',
                            protocol,version,'--tls-max',maximum,'--max-time','5','--output','/dev/null',
                            '--write-out','%{http_code} %{http_version}',
                            '--header','X-SecPal-Runtime-Probe: '+generation,
                            '--header','Host: '+hostname,
                            f'https://{hostname}:{port}/_secpal/proxy-generation'],capture_output=True)
                        self.assertEqual(result.returncode,0,'TLS/HTTP fixture rejected')
                        self.assertEqual(result.stdout.decode(),'204 '+('2' if protocol=='--http2' else '1.1'))
        # An interrupted publication is never replayed as accepted. Restore the
        # durable predecessor, then witness actual serving state after reload.
        interrupted=self.directory/'interrupted.pem'
        interrupted.write_bytes(rejected.pem); interrupted.chmod(0o600)
        code=('import os,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
              'from haproxy_config_lifecycle import publish; '
              'publish(Path(sys.argv[2]),Path(sys.argv[3]).read_bytes(),lambda _:None,'
              'lambda:os._exit(73),mode=0o600,journal=Path(sys.argv[4]))')
        child=subprocess.run([sys.executable,'-c',code,str(ROOT/'scripts'),str(self.pem),
                              str(interrupted),str(self.journal)],capture_output=True,timeout=5)
        self.assertEqual(child.returncode,73)
        self.assertTrue(self.journal.exists())
        recover_publication(self.pem,self.journal,lambda _:None,self.reload)
        self.assertTrue(self.pem.read_bytes()==renewed.pem,'interrupted publication lost its predecessor')
        verify_served(renewed,self.spec,self.authority.path)
        now=int(time.time())
        observation={'observed_at':now,'not_after':renewed.not_after,'served':'MATCH','renewal':'SUCCESS','renewal_at':now}
        self.assertEqual(health(observation,now)['state'],'HEALTHY')
        self.assertEqual(health(dict(observation,renewal='FAILURE'),now)['state'],'DEGRADED')
        self.assertEqual(health(dict(observation,not_after=now+86400),now)['reason'],'certificate-near-expiry')
        self.assertEqual(health(dict(observation,not_after=now-1),now)['state'],'FAILED')
        self.assertEqual(health(dict(observation,observed_at=None),now)['state'],'UNKNOWN')
        lock=self.directory/'renew.lock'
        with controller.serialized(lock):
            with self.assertRaisesRegex(ValueError,'admit-exclusive-tls-invocation'):
                with controller.serialized(lock): self.fail('duplicate renewal accepted')
        with controller.serialized(lock): pass
    def test_certificate_negative_contract(self):
        chain,key=self.authority.material(self.names)
        _,wrong=self.authority.material(self.names)
        expired,expired_key=self.authority.material(self.names,expired=True)
        wrong_purpose,purpose_key=self.authority.material(self.names,purpose=False)
        near,near_key=self.authority.material(self.names,days=1)
        for fullchain,private,names in [(chain,wrong,self.names),(chain,key,('wrong.example.test',self.names[1])),
            (chain[:150],key,self.names),(chain,key[:100],self.names),
            (expired,expired_key,self.names),(wrong_purpose,purpose_key,self.names),
            (near,near_key,self.names)]:
            with self.subTest():
                with self.assertRaises(ValueError): admit_certificate(fullchain,private,names,int(time.time()))
        bad_ca=self.directory/'untrusted.pem'
        bad_ca.write_bytes(chain.split(b'-----END CERTIFICATE-----')[0]+b'-----END CERTIFICATE-----\n')
        admitted=admit_certificate(chain,key,self.names,int(time.time()))
        with self.assertRaises(ValueError): verify_chain(admitted,bad_ca)
        path=self.directory/'negative-serving.pem'
        path.write_bytes(admitted.pem); path.chmod(0o600)
        old=path.read_bytes()
        with self.assertRaises(ValueError):
            publish(path,b'partial PEM',lambda candidate:validate_candidate(candidate,direct.render(self.spec).encode()),self.reload,
                    mode=0o600,journal=self.directory/'negative-pending')
        self.assertTrue(path.read_bytes()==old,'invalid candidate replaced serving material')

    def test_private_responder_and_key_isolation(self):
        denied=subprocess.run(['/usr/sbin/capsh','--drop=cap_net_admin','--','-c',
            '/usr/sbin/nft --json list table inet secpal_acme'],capture_output=True,timeout=5)
        self.assertNotEqual(denied.returncode,0,'native nft read unexpectedly allowed without CAP_NET_ADMIN')
        with socket.socket() as responder:
            responder.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            responder.bind(('127.0.0.1',18084)); responder.listen(2)
            with socket.create_connection(('127.0.0.1',18084),timeout=1):
                accepted,_=responder.accept(); accepted.close()
            key=self.client/'config/live/secpal-viewer/privkey.pem'
            self.assertEqual(key.stat().st_mode & 0o777,0o600)
            code=('import os,socket,sys; os.setgid(1000); os.setuid(1000); '
                  'rejected=[]\n'
                  'try:\n socket.create_connection(("127.0.0.1",18084),timeout=1).close()\n'
                  'except OSError:\n rejected.append("responder")\n'
                  'try:\n open(sys.argv[1],"rb").close()\n'
                  'except PermissionError:\n rejected.append("key")\n'
                  'sys.exit(0 if rejected==["responder","key"] else 1)')
            result=subprocess.run([sys.executable,'-c',code,str(key)],capture_output=True,timeout=3)
            self.assertEqual(result.returncode,0,'unauthorized UID reached responder or private key')

    def test_z_native_transport_withdrawal(self):
        self.process.terminate(); self.process.wait(5)
        native=controller.run
        modules={'present':True}
        def observe(operation,arguments,**kwargs):
            if operation=='observe-acme-withdrawal-stopped-unit': return b'inactive'
            if 'modules' in operation:
                return (('400 secpal_acme cil\n' if modules['present'] else '')+'400 secpal_acme_state cil\n').encode()
            if operation=='withdraw-acme-transport-policy':
                self.assertEqual(arguments,['/usr/sbin/semodule','-r','secpal_acme'])
                modules['present']=False
                return b''
            return native(operation,arguments,**kwargs)
        with mock.patch.object(controller,'run',side_effect=observe), \
                mock.patch.object(controller.pwd,'getpwnam',return_value=mock.Mock(pw_uid=188)), \
                mock.patch.object(controller,'POLICY_READY',self.directory/'policy-ready'):
            controller.policy_withdraw()
        tables=json.loads(subprocess.check_output(['/usr/sbin/nft','--json','list','tables']))
        self.assertFalse(any(row.get('table',{}).get('name')=='secpal_acme' for row in tables['nftables']))


if __name__=='__main__': unittest.main()
