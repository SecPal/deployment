#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""DIRECT TLS boundary and durable publication contract regressions."""

import sys
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

    def test_read_only_health_never_authorizes_pending_publication(self):
        spec=importlib.util.spec_from_file_location('tls_health_controller',ROOT/'scripts/direct-viewer-tls.py')
        controller=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        with mock.patch.object(sys,'argv',['direct-viewer-tls.py','--health']), \
                mock.patch.object(controller,'package_authority'), mock.patch.object(controller,'infrastructure'), \
                mock.patch.object(controller,'status',return_value=1), \
                mock.patch.object(controller,'serialized',side_effect=AssertionError('health acquired publication authority')):
            self.assertEqual(controller.main(),1)


if __name__=='__main__': unittest.main()
