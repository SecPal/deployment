#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Closed, payload-free Rocky transport evidence contract and loopback integration."""
from __future__ import annotations

import copy
import contextlib
import io
import importlib.util
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
import sys
import unittest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import instance_transport_contract as contract

spec = importlib.util.spec_from_file_location('instance_transport_observer', ROOT / 'scripts/ci-cloud/observe-instance-transport.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class TransportContract(unittest.TestCase):
    def identity(self):
        return dict(repository='SecPal/deployment', trusted_control_sha='a'*40,
                    target_sha='b'*40, workflow_run_id='12345', workflow_run_attempt='1',
                    provider_profile='gcp-rocky-10-2-x86-64', project='secpal-dev',
                    zone='europe-west3-a', expected_instance_name='sprk-12345-1-instance')

    def document(self):
        return contract.assemble(self.identity(), 100, 200, 'COMPLETE', 'SUCCESS', 0, [])

    def test_closed_identity_and_document(self):
        doc = self.document()
        contract.admit(doc, self.identity())
        for change in ({'extra':'Authorization: Bearer SYNTHETIC_SECRET'},
                       {'observation_end':99}, {'observation_end':-1},
                       {'collection_status':'PASS'}, {'provider_exit_code':1},
                       {'trusted_control_sha':'c'*40}, {'expected_instance_name':'sprk-9-1-instance'}):
            with self.subTest(change=change):
                candidate = copy.deepcopy(doc); candidate.update(change)
                with self.assertRaises(contract.TransportError):
                    contract.admit(candidate, self.identity())

    def test_current_producer_argv_stdio_environment_are_preserved(self):
        with patch.object(observer.subprocess, 'Popen') as popen:
            observer.launch_apply()
        popen.assert_called_once_with(['tofu', 'apply', '--auto-approve', '--input=false'])

    def test_workflow_cli_delimiter_preserves_exact_apply(self):
        args=['observer','--output','/unused/transport.json']
        for name,value in self.identity().items(): args.extend(['--'+name.replace('_','-'),value])
        args.extend(['--','tofu','apply','--auto-approve','--input=false'])
        with patch.object(sys,'argv',args),patch.object(observer,'observe_apply',return_value=0) as apply:
            self.assertEqual(observer.main(),0)
            apply.assert_called_once()

    def test_schema_agreement(self):
        self.assertEqual(json.loads((ROOT/'schemas/instance-insert-transport-evidence.schema.json').read_text()), contract.schema())

    def test_exact_socket_counters_and_payload_exclusion(self):
        listener = socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
        client = socket.socket(); client.connect(listener.getsockname()); peer,_ = listener.accept()
        try:
            row = observer.socket_identity(client.fileno(), os.getpid())
            initial = observer.exact_query(row)
            self.assertEqual(initial['state'], 'ESTABLISHED')
            secret = b'Authorization: Bearer SYNTHETIC_SECRET\noauth-SYNTHETIC_SECRET\nBEGIN OPENSSH PRIVATE KEY\nstartup-script-SYNTHETIC_METADATA\nENV_SYNTHETIC_SECRET'
            client.sendall(secret); peer.settimeout(1); received=b''
            while len(received)<len(secret): received += peer.recv(len(secret)-len(received))
            after = observer.exact_query(row)
            self.assertEqual(after['bytes_sent']-initial['bytes_sent'],len(secret))
            self.assertEqual(after['bytes_received'], initial['bytes_received'])
            self.assertNotIn('SYNTHETIC',json.dumps(after))
            self.assertNotIn('Authorization',json.dumps(after))
        finally:
            client.close(); peer.close(); listener.close()


    def raw_connection(self):
        body = bytearray(72)
        body[0:2] = bytes((2,1))
        struct.pack_into('!HH',body,4,12345,443)
        body[8:12] = socket.inet_aton('127.0.0.1')
        body[24:28] = socket.inet_aton('127.0.0.2')
        struct.pack_into('=II',body,44,12,34)
        struct.pack_into('=I',body,68,123)
        info = bytearray(248); info[0]=1
        struct.pack_into('=QQ',info,200,10,0)
        return bytes(body)+struct.pack('=HH',252,2)+bytes(info)

    def connection_document(self):
        raw = contract.normalize_diag(self.raw_connection(),110)
        row = contract.new_connection(raw,1234,12,1)
        contract.add_sample(row,dict(raw['snapshot'],at=180,bytes_sent=20),'LIVE_SOCKET')
        return contract.assemble(self.identity(),100,200,'COMPLETE','OTHER',1,[row])

    def test_bounded_normalization_admission_and_unknowns(self):
        doc = self.connection_document()
        contract.admit(doc,self.identity())
        for field in ('http_request_attribution','secure_transport_progress','reset_origin'):
            self.assertEqual(doc['connections'][0][field],'UNKNOWN')
        for mutation in ('counter','time','activity','ip','state','cookie','extra','receipt','ordering','bounds','family'):
            with self.subTest(mutation=mutation):
                candidate=copy.deepcopy(doc); row=candidate['connections'][0]
                if mutation=='counter': row['last']['bytes_sent']=-1
                if mutation=='time': row['last']['at']=201
                if mutation=='activity': row['last_send_increase_sample']=None
                if mutation=='ip': row['remote_address']='Authorization: Bearer SYNTHETIC_SECRET'
                if mutation=='state': row['states_seen']=['SYN_SENT']
                if mutation=='cookie': candidate['connections'].append(copy.deepcopy(row))
                if mutation=='extra': row['payload']='BEGIN OPENSSH PRIVATE KEY'
                if mutation=='receipt': row['http_request_attribution']='FULL_HTTP_REQUEST_BODY_ACCEPTED_BY_GCP'
                if mutation=='ordering': row['ordinal']=2
                if mutation=='bounds': candidate['connections']*=65
                if mutation=='family': row['remote_address']='::1'
                with self.assertRaises(contract.TransportError): contract.admit(candidate,self.identity())
        for raw in (b'{}'*(contract.MAX_DOCUMENT_BYTES+1),b'{"a":1,"a":2}',b'['*2000):
            with self.assertRaises(contract.TransportError): contract.decode_document(raw)
        for raw in (b'',self.raw_connection()[:90],self.raw_connection()+b'x',self.raw_connection()*100):
            with self.assertRaises(contract.TransportError): contract.normalize_diag(raw,100)

    def test_profile_and_provider_identity_agree_with_existing_owners(self):
        control_spec=importlib.util.spec_from_file_location('rocky_control',ROOT/'scripts/ci-cloud/rocky-control.py')
        control=importlib.util.module_from_spec(control_spec); control_spec.loader.exec_module(control)
        janitor_spec=importlib.util.spec_from_file_location('rocky_janitor',ROOT/'scripts/ci-cloud/gcp-rocky-janitor.py')
        janitor=importlib.util.module_from_spec(janitor_spec); sys.modules[janitor_spec.name]=janitor; janitor_spec.loader.exec_module(janitor)
        fields=contract.schema()['properties']
        self.assertEqual(set(fields['provider_profile']['enum']),set(control.PROFILE_PATHS))
        self.assertEqual(set(fields['provider_profile']['enum']),janitor.PROFILES)
        self.assertEqual(fields['project']['const'],janitor.PROJECT)
        self.assertEqual(fields['zone']['const'],janitor.ZONE)
        for value in ('12345','0','-1','1'*21,'SYNTHETIC_SECRET'):
            candidate=self.identity(); candidate['workflow_run_id']=value
            candidate['expected_instance_name']=f'sprk-{value}-1-instance'
            doc=contract.assemble(candidate,0,0,'UNAVAILABLE','NOT_RUN',None,[])
            accepted=True
            try: contract.admit(doc,candidate)
            except contract.TransportError: accepted=False
            self.assertEqual(accepted,bool(control.RUN_ID.fullmatch(value)))
            self.assertEqual(accepted,bool(janitor.RUN_ID.fullmatch(value)))

    def test_diagnostic_admission_and_retention_failure_stop_continuation(self):
        workflow=yaml.safe_load((ROOT/'.github/workflows/rocky-cloud-qualification.yml').read_text())
        provision=workflow['jobs']['provision']; ids={step['id']:step for step in provision['steps'] if 'id' in step}
        transition=ids['identity_transition']['if']
        self.assertIn("steps.apply.outcome == 'success'",transition)
        self.assertIn("steps.transport_admission.outcome == 'success'",transition)
        self.assertIn("steps.transport_publication.outcome == 'success'",transition)
        self.assertIn("needs.provision.result == 'failure'",workflow['jobs']['cleanup']['if'])
        self.assertIn('always()',workflow['jobs']['cleanup']['if'])

    def test_missing_destroy_notification_does_not_prove_socket_disappearance(self):
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
        client=socket.socket(); client.connect(listener.getsockname()); peer,_=listener.accept()
        try:
            collect=observer.Observer(os.getpid(),{Path(sys.executable).resolve()},ports=(listener.getsockname()[1],))
            collect.prepare(); collect.sample()
            _,rows=collect.finish()
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['final_snapshot_kind'],'NO_DESTROY_NOTIFICATION_OBSERVED')
            # Independent liveness proves a missing event cannot imply disappearance.
            self.assertEqual(observer.exact_query(observer.socket_identity(client.fileno(),os.getpid()))['state'],'ESTABLISHED')
        finally:
            client.close(); peer.close(); listener.close()

    def test_retransmission_and_preconnection_representation_preserve_limits(self):
        body=bytearray(self.raw_connection()); body[1]=2; body[76]=2
        struct.pack_into('=Q',body,276,0)
        struct.pack_into('=I',body,176,3)
        normalized=contract.normalize_diag(bytes(body),110)
        row=contract.new_connection(normalized,1234,12,1)
        self.assertEqual(row['first']['state'],'SYN_SENT')
        self.assertEqual(row['first']['retransmissions'],3)
        doc=contract.assemble(self.identity(),100,200,'COMPLETE','OTHER',1,[row])
        contract.admit(doc,self.identity())
        self.assertEqual(doc['connection_progress'],'SYN_SENT_OBSERVED')
        self.assertEqual(row['secure_transport_progress'],'UNKNOWN')
        self.assertEqual(row['reset_origin'],'UNKNOWN')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'result.json'
            with patch.object(Path,'replace',side_effect=OSError('ENV_SYNTHETIC_SECRET')):
                with self.assertRaises(OSError): observer.persist(path,doc,self.identity())
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_live_gates_reject_authority_payload_and_producer_mutations(self):
        architecture_spec=importlib.util.spec_from_file_location('transport_architecture',ROOT/'scripts/validate-rocky-evidence-architecture.py')
        architecture=importlib.util.module_from_spec(architecture_spec); architecture_spec.loader.exec_module(architecture)
        cloud_spec=importlib.util.spec_from_file_location('transport_cloud',ROOT/'scripts/validate-ci-cloud.py')
        cloud=importlib.util.module_from_spec(cloud_spec); cloud_spec.loader.exec_module(cloud)
        mutations=(('scripts/ci-cloud/instance_transport_contract.py','import json','import os'),
                   ('scripts/ci-cloud/observe-instance-transport.py','set_cookie_filter(self.listener,[])','pass'),
                   ('scripts/ci-cloud/observe-instance-transport.py',"['tofu','apply','--auto-approve','--input=false']","['tofu','apply','--auto-approve','--input=false','--parallelism=1']"),
                   ('.github/workflows/rocky-cloud-qualification.yml','.commit.commit.verification.verified','.commit.commit.message'))
        for relative,old,new in mutations:
            with self.subTest(relative=relative,old=old),tempfile.TemporaryDirectory() as directory:
                temporary=Path(directory)
                for path in ('scripts/ci-cloud/instance_transport_contract.py','scripts/ci-cloud/observe-instance-transport.py','schemas/instance-insert-transport-evidence.schema.json','.github/workflows/rocky-cloud-qualification.yml'):
                    target=temporary/path; target.parent.mkdir(parents=True,exist_ok=True); target.write_text((ROOT/path).read_text())
                target=temporary/relative; source=target.read_text(); self.assertIn(old,source); target.write_text(source.replace(old,new,1))
                if relative.startswith('.github'):
                    with self.assertRaises(cloud.ContractError): cloud.validate_instance_transport_workflow(temporary)
                else:
                    with patch.object(architecture,'ROOT',temporary):
                        with self.assertRaises(architecture.ArchitectureError): architecture.validate_instance_transport_architecture()

    def test_refused_socket_never_becomes_no_tcp_or_dns_failure(self):
        reserve=socket.socket(); reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]; reserve.close()
        client=socket.socket(); client.bind(('127.0.0.1',0))
        try:
            row={'family':socket.AF_INET,'local_address':'127.0.0.1','remote_address':'127.0.0.1',
                 'local_port':client.getsockname()[1],'remote_port':port,'inode':0}
            self.assertNotEqual(client.connect_ex(('127.0.0.1',port)),0)
            self.assertIsNone(observer.exact_query(row))
            doc=contract.assemble(self.identity(),0,1,'UNAVAILABLE','OTHER',1,[])
            contract.admit(doc,self.identity())
            self.assertEqual(doc['endpoint_observation'],'UNKNOWN')
            self.assertEqual(doc['connection_progress'],'UNKNOWN')
            self.assertEqual(doc['dns_completion'],'UNKNOWN')
        finally: client.close()

    def test_collector_failure_does_not_terminate_or_capture_producer(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'result.json'
            with patch.object(observer.Observer,'prepare',side_effect=OSError('Authorization: Bearer SYNTHETIC_SECRET')), patch.object(observer,'launch_apply') as launch:
                self.assertEqual(observer.observe_apply(self.identity(),output),1)
                launch.assert_not_called()
            doc=contract.decode_document(output.read_bytes()); contract.admit(doc,self.identity())
            self.assertEqual(doc['collection_status'],'FAILED_STARTUP')
            self.assertEqual(doc['terminal_provider_result'],'NOT_RUN')
            self.assertNotIn('SYNTHETIC',output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            self.assertEqual(list(Path(directory).iterdir()),[output])
        instance=observer.Observer(os.getpid(),set())
        with patch.object(instance,'sample',side_effect=RuntimeError('ENV_SYNTHETIC_SECRET')):
            instance.run()
        self.assertEqual(instance.status,'FAILED_RUNTIME')
        instance=observer.Observer(os.getpid(),set()); instance.thread=MagicMock(); instance.thread.is_alive.return_value=True
        instance.listener=MagicMock()
        instance.finish()
        self.assertEqual(instance.status,'FAILED_SHUTDOWN'); instance.listener.close.assert_called_once()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'result.json'; producer=MagicMock(); producer.wait.return_value=1
            def fail_during_apply(*args):
                time.sleep(0.05)
                raise RuntimeError('oauth-SYNTHETIC_SECRET')
            producer.wait.side_effect=lambda: (time.sleep(0.1),1)[1]
            with patch.object(observer,'launch_apply',return_value=producer), patch.object(observer.Observer,'sample',side_effect=fail_during_apply):
                self.assertEqual(observer.observe_apply(self.identity(),output),1)
            producer.terminate.assert_not_called(); producer.kill.assert_not_called()
            doc=contract.decode_document(output.read_bytes()); contract.admit(doc,self.identity())
            self.assertEqual(doc['terminal_provider_result'],'OTHER')
            self.assertEqual(doc['provider_exit_code'],1)

    def test_normalizer_purity(self):
        # These surfaces must consume supplied values, never reach back into a system.
        with (patch('builtins.open',side_effect=AssertionError('filesystem capability')),
              patch.object(socket,'socket',side_effect=AssertionError('network capability')),
              patch.object(time,'monotonic_ns',side_effect=AssertionError('clock capability'))):
            doc=self.connection_document()
            contract.admit(doc,self.identity())

    def test_filtered_destruction_process_scope_and_multiple_connections(self):
        code=r"""import socket,sys
c=None
for command in sys.stdin:
 command=command.strip()
 if command=='CONNECT':
  c=socket.socket(); c.connect(('127.0.0.1',int(sys.argv[1]))); print('CONNECTED',flush=True)
 elif command=='SEND':
  c.sendall(b'Authorization: Bearer SYNTHETIC_SECRET\nBEGIN OPENSSH PRIVATE KEY\noauth-SYNTHETIC_SECRET\nstartup-script-SYNTHETIC_METADATA\nENV_SYNTHETIC_SECRET'); print('SENT',flush=True)
 elif command=='SHUTDOWN':
  c.shutdown(socket.SHUT_WR); print('SHUTDOWN',flush=True)
 elif command=='CLOSE':
  c.close(); print('CLOSED',flush=True)
 elif command=='EXIT': break
"""
        def wait_for(predicate):
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                if predicate(): return
                time.sleep(0.02)
            self.fail('bounded observation did not arrive')
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(4); listener.settimeout(2)
        with contextlib.ExitStack() as stack:
            stack.callback(listener.close)
            relevant=subprocess.Popen([sys.executable,'-c',code,str(listener.getsockname()[1])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env={'TRANSPORT_TEST_SECRET':'ENV_SYNTHETIC_SECRET_VALUE'})
            unrelated=subprocess.Popen([sys.executable,'-c',code,str(listener.getsockname()[1])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            for process in (relevant,unrelated):
                stack.callback(process.stdout.close); stack.callback(process.stdin.close)
                stack.callback(lambda p=process: p.wait(timeout=2))
                stack.callback(lambda p=process: (p.stdin.write('EXIT\n'),p.stdin.flush()) if p.poll() is None else None)
            def command(process,value):
                process.stdin.write(value+'\n'); process.stdin.flush()
                self.assertEqual(process.stdout.readline().strip(),{'CONNECT':'CONNECTED','SEND':'SENT','SHUTDOWN':'SHUTDOWN','CLOSE':'CLOSED'}[value])
            collect=observer.Observer(relevant.pid,{Path(sys.executable).resolve()},ports=(listener.getsockname()[1],))
            collect.prepare(); collect.start_thread(); stack.callback(collect.finish)
            command(relevant,'CONNECT'); peer,_=listener.accept(); stack.callback(peer.close)
            wait_for(lambda:len(collect.connections)==1)
            first=next(iter(collect.connections.values()))
            command(unrelated,'CONNECT'); other,_=listener.accept(); stack.callback(other.close)
            command(unrelated,'SEND'); other.recv(4096)
            other.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); other.close(); command(unrelated,'CLOSE')
            time.sleep(0.25)
            self.assertEqual(len(collect.connections),1)
            command(relevant,'SEND'); peer.recv(4096)
            wait_for(lambda:first['last']['bytes_sent']>first['first']['bytes_sent'])
            self.assertEqual(first['last']['bytes_received'],first['first']['bytes_received'])
            peer.sendall(b'partial local bytes without parsed headers')
            wait_for(lambda:first['last']['bytes_received']>first['first']['bytes_received'])
            peer.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); peer.close(); command(relevant,'CLOSE')
            wait_for(lambda:first['final_snapshot_kind']=='DESTROY_NOTIFICATION')
            self.assertEqual(first['reset_origin'],'UNKNOWN')
            command(relevant,'CONNECT'); next_peer,_=listener.accept(); stack.callback(next_peer.close)
            wait_for(lambda:len(collect.connections)==2)
            second=list(collect.connections.values())[1]
            command(relevant,'SHUTDOWN')
            wait_for(lambda:second['fin_observation']=='LOCAL_FIN_OBSERVED')
            next_peer.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); next_peer.close(); command(relevant,'CLOSE')
            wait_for(lambda:second['final_snapshot_kind']=='DESTROY_NOTIFICATION')
            end,rows=collect.finish()
            self.assertEqual(collect.status,'COMPLETE')
            self.assertEqual(len(rows),2)
            self.assertEqual({row['process_id'] for row in rows},{relevant.pid})
            self.assertEqual(len({row['socket_cookie'] for row in rows}),2)
            self.assertNotIn('SYNTHETIC',json.dumps(rows))
            self.assertNotIn('Authorization',json.dumps(rows))
            for marker in ('Bearer','Authorization:','oauth','BEGIN OPENSSH PRIVATE KEY','startup-script-SYNTHETIC_METADATA','ENV_SYNTHETIC_SECRET_VALUE'):
                self.assertNotIn(marker,json.dumps(rows))


if __name__ == '__main__':
    unittest.main()
