#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence: local destroy is insufficient after an ambiguous insert."""

from __future__ import annotations

import copy
import datetime
import http.server
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('rocky_cleanup', ROOT / 'scripts/ci-cloud/gcp-rocky-janitor.py')
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


class AmbiguousInsertTests(unittest.TestCase):
    def test_empty_local_state_cannot_claim_provider_cleanup(self):
        # The provider created the instance but the insert response never reached
        # OpenTofu's SetId. All six supporting resources are in retained state.
        provider = {c for c in M.DELETE_ORDER}
        retained = json.loads((ROOT/'tests/fixtures/rocky-ambiguous-instance-insert.json').read_text())['runs']
        expected_types = {'google_compute_disk','google_compute_firewall','google_compute_network','google_compute_subnetwork'}
        for run in retained:
            self.assertEqual(run['outcome'],'AMBIGUOUS_INSTANCE_INSERT_TIMEOUT')
            self.assertEqual({r['type'] for r in run['retained_resources']},expected_types)
            self.assertEqual(len(run['retained_resources']),6)
        state = {r['provider_id'] for r in retained[0]['retained_resources']}
        workflow = yaml.safe_load((ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text())
        command = next(s['run'] for s in workflow['jobs']['cleanup']['steps'] if s['name'] == 'Destroy exact state and prove it empty')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            adapter = path / 'tofu'
            adapter.write_text('#!/usr/bin/env python3\nimport json,sys,pathlib\np=pathlib.Path("state.json")\nif sys.argv[1]=="destroy": p.write_text("[]")\nelif sys.argv[1:]==["state","list"]: print("\\n".join(json.loads(p.read_text())),end="")\nelse: sys.exit(2)\n')
            adapter.chmod(0o700)
            (path / 'state.json').write_text(json.dumps(sorted(state)))
            completed = subprocess.run(['bash','-euo','pipefail','-c',command],cwd=path,env={**os.environ,'PATH':str(path)+os.pathsep+os.environ['PATH']},capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            state = set(json.loads((path / 'state.json').read_text()))
            provider.difference_update(M.DELETE_ORDER[1:])
            self.assertEqual(state,set())
            # Accepted baseline says success, yet the provider still has an
            # unrecorded instance. The corrective workflow must add independent
            # inventory admission before it can produce total-cleanup success.
            self.assertEqual(provider,{'instance'})
            client = ProviderAdapter(provider)
            authority = M.exact_authority(VARIABLES,ENV,1800000200)
            self.assertFalse(M.verify_run_absence(client,authority), 'false CLEANUP_PASS: local state empty while provider instance remains')
            M.cleanup_run(client,authority)
            self.assertTrue(M.verify_run_absence(client,authority))


LABELS = {
    'secpal_ci_owner': 'rocky-host-qualification',
    'repository': 'secpal-deployment',
    'github_run_id': '12345', 'github_run_attempt': '1',
    'target_sha': 'a'*40, 'control_sha': 'b'*40,
    'provider_profile': 'gcp-rocky-10-2-arm64',
    'created_at': '1800000000', 'expires_at': '1800010800',
}
ENV = {
    'GITHUB_REPOSITORY': 'SecPal/deployment', 'GITHUB_REF': 'refs/heads/main',
    'GITHUB_SHA': 'b'*40, 'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1',
    'TARGET_SHA': 'a'*40, 'PROVIDER_PROFILE': LABELS['provider_profile'],
}
VARIABLES = {
    'project_id': M.PROJECT, 'zone': M.ZONE, 'run_id': '12345', 'run_attempt': '1',
    'target_sha': 'a'*40, 'trusted_control_sha': 'b'*40,
    'profile': LABELS['provider_profile'], 'created_at': LABELS['created_at'],
    'expires_at': LABELS['expires_at'],
}


def resource(component):
    name = f'sprk-12345-1-{component}'
    item = {
        'kind': {'instance':'compute#instance','disk':'compute#disk','network':'compute#network','subnet':'compute#subnetwork'}.get(component,'compute#firewall'),
        'id': '987654321', 'name': name,
        'selfLink': f'https://www.googleapis.com/compute/v1/projects/{M.PROJECT}/{M.SCOPES[component]}/{name}',
        'creationTimestamp': datetime.datetime.fromtimestamp(1800000001,datetime.timezone.utc).isoformat(),
    }
    if component in {'instance','disk'}:
        item['labels'] = dict(LABELS)
        item['zone'] = f'https://www.googleapis.com/compute/v1/projects/{M.PROJECT}/zones/{M.ZONE}'
    if component != 'disk':
        item['description'] = json.dumps(dict(zip(['o','r','i','a','t','c','p','n','x'],LABELS.values())))
    return item


class ProviderAdapter:
    def __init__(self, components):
        self.resources = {c:resource(c) for c in components}
        self.reads = []
        self.deleted = []
        self.read_error = None
        self.delete_error = None
        self.disappear = False
    def get_component(self,component,name):
        self.reads.append((component,name))
        if self.read_error:
            raise M.JanitorError(self.read_error)
        if self.disappear and self.reads.count((component,name)) > 1:
            self.resources.pop(component,None)
        return copy.deepcopy(self.resources.get(component))
    def delete_component(self,component,name,resource_id):
        if self.delete_error:
            raise M.JanitorError(self.delete_error)
        actual = self.resources.pop(component,None)
        self.deleted.append((component,name))
        # Model the documented name-addressed provider mutation faithfully:
        # targetId admission detects a race after dispatch, not before it.
        M.validate_delete_operation({'kind':'compute#operation','operationType':'delete','targetLink':actual['selfLink'],'targetId':actual['id']},component,name,resource_id)
    def list_component(self,*args):
        raise AssertionError('broad inventory forbidden')


class ExactCleanupTests(unittest.TestCase):
    def authority(self, variables=None, env=None):
        return M.exact_authority(VARIABLES if variables is None else variables,ENV if env is None else env,1800000200)

    def test_ambiguous_create_and_local_empty_provider_present(self):
        for components in [[], ['instance'], list(M.DELETE_ORDER)]:
            with self.subTest(components=components):
                client = ProviderAdapter(components)
                authority = self.authority()
                outcome = M.reconcile_instance(client,authority)
                self.assertEqual(outcome, 'EXACT_RUN_OWNED_INSTANCE_PRESENT' if 'instance' in components else 'ABSENT')
                # Destroy removes only state entries; a provider-created instance
                # never reached SetId and survives ordinary state destruction.
                for c in M.DELETE_ORDER[1:]:
                    client.resources.pop(c,None)
                self.assertEqual(M.verify_run_absence(client,authority),not components)
                M.cleanup_run(client,authority)
                self.assertTrue(M.verify_run_absence(client,authority))
                self.assertEqual(client.resources,{})
                self.assertEqual(client.deleted, [('instance','sprk-12345-1-instance')] if components else [])
                self.assertEqual({c for c,n in client.reads},set(M.DELETE_ORDER))

    def test_all_families_are_independently_verified_and_deleted(self):
        client = ProviderAdapter(M.DELETE_ORDER)
        M.cleanup_run(client,self.authority())
        self.assertEqual([c for c,n in client.deleted],list(M.DELETE_ORDER))
        self.assertTrue(M.verify_run_absence(client,self.authority()))

    def test_wrong_ownership_never_deletes_even_with_matching_name(self):
        for component in M.DELETE_ORDER:
            for field in LABELS:
                client = ProviderAdapter([component])
                item = client.resources[component]
                if component in {'instance','disk'}:
                    item['labels'][field] = 'wrong-secret-body'
                else:
                    keys = dict(zip(LABELS,['o','r','i','a','t','c','p','n','x']))
                    desc = json.loads(item['description'])
                    desc[keys[field]] = 'wrong-secret-body'
                    item['description'] = json.dumps(desc)
                with self.subTest(component=component,field=field):
                    with self.assertRaises(M.JanitorError):
                        M.cleanup_run(client,self.authority())
                    self.assertEqual(client.deleted,[])
                    self.assertFalse(M.verify_run_absence(client,self.authority()))

    def test_wrong_immutable_identity_and_description(self):
        for key,value in [('selfLink',resource('instance')['selfLink'].replace(M.PROJECT,'other-project')),('zone','wrong-zone'),('id',''),('creationTimestamp','2020-01-01T00:00:00Z'),('description','{}'),('kind','compute#disk')]:
            client = ProviderAdapter(['instance'])
            client.resources['instance'][key] = value
            with self.subTest(key=key):
                self.assertEqual(M.reconcile_instance(client,self.authority()),'INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE')
                with self.assertRaises(M.JanitorError): M.cleanup_run(client,self.authority())
                self.assertEqual(client.deleted,[])

    def test_unknown_get_and_delete_fail_closed_without_secret_diagnostics(self):
        client = ProviderAdapter(['instance'])
        client.read_error = 'access-token-private-provider-body'
        self.assertEqual(M.reconcile_instance(client,self.authority()),'UNKNOWN_PROVIDER_STATE')
        self.assertFalse(M.verify_run_absence(client,self.authority()))
        with self.assertRaises(M.JanitorError) as raised: M.cleanup_run(client,self.authority())
        self.assertNotIn(client.read_error,str(raised.exception))
        self.assertEqual(client.deleted,[])
        client.read_error = None
        client.delete_error = 'private-delete-timeout'
        with self.assertRaises(M.JanitorError) as raised: M.cleanup_run(client,self.authority())
        self.assertNotIn(client.delete_error,str(raised.exception))
        self.assertFalse(M.verify_run_absence(client,self.authority()))

    def test_concurrent_disappearance(self):
        client = ProviderAdapter(['instance'])
        client.disappear = True
        M.cleanup_run(client,self.authority())
        self.assertTrue(M.verify_run_absence(client,self.authority()))
        self.assertEqual(client.deleted,[])

    def test_candidate_and_replay_authority_refused(self):
        for key in ['project_id','zone','run_id','run_attempt','target_sha','trusted_control_sha','profile','created_at','expires_at']:
            variables = dict(VARIABLES)
            variables[key] = 'wrong'
            with self.subTest(key=key):
                with self.assertRaises(M.JanitorError): self.authority(variables)
        for key in ['GITHUB_REPOSITORY','GITHUB_REF','GITHUB_SHA','TARGET_SHA','PROVIDER_PROFILE','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT']:
            env = dict(ENV)
            env[key] = 'wrong'
            with self.subTest(env=key):
                with self.assertRaises(M.JanitorError): self.authority(env=env)
        variables = dict(VARIABLES,expires_at='1800010801')
        with self.assertRaises(M.JanitorError): self.authority(variables)


class ProviderHTTPTests(unittest.TestCase):
    def test_real_http_exact_404_and_owned_json_are_distinct_from_unknown(self):
        fixture = {'status':404,'body':b'', 'paths':[]}
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                fixture['paths'].append(self.path)
                self.send_response(fixture['status'])
                self.end_headers()
                self.wfile.write(fixture['body'])
            def log_message(self,*args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            with patch.object(M,'API_ROOT',f'http://127.0.0.1:{server.server_port}'):
                client = M.GCPClient('non-secret-test-token')
                authority = M.exact_authority(VARIABLES,ENV,1800000200)
                for status,body,expected in [
                    (404,b'','ABSENT'),
                    (200,json.dumps(resource('instance')).encode(),'EXACT_RUN_OWNED_INSTANCE_PRESENT'),
                    (200,b'{}','INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE'),
                    (200,b'','INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE'),
                    (200,b'{"name":"one","name":"two"}','UNKNOWN_PROVIDER_STATE'),
                    (200,b'not-json-secret','UNKNOWN_PROVIDER_STATE'),
                    (403,b'private-response','UNKNOWN_PROVIDER_STATE'),
                    (503,b'private-response','UNKNOWN_PROVIDER_STATE'),
                ]:
                    fixture.update(status=status,body=body)
                    with self.subTest(status=status,body=body):
                        self.assertEqual(M.reconcile_instance(client,authority),expected)
                self.assertEqual(set(fixture['paths']),{'/projects/secpal-dev/zones/europe-west3-a/instances/sprk-12345-1-instance'})
                with patch.object(M.urllib.request,'urlopen',side_effect=TimeoutError('private-token')):
                    self.assertEqual(M.reconcile_instance(client,authority),'UNKNOWN_PROVIDER_STATE')
                with self.assertRaises(M.JanitorError): client.get_component('instance','arbitrary-name')
                with self.assertRaises(M.JanitorError): client.delete_component('arbitrary-kind','sprk-12345-1-instance','987654321')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_closed_diagnostics_and_cli_cannot_authorize_ambiguous_success(self):
        import contextlib
        import io
        from jsonschema import Draft202012Validator
        authority = M.exact_authority(VARIABLES,ENV,1800000200)
        schema = json.loads((ROOT/'schemas/rocky-cloud-provider-result.schema.json').read_text())
        for outcome in ['ABSENT','EXACT_RUN_OWNED_INSTANCE_PRESENT','INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE','UNKNOWN_PROVIDER_STATE']:
            document = M.diagnostic(authority,'ambiguous-create-read-back','instance',outcome)
            self.assertTrue(Draft202012Validator(schema).is_valid(document))
            document['credentials'] = 'secret'
            self.assertFalse(Draft202012Validator(schema).is_valid(document))
        with tempfile.TemporaryDirectory() as directory:
            variables = Path(directory)/'variables.json'
            variables.write_text(json.dumps(VARIABLES))
            for components in [[],['instance']]:
                stream = io.StringIO()
                arguments = ['janitor','--project',M.PROJECT,'--region',M.REGION,'--zone',M.ZONE,'--now','1800000200','--exact-action','reconcile','--variables',str(variables)]
                with patch.dict(os.environ,ENV,clear=True), patch.object(sys,'argv',arguments), patch.object(M,'GCPClient',return_value=ProviderAdapter(components)),contextlib.redirect_stdout(stream):
                    self.assertEqual(M.main(),1)
                document = json.loads(stream.getvalue())
                self.assertTrue(Draft202012Validator(schema).is_valid(document))
                self.assertNotIn('candidate',stream.getvalue())
                self.assertNotIn('token',stream.getvalue())

    def test_replacement_between_reads_refuses_delete(self):
        client = ProviderAdapter(['instance'])
        original = client.get_component
        def replacement(component,name):
            item = original(component,name)
            if len(client.reads)>len(M.DELETE_ORDER) and item:
                item['id'] = '777'
            return item
        client.get_component = replacement
        with self.assertRaises(M.JanitorError):
            M.cleanup_run(client,M.exact_authority(VARIABLES,ENV,1800000200))
        self.assertEqual(client.deleted,[])


class DeleteIntegrityTests(unittest.TestCase):
    def test_delete_operation_bound_to_admitted_incarnation(self):
        client = M.GCPClient('non-secret-test-token')
        component = 'instance'
        name = 'sprk-12345-1-instance'
        expected_id = '987654321'
        operation = {
            'kind':'compute#operation', 'name':'operation-12345',
            'operationType':'delete', 'targetId':expected_id,
            'targetLink':resource(component)['selfLink'], 'status':'DONE',
        }
        for key,bad in [('targetId','777'),('targetLink',resource(component)['selfLink'].replace('secpal-dev','other-project')),('operationType','insert'),('kind','compute#instance'),('name',''),('status','UNKNOWN')]:
            changed = dict(operation)
            changed[key] = bad
            with self.subTest(key=key),patch.object(client,'request',return_value=changed):
                with self.assertRaises(M.JanitorError):
                    client.delete_component(component,name,expected_id)
        with patch.object(client,'request',return_value=operation):
            client.delete_component(component,name,expected_id)
        with patch.object(client,'request',return_value=dict(operation,status='RUNNING')) as request,patch.object(M.time,'monotonic',side_effect=[0,121]):
            with self.assertRaises(M.JanitorError): client.delete_component(component,name,expected_id)
            self.assertEqual(request.call_count,1)


    def test_replacement_after_final_get_cannot_produce_cleanup_success(self):
        client = ProviderAdapter(['instance'])
        original_delete = client.delete_component
        def replacement(component,name,resource_id):
            client.resources[component]['id'] = '777'
            client.resources[component]['labels'] = {'foreign':'true'}
            original_delete(component,name,resource_id)
        client.delete_component = replacement
        with self.assertRaises(M.JanitorError):
            M.cleanup_run(client,M.exact_authority(VARIABLES,ENV,1800000200))

    def test_cleanup_mutation_is_serialized_by_original_run(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/rocky-cloud-qualification.yml').read_text())
        self.assertEqual(workflow['concurrency'],{'group':'rocky-cloud-${{ inputs.continuation_run_id || github.run_id }}','cancel-in-progress':False})


class DeadlineBudgetTests(unittest.TestCase):
    def test_exact_client_budget_clips_requests_and_never_admits_late_absence(self):
        clock = [0.0]
        timeouts = []
        def absent(request, timeout):
            timeouts.append(timeout)
            clock[0] += timeout
            raise urllib.error.HTTPError(request.full_url,404,'absent',{},None)
        with patch.object(M.time,'monotonic',side_effect=lambda:clock[0]),patch.object(M.urllib.request,'urlopen',side_effect=absent):
            client = M.GCPClient('non-secret-test-token',deadline=35.0)
            authority = M.exact_authority(VARIABLES,ENV,1800000200)
            self.assertEqual(M.reconcile_instance(client,authority),'ABSENT')
            self.assertEqual(M.reconcile_instance(client,authority),'UNKNOWN_PROVIDER_STATE')
            self.assertEqual(M.reconcile_instance(client,authority),'UNKNOWN_PROVIDER_STATE')
            self.assertEqual(timeouts,[30.0,5.0])

    def test_cleanup_credential_covers_the_entire_existing_job(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/rocky-cloud-qualification.yml').read_text())
        cleanup = workflow['jobs']['cleanup']
        auth = next(s for s in cleanup['steps'] if s.get('id')=='cleanup_auth')
        self.assertGreaterEqual(int(auth['with']['access_token_lifetime'].removesuffix('s')),60*cleanup['timeout-minutes'])
        self.assertEqual(cleanup['permissions']['id-token'],'write')

    def test_completed_delete_needs_no_extra_operation_poll(self):
        client = M.GCPClient('non-secret-test-token')
        item = resource('instance')
        operation = {'kind':'compute#operation','operationType':'delete','name':'operation-1','targetLink':item['selfLink'],'targetId':item['id'],'status':'DONE'}
        with patch.object(client,'request',return_value=operation) as request:
            client.delete_component('instance',item['name'],item['id'])
            self.assertEqual(request.call_count,1)

    def test_cleanup_has_one_final_absence_snapshot(self):
        client = ProviderAdapter(M.DELETE_ORDER)
        result = M.cleanup_run(client,M.exact_authority(VARIABLES,ENV,1800000200))
        self.assertEqual(result,{c:'ABSENT' for c in M.DELETE_ORDER})
        self.assertEqual(len(client.reads),3*len(M.DELETE_ORDER))


if __name__ == '__main__':
    unittest.main()
