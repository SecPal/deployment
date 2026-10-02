#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fixed deployment#81 source resolver; run only from accepted protected main."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

from jsonschema.exceptions import ValidationError

import postgresql_qualification_contract as contract

ROOT = Path(__file__).resolve().parents[2]
PROBE_PATHS = (
    'scripts/ci-cloud/postgresql_qualification_contract.py',
    'scripts/ci-cloud/postgresql-qualification-control.py',
    'scripts/ci-cloud/qualify-native-postgresql.py',
    'scripts/ci-cloud/run-native-postgresql-qualification.sh',
    'scripts/ci-cloud/rocky_preparation_contract.py',
    'scripts/ci-cloud/collect-rocky-preparation.py',
    'scripts/integration_runtime_contract.py',
    'scripts/render-native-postgresql.py',
    'schemas/postgresql-qualification-evidence.schema.json',
    'schemas/postgresql-qualification-diagnostic.schema.json',
)
QUERY = '''query PostgreSQLCandidate {
  repository(owner:"SecPal", name:"deployment") {
    nameWithOwner defaultBranchRef { name }
    pullRequests(first:100, states:OPEN) {
      totalCount pageInfo { hasNextPage }
      nodes {
        number state isDraft body headRefOid baseRefName
        headRepository { nameWithOwner } repository { nameWithOwner }
        commits { totalCount }
        closingIssuesReferences(first:100) {
          totalCount pageInfo { hasNextPage }
          nodes { number repository { nameWithOwner } }
        }
        timelineItems(first:100, itemTypes:[READY_FOR_REVIEW_EVENT,CONVERT_TO_DRAFT_EVENT]) {
          totalCount pageInfo { hasNextPage } nodes { __typename }
        }
      }
    }
  }
}'''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise contract.QualificationError('resolve-candidate', 'identity-mismatch')


class GitHubObserver:
    """Bounded provider representations, with no caller-selected repository/URL."""
    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect)
        self.calls = 0

    def request(self, path: str, document: dict | None = None) -> object:
        self.calls += 1
        if self.calls > 40 or not (path == '/graphql' or path.startswith('/repos/SecPal/deployment/')):
            raise contract.QualificationError('resolve-candidate', 'observation-limit-exceeded')
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not token:
            raise contract.QualificationError('resolve-candidate', 'identity-mismatch')
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'SecPal-PostgreSQL-Qualification'}
        payload = None if document is None else contract.canonical_bytes(document)
        request = urllib.request.Request('https://api.github.com' + path, data=payload, headers=headers)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(4194305)
                if response.status != 200 or len(raw) > 4194304:
                    raise contract.QualificationError('resolve-candidate', 'observation-limit-exceeded')
            return json.loads(raw, object_pairs_hook=contract.duplicate_keys)
        except (OSError, ValueError, urllib.error.HTTPError):
            raise contract.QualificationError('resolve-candidate', 'command-failed') from None

    @staticmethod
    def connection(document: dict) -> list:
        nodes = document['nodes']
        if (not isinstance(nodes, list) or document['pageInfo']['hasNextPage'] is not False
                or type(document['totalCount']) is not int or document['totalCount'] != len(nodes)):
            raise contract.QualificationError('resolve-candidate', 'observation-limit-exceeded')
        return nodes

    def candidate(self) -> dict:
        result = self.request('/graphql', {'query': QUERY})
        if not isinstance(result, dict) or result.get('errors'):
            raise contract.QualificationError('resolve-candidate', 'representation-invalid')
        repository = result['data']['repository']
        if repository['nameWithOwner'] != 'SecPal/deployment' or repository['defaultBranchRef']['name'] != 'main':
            raise contract.QualificationError('resolve-candidate', 'identity-mismatch')
        pulls = []
        for pull in self.connection(repository['pullRequests']):
            closing = [f"{issue['repository']['nameWithOwner']}#{issue['number']}"
                       for issue in self.connection(pull['closingIssuesReferences'])]
            events = self.connection(pull['timelineItems'])
            commits = []
            if 'SecPal/deployment#81' in closing:
                total = pull['commits']['totalCount']
                if type(total) is not int or not 1 <= total <= 300:
                    raise contract.QualificationError('resolve-candidate', 'observation-limit-exceeded')
                for page in range(1, (total + 99) // 100 + 1):
                    observations = self.request(f"/repos/SecPal/deployment/pulls/{pull['number']}/commits?per_page=100&page={page}")
                    if not isinstance(observations, list) or len(observations) > 100:
                        raise contract.QualificationError('resolve-candidate', 'representation-invalid')
                    commits.extend({'sha': item['sha'],
                                    'verified': item['commit']['verification']['verified'],
                                    'reason': item['commit']['verification']['reason']} for item in observations)
                if len(commits) != total:
                    raise contract.QualificationError('resolve-candidate', 'source-drift')
            pulls.append({
                'number': pull['number'], 'state': pull['state'], 'repository': pull['repository']['nameWithOwner'],
                'head_repository': None if pull['headRepository'] is None else pull['headRepository']['nameWithOwner'],
                'base': pull['baseRefName'], 'head': pull['headRefOid'], 'body': pull['body'],
                'closing_issues': closing, 'draft': pull['isDraft'],
                'ready_events': sum(event['__typename'] == 'ReadyForReviewEvent' for event in events),
                'draft_events': sum(event['__typename'] == 'ConvertToDraftEvent' for event in events),
                'commits': commits,
            })
        return contract.select_candidate(pulls)

    def fixed_blob(self, tree_sha: str, fixed_path: str) -> tuple[str, bytes]:
        if fixed_path not in (contract.CANDIDATE_PATH, contract.CONSUMER_PATH,
                              'scripts/ci-cloud/postgresql_qualification_contract.py',
                              'scripts/ci-cloud/rocky_preparation_contract.py'):
            raise contract.QualificationError('read-candidate-data', 'identity-mismatch')
        object_sha = tree_sha
        components = fixed_path.split('/')
        for index, component in enumerate(components):
            if not isinstance(object_sha, str) or contract.SHA.fullmatch(object_sha) is None:
                raise contract.QualificationError('read-candidate-data', 'representation-invalid')
            tree = self.request(f'/repos/SecPal/deployment/git/trees/{object_sha}')
            if tree['sha'] != object_sha or tree['truncated'] is not False or len(tree['tree']) > 10000:
                raise contract.QualificationError('read-candidate-data', 'representation-invalid')
            entries = [entry for entry in tree['tree'] if entry['path'] == component]
            last = index == len(components) - 1
            mode = ('100755' if fixed_path in (contract.CONSUMER_PATH,
                    'scripts/ci-cloud/rocky_preparation_contract.py') else '100644')
            if (len(entries) != 1 or entries[0]['type'] != ('blob' if last else 'tree')
                    or entries[0]['mode'] != (mode if last else '040000')):
                raise contract.QualificationError('read-candidate-data', 'identity-mismatch')
            object_sha = entries[0]['sha']
        blob = self.request(f'/repos/SecPal/deployment/git/blobs/{object_sha}')
        if blob['encoding'] != 'base64' or blob['sha'] != object_sha or not 0 < blob['size'] <= (8192 if fixed_path == contract.CANDIDATE_PATH else 262144):
            raise contract.QualificationError('read-candidate-data', 'representation-invalid')
        try:
            raw = base64.b64decode(''.join(blob['content'].splitlines()), validate=True)
            identity = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if len(raw) != blob['size'] or identity != object_sha:
                raise contract.QualificationError('read-candidate-data', 'identity-mismatch')
            return object_sha, raw
        except (ValueError, UnicodeError):
            raise contract.QualificationError('read-candidate-data', 'representation-invalid') from None

    def declaration(self, head: str) -> tuple[str, str, str, dict]:
        commit = self.request(f'/repos/SecPal/deployment/git/commits/{head}')
        if commit['sha'] != head:
            raise contract.QualificationError('read-candidate-data', 'identity-mismatch')
        tree = commit['tree']['sha']
        blob, raw = self.fixed_blob(tree, contract.CANDIDATE_PATH)
        consumer_blob, consumer = self.fixed_blob(tree, contract.CONSUMER_PATH)
        if consumer != (ROOT / contract.CONSUMER_PATH).read_bytes():
            raise contract.QualificationError('read-candidate-data', 'identity-mismatch')
        # Bind the complete executable import closure, not only its entrypoint.
        for fixed_path in ('scripts/ci-cloud/postgresql_qualification_contract.py',
                           'scripts/ci-cloud/rocky_preparation_contract.py'):
            _, module = self.fixed_blob(tree, fixed_path)
            if module != (ROOT / fixed_path).read_bytes():
                raise contract.QualificationError('read-candidate-data', 'identity-mismatch')
        return tree, blob, consumer_blob, contract.parse_declaration(raw.decode('utf-8'))


def probe_digest() -> str:
    digest = hashlib.sha256()
    for name in PROBE_PATHS:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        digest.update(name.encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def resolve(options: argparse.Namespace) -> dict:
    observer = GitHubObserver()
    pull = observer.candidate()
    tree, blob, consumer_blob, declaration = observer.declaration(pull['head'])
    current = observer.candidate()
    if current != pull:
        raise contract.QualificationError('resolve-candidate', 'source-drift')
    now = int(time.time())
    authorization = {
        'schema_version': 1, 'selector': contract.SELECTOR, 'repository': 'SecPal/deployment',
        'issue': 81, 'pull_request': pull['number'], 'candidate_sha': pull['head'],
        'candidate_tree': tree, 'candidate_blob': blob, 'consumer_blob': consumer_blob,
        'declaration_sha256': contract.declaration_digest(declaration), 'control_sha': options.control_sha,
        'probe_sha256': probe_digest(), 'profile': options.profile, 'run_id': options.run_id,
        'run_attempt': options.run_attempt, 'issued_at': now, 'expires_at': now + 10800,
    }
    contract.admit_authorization(authorization, control_sha=options.control_sha, profile=options.profile,
                                 run_id=options.run_id, run_attempt=options.run_attempt, now=now, declaration=declaration)
    return {'authorization': authorization, 'declaration': declaration}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('resolve', 'reconfirm', 'admit', 'admit-diagnostic'))
    parser.add_argument('--profile', required=True, choices=tuple(contract.rpm.PROFILE_ARCHITECTURES))
    parser.add_argument('--control-sha', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prepared', type=Path)
    parser.add_argument('--continuation', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--host-evidence', type=Path)
    parser.add_argument('--qualification-run-id')
    parser.add_argument('--qualification-run-attempt')
    options = parser.parse_args()
    try:
        if options.operation in ('admit', 'admit-diagnostic'):
            from jsonschema import Draft202012Validator
            if any(path is None or path.is_symlink() or not path.is_file() or path.stat().st_size > 131072
                   for path in (options.prepared, options.continuation, options.evidence, options.host_evidence)):
                raise contract.QualificationError('admit-qualification', 'representation-invalid')
            prepared = json.loads(options.prepared.read_text(), object_pairs_hook=contract.duplicate_keys)
            auth = contract.admit_authorization(prepared['authorization'], control_sha=options.control_sha,
                profile=options.profile, run_id=options.run_id, run_attempt=options.run_attempt, now=int(time.time()), declaration=prepared['declaration'])
            contract.admit_declaration(prepared['declaration'])
            if auth['probe_sha256'] != probe_digest():
                raise contract.QualificationError('validate-authorization', 'identity-mismatch')
            continuation = json.loads(options.continuation.read_text(), object_pairs_hook=contract.duplicate_keys)
            for key, value in {'run_id': options.run_id, 'run_attempt': options.run_attempt,
                               'trusted_control_sha': options.control_sha, 'profile': options.profile}.items():
                if continuation.get(key) != value:
                    raise contract.QualificationError('admit-qualification', 'identity-mismatch')
            evidence = json.loads(options.evidence.read_text(), object_pairs_hook=contract.duplicate_keys)
            schema_name = ('postgresql-qualification-diagnostic.schema.json'
                           if options.operation == 'admit-diagnostic' else 'postgresql-qualification-evidence.schema.json')
            schema = json.loads((ROOT / 'schemas' / schema_name).read_text())
            Draft202012Validator(schema).validate(evidence)
            shared = dict(authorization=auth, qualification_run_id=options.qualification_run_id,
                          qualification_run_attempt=options.qualification_run_attempt,
                          host_evidence_sha256=hashlib.sha256(options.host_evidence.read_bytes()).hexdigest())
            if options.operation == 'admit-diagnostic':
                binding = dict(control_sha=options.control_sha, profile=options.profile,
                    access_run_id=options.qualification_run_id, access_run_attempt=options.qualification_run_attempt,
                    instance_id=continuation['instance_id'], instance_name=continuation['instance_name'])
                document = contract.admit_diagnostic(evidence, binding=binding, **shared)
            else:
                document = contract.admit_evidence(evidence, instance_id=continuation['instance_id'],
                    instance_name=continuation['instance_name'], declaration=prepared['declaration'], **shared)
            options.output.write_bytes(contract.canonical_bytes(document) + b'\n')
            options.output.chmod(0o600)
            return 0
        document = resolve(options)
        if options.operation == 'reconfirm':
            if options.prepared is None or options.prepared.stat().st_size > 16384:
                raise contract.QualificationError('validate-authorization', 'representation-invalid')
            prepared = json.loads(options.prepared.read_text(), object_pairs_hook=contract.duplicate_keys)
            authorization = contract.admit_authorization(prepared['authorization'], control_sha=options.control_sha,
                profile=options.profile, run_id=options.run_id, run_attempt=options.run_attempt, now=int(time.time()), declaration=prepared['declaration'])
            stable = ('candidate_sha', 'candidate_tree', 'candidate_blob', 'consumer_blob', 'declaration_sha256', 'pull_request', 'probe_sha256')
            if any(document['authorization'][key] != authorization[key] for key in stable):
                raise contract.QualificationError('resolve-candidate', 'source-drift')
            document = prepared
        options.output.write_bytes(contract.canonical_bytes(document) + b'\n')
        options.output.chmod(0o600)
        return 0
    except (contract.QualificationError, KeyError, TypeError, ValueError, OSError, ValidationError) as error:
        failure = (contract.diagnostic(error.operation, error.reason) if isinstance(error, contract.QualificationError)
                   else contract.diagnostic('resolve-candidate', 'representation-invalid'))
        print(json.dumps(failure), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
