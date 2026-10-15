#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""One bounded reference-host transport; accepted control owns all grading.

Private operational authority provisions the disposable host, accepted control
bundle, root-owned exact lease and restricted host-specific SSH access. This
program has no provisioning, arbitrary remote command or caller PASS mode.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from jsonschema.exceptions import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent))
import postgresql_qualification_contract as contract

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control = load('reference_postgresql_control', 'scripts/ci-cloud/postgresql-qualification-control.py')
guest = load('reference_postgresql_guest', 'scripts/ci-cloud/qualify-native-postgresql.py')
COMMANDS = {
    'check': 'sudo -n /usr/bin/python3 -I /opt/secpal-control/scripts/ci-cloud/qualify-native-postgresql.py --reference-host-check',
    'run': 'sudo -n /usr/bin/python3 -I /opt/secpal-control/scripts/ci-cloud/qualify-native-postgresql.py --reference-host',
}


def read(path):
    facts = path.lstat()
    if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_size > 131072):
        raise contract.QualificationError('validate-authorization', 'representation-invalid')
    return json.loads(path.read_text(), object_pairs_hook=contract.duplicate_keys)


def write(path, document):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(contract.canonical_bytes(document) + b'\n')


def claim(directory, run_id, run_attempt):
    if (not isinstance(run_id, str) or contract.RUN.fullmatch(run_id) is None
            or not isinstance(run_attempt, str) or contract.ATTEMPT.fullmatch(run_attempt) is None):
        raise contract.QualificationError('claim-reference-run', 'representation-invalid')
    try:
        write(directory / f'claimed-{run_id}-{run_attempt}.json', {'run_id': run_id, 'run_attempt': run_attempt})
    except OSError:
        raise contract.QualificationError('claim-reference-run', 'identity-mismatch') from None


def authenticate_control(observer, sha):
    """Immutable accepted-main bytes, not candidate-local transport or grader."""
    try:
        _authenticate_control(observer, sha)
    except (ValueError, KeyError, TypeError, AttributeError, OSError):
        raise contract.QualificationError('validate-authorization', 'representation-invalid') from None


def _authenticate_control(observer, sha):
    head = observer.request('/repos/SecPal/deployment/commits/main')
    if (head['sha'] != sha or head['commit']['verification']['verified'] is not True
            or head['commit']['verification']['reason'] != 'valid'):
        raise contract.QualificationError('validate-authorization', 'source-drift')
    tree = observer.request('/repos/SecPal/deployment/git/trees/' + head['commit']['tree']['sha'] + '?recursive=1')
    if tree.get('truncated') is not False or not isinstance(tree.get('tree'), list) or len(tree['tree']) > 10000:
        raise contract.QualificationError('validate-authorization', 'observation-limit-exceeded')
    entries = {entry['path']: entry for entry in tree['tree']}
    for path in (*control.PROBE_PATHS, 'scripts/ci-cloud/postgresql-reference-host.py'):
        entry = entries.get(path, {})
        if entry.get('type') != 'blob' or entry.get('mode') not in ('100644', '100755'):
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        blob = observer.request('/repos/SecPal/deployment/git/blobs/' + entry['sha'])
        if blob.get('encoding') != 'base64' or type(blob.get('size')) is not int or not 0 < blob['size'] <= 262144:
            raise contract.QualificationError('validate-authorization', 'representation-invalid')
        content = base64.b64decode(''.join(blob['content'].split()), validate=True)
        local = ROOT / path
        if (len(content) != blob['size'] or local.is_symlink()
                or hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() != entry['sha']
                or content != local.read_bytes()):
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')


class Transport:
    def __init__(self, authorization, identity_file):
        self.host = contract.admit_reference_host(authorization['reference_host'])
        self.identity_file = identity_file.resolve(strict=True)
        facts = identity_file.lstat()
        if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid()
                or stat.S_IMODE(facts.st_mode) != 0o600):
            raise contract.QualificationError('authenticate-reference-host', 'identity-mismatch')

    def observe(self, operation):
        if operation not in COMMANDS:
            raise contract.QualificationError('transport-reference-host', 'representation-invalid')
        with tempfile.TemporaryDirectory(prefix='secpal-pg-reference-') as directory:
            known = Path(directory) / 'known_hosts'
            known.write_text('secpal-postgresql-reference ' + self.host['ssh_host_key'] + '\n')
            known.chmod(0o600)
            args = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'UserKnownHostsFile=' + str(known), '-o', 'HostKeyAlias=secpal-postgresql-reference',
                    '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no',
                    '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
                    '-o', 'KbdInteractiveAuthentication=no',
                    '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
                    '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                    '-i', str(self.identity_file), 'secpal-cloud@' + self.host['address'], COMMANDS[operation]]
            result = guest.bounded_process(args,
                environment={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent'},
                timeout=60 if operation == 'check' else 2700, limit=131072,
                operation='authenticate-reference-host' if operation == 'check' else 'transport-reference-host')
        if result.returncode != 0:
            # Retain bounded typed guest diagnostics when authenticated execution
            # returned them. SSH errors and uncertain cleanup never become PASS.
            if operation == 'run':
                try:
                    diagnostic = json.loads(result.stderr, object_pairs_hook=contract.duplicate_keys)
                    self.failure = diagnostic
                except (ValueError, TypeError):
                    self.failure = None
            raise contract.QualificationError('authenticate-reference-host' if result.returncode == 255
                                               else 'transport-reference-host', 'command-failed')
        try:
            return json.loads(result.stdout, object_pairs_hook=contract.duplicate_keys)
        except (ValueError, TypeError):
            raise contract.QualificationError('retrieve-reference-evidence', 'representation-invalid') from None


def execute(prepared, identity_file, directory):
    auth = prepared['authorization']
    contract.admit_authorization(auth, control_sha=auth['control_sha'], profile=auth['profile'],
        run_id=auth['run_id'], run_attempt=auth['run_attempt'], now=int(time.time()), declaration=prepared['declaration'])
    if auth['profile'] not in contract.REFERENCE_PROFILES:
        raise contract.QualificationError('validate-authorization', 'identity-mismatch')
    authenticate_control(control.GitHubObserver(), auth['control_sha'])
    options = argparse.Namespace(control_sha=auth['control_sha'], profile=auth['profile'],
        run_id=auth['run_id'], run_attempt=auth['run_attempt'], reference_host=auth['reference_host'])
    fresh = control.resolve(options)
    stable = set(auth) - {'issued_at', 'expires_at'}
    if (any(fresh['authorization'][k] != auth[k] for k in stable)
            or fresh['declaration'] != prepared['declaration']):
        raise contract.QualificationError('resolve-candidate', 'source-drift')
    transport = Transport(auth, identity_file)
    claim(directory, auth['run_id'], auth['run_attempt'])
    host_digest = None
    cleanup_complete = False
    binding = dict(control_sha=auth['control_sha'], profile=auth['profile'],
        access_run_id=auth['run_id'], access_run_attempt=auth['run_attempt'], reference_host=auth['reference_host'])
    try:
        checked = transport.observe('check')
        if (not isinstance(checked, dict) or set(checked) != {'authorization', 'resource', 'host_facts', 'probe_sha256'}
                or checked['authorization'] != auth or checked['resource'] != binding
                or checked['probe_sha256'] != control.probe_digest() or checked['probe_sha256'] != auth['probe_sha256']):
            raise contract.QualificationError('authenticate-reference-host', 'identity-mismatch')
        facts = contract.admit_reference_host_facts(checked['host_facts'], auth)
        host_digest = contract.reference_host_digest(facts)
        write(directory / 'host-observation.json', checked)
        evidence = transport.observe('run')
        from jsonschema import Draft202012Validator
        Draft202012Validator(json.loads((ROOT/'schemas/postgresql-qualification-evidence.schema.json').read_text())).validate(evidence)
        admitted = contract.admit_evidence(evidence, authorization=auth, reference_host=auth['reference_host'],
            reference_host_facts=facts, qualification_run_id=auth['run_id'], qualification_run_attempt=auth['run_attempt'],
            host_evidence_sha256=host_digest, declaration=prepared['declaration'])
        cleanup_complete = True
        # Independent current-source recheck after execution. A moved candidate
        # cannot reuse this result; successful cleanup remains retained evidence.
        write(directory / 'observation.json', evidence)
        after = control.resolve(options)
        if any(after['authorization'][k] != auth[k] for k in stable):
            raise contract.QualificationError('resolve-candidate', 'source-drift')
        write(directory / 'admitted.json', admitted)
        return admitted
    except Exception as error:
        operation, reason = (error.operation, error.reason) if isinstance(error, contract.QualificationError) else ('admit-qualification', 'representation-invalid')
        diagnostic = contract.bound_diagnostic(operation, reason, authorization=auth, binding=binding,
            qualification_run_id=auth['run_id'], qualification_run_attempt=auth['run_attempt'],
            host_evidence_sha256=host_digest, cleanup_complete=cleanup_complete)
        remote = getattr(transport, 'failure', None)
        if remote is not None and host_digest is not None:
            try:
                from jsonschema import Draft202012Validator
                Draft202012Validator(json.loads((ROOT/'schemas/postgresql-qualification-diagnostic.schema.json').read_text())).validate(remote)
                remote = contract.admit_diagnostic(remote, authorization=auth, binding=binding,
                    qualification_run_id=auth['run_id'], qualification_run_attempt=auth['run_attempt'],
                    host_evidence_sha256=host_digest)
                write(directory / 'guest-diagnostic.json', remote)
                diagnostic['cleanup_complete'] = remote['cleanup_complete']
            except (contract.QualificationError, ValidationError, ValueError, KeyError, TypeError):
                pass
        write(directory / 'diagnostic.json', diagnostic)
        raise contract.QualificationError(operation, reason) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run'))
    parser.add_argument('--operation-directory', type=Path, required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--reference-host', type=Path)
    parser.add_argument('--run-id')
    parser.add_argument('--identity-file', type=Path)
    parser.add_argument('--apply', action='store_true')
    options = parser.parse_args()
    try:
        directory = options.operation_directory
        if options.operation == 'prepare':
            if not options.architecture or options.reference_host is None or options.run_id is None or options.apply:
                raise contract.QualificationError('validate-authorization', 'representation-invalid')
            observer = control.GitHubObserver()
            sha = observer.request('/repos/SecPal/deployment/commits/main')['sha']
            authenticate_control(observer, sha)
            options.control_sha, options.profile, options.run_attempt = sha, 'reference-rocky-10-2-' + options.architecture, '1'
            options.reference_host = contract.admit_reference_host(read(options.reference_host))
            prepared = control.resolve(options)
            directory.mkdir(mode=0o700, parents=False, exist_ok=False)
            write(directory/'prepared.json', prepared)
            write(directory/'probe-manifest.json', control.probe_manifest())
        else:
            facts = directory.lstat()
            if (not options.apply or options.identity_file is None or not stat.S_ISDIR(facts.st_mode)
                    or facts.st_uid != os.geteuid() or stat.S_IMODE(facts.st_mode) != 0o700):
                raise contract.QualificationError('validate-authorization', 'identity-mismatch')
            execute(read(directory/'prepared.json'), options.identity_file, directory)
        return 0
    except (contract.QualificationError, ValidationError, ValueError, KeyError, TypeError, OSError) as error:
        operation, reason = (error.operation, error.reason) if isinstance(error, contract.QualificationError) else ('validate-authorization', 'representation-invalid')
        print(json.dumps(contract.diagnostic(operation, reason)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
