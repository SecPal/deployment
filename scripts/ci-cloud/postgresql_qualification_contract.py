#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure data admission for deployment#81; authority is accepted main.

Evidence architecture owner: SecPal/.github/docs/evidence-architecture-contract.md.
PostgreSQL policy owner: deployment#81 and ADR-017. Frozen #80 claims are not
extended here. This module has no filesystem, environment or process authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import rocky_preparation_contract as rpm

RESPONSIBILITY = 'normalization,admission,assembly'
INVARIANT_OWNERS = {
    'postgresql-native-infrastructure': 'SecPal/deployment#81',
    'postgresql-package-provenance': 'rocky_preparation_contract.admit_package',
    'evidence-architecture': 'SecPal/.github/docs/evidence-architecture-contract.md',
}
SELECTOR = 'native-postgresql-18'
CANDIDATE_PATH = 'config/production/postgresql-contract.json'
CONSUMER_PATH = 'scripts/render-native-postgresql.py'
PACKAGES = ('postgresql18-server', 'postgresql18', 'postgresql18-private-libs')
DECLARATION = {
    'schema_version': 1, 'major': 18,
    'packages': list(PACKAGES), 'repository': 'appstream',
    'package_version': '18.6', 'package_release': '1.el10_2',
    'service': 'postgresql.service', 'data_directory': '/var/lib/pgsql/data',
    'listen_addresses': ['127.0.0.1', '::1'], 'port': 5432, 'database': 'secpal',
    'transport': {
        'server_name': 'db.secpal.internal', 'sslmode': 'verify-full',
        'authentication': 'scram-sha-256', 'minimum_tls': 'TLSv1.2',
        'material_root': '/etc/secpal/postgresql/current',
    },
    'roles': {
        'owner': 'secpal_owner', 'runtime': 'secpal_runtime',
        'migration': 'secpal_migration', 'backup': 'secpal_backup',
        'replication': 'secpal_replication',
    },
    'network': {
        'backend': 'pasta', 'mapping': '169.254.81.1',
        'hostname': 'db.secpal.internal', 'loopback_tcp_port': 5432,
        'loopback_policy': 'runtime-user-postgresql-only',
    },
    'state': {'sessions': 'database', 'queues': 'database', 'cache': 'database'},
}
# Reviewed SecPal publisher authority; this identity is fixed by trusted main,
# never dispatch/candidate data. The older #119 application fixture stays separate.
APPLICATION_RUNTIME = {
    'image': 'ghcr.io/secpal/api@sha256:ac97416f3feac5c57204421059105389c9add2cfbcda1b063eadf4c6ad7647ab',
    'source_commit': '7da77556e7a4896940b6c50ccf6ba2c3fb9a8653',
    'repository': 'SecPal/api',
    'workflow': 'SecPal/api/.github/workflows/publish-container.yml',
    'source_ref': 'refs/heads/main',
    'platform_digests': {
        'amd64': 'sha256:8d0d960306c6989be55a9c7bc41937699e55dbdbc6193bff870f38a1b19605a3',
        'arm64': 'sha256:ed91caa822e189187d57e0ff322c54e3b9837aa679cc087015933dcda9a3be7e',
    },
}
DECLARATION['application_runtime'] = APPLICATION_RUNTIME
APPLICATION_PROBES = {
    'pdo': {'connected': True, 'stage': 'connection', 'driver': 'pgsql',
            'host': 'db.secpal.internal', 'sslmode': 'verify-full',
            'sslrootcert': '/run/secpal-pg/application/ca.crt',
            'tls': 'TLSv1.3'},
    'wrong-hostname': {'connected': False, 'stage': 'connection', 'reason': 'hostname'},
    'wrong-ca': {'connected': False, 'stage': 'connection', 'reason': 'certificate'},
    'wrong-password': {'connected': False, 'stage': 'connection', 'reason': 'authentication'},
    'plaintext': {'connected': False, 'stage': 'configuration', 'reason': 'tls-policy'},
    'insecure-verification': {'connected': False, 'stage': 'configuration', 'reason': 'tls-policy'},
    'environment-substitution': {'connected': True, 'stage': 'connection', 'driver': 'pgsql',
            'host': 'db.secpal.internal', 'sslmode': 'verify-full',
            'sslrootcert': '/run/secpal-pg/application/ca.crt',
            'tls': 'TLSv1.3'},
}
APPLICATION_HEALTH = {
    'ready-up': {'http_status': 200, 'body_status': 'ready'},
    'live-up': {'http_status': 200, 'body_status': 'alive'},
    'ready-down': {'http_status': 503, 'body_status': 'not_ready'},
    'live-down': {'http_status': 200, 'body_status': 'alive'},
    'ready-restored': {'http_status': 200, 'body_status': 'ready'},
}


def normalize_application_http(raw: str) -> dict[str, Any]:
    document = normalize_json_fact(raw)
    if (not isinstance(document, dict) or set(document) != {'http_status', 'body_status'}
            or type(document['http_status']) is not int
            or document['http_status'] not in (200, 503)
            or document['body_status'] not in ('ready', 'not_ready', 'alive')):
        raise QualificationError('probe-readiness', 'representation-invalid')
    return document


def admit_application(raw: object) -> dict[str, Any]:
    if (not isinstance(raw, dict) or set(raw) != {'runtime', 'probes', 'health', 'same_process'}
            or canonical_bytes(raw['runtime']) != canonical_bytes(APPLICATION_RUNTIME)
            or raw['same_process'] is not True
            or canonical_bytes(raw['health']) != canonical_bytes(APPLICATION_HEALTH)
            or not isinstance(raw['probes'], dict) or set(raw['probes']) != set(APPLICATION_PROBES)):
        raise QualificationError('probe-application', 'invariant-failed')
    for name, expected in APPLICATION_PROBES.items():
        observed = raw['probes'][name]
        if name in ('pdo', 'environment-substitution'):
            if (not isinstance(observed, dict) or observed.get('tls') not in ('TLSv1.2', 'TLSv1.3')):
                raise QualificationError('probe-application', 'invariant-failed')
            observed = dict(observed, tls='TLSv1.3')
        if canonical_bytes(observed) != canonical_bytes(expected):
            raise QualificationError('probe-application', 'invariant-failed')
    return json.loads(canonical_bytes(raw))


OPERATIONS = frozenset({
    'resolve-candidate', 'read-candidate-data', 'admit-candidate-data',
    'validate-authorization', 'install-postgresql', 'initialize-postgresql',
    'configure-postgresql', 'configure-loopback-policy', 'issue-test-material',
    'start-postgresql', 'observe-native-service', 'observe-data-directory',
    'observe-packages', 'observe-listeners', 'observe-selinux', 'observe-roles',
    'admit-application-image', 'initialize-application', 'probe-application',
    'probe-transport', 'probe-privileges', 'probe-network', 'probe-readiness',
    'probe-semantics', 'admit-qualification', 'write-evidence', 'cleanup-test-material',
})
REASONS = frozenset({
    'command-failed', 'representation-invalid', 'observation-limit-exceeded',
    'invariant-failed', 'identity-mismatch', 'source-drift', 'expired',
})
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
RUN = re.compile(r'^[1-9][0-9]{0,19}$')
ATTEMPT = re.compile(r'^[1-9][0-9]{0,2}$')
PROBES = {
    'verified-tls': 0, 'wrong-hostname': 2, 'wrong-ca': 2,
    'plaintext': 2, 'wrong-password': 2, 'runtime-ddl': 3,
    'runtime-role-escalation': 3, 'migration-ddl': 0,
    'backup-read': 0, 'backup-ddl': 3,
    'rootless-verified-tls': 0, 'rootless-unmapped': 2,
    'other-loopback-port': 1,
    'ready-up': 0, 'ready-down': 1, 'liveness-down': 0,
    'server-key-runtime-denied': 1, 'jsonb-uuid-constraints-rollback': 0, 'row-locks': 0,
    'transaction-advisory-locks': 0, 'persistence-restart': 0,
}


class QualificationError(RuntimeError):
    def __init__(self, operation: str, reason: str):
        if operation not in OPERATIONS or reason not in REASONS:
            operation, reason = 'admit-qualification', 'representation-invalid'
        self.operation, self.reason = operation, reason
        super().__init__(f'{operation}:{reason}')


def diagnostic(operation: str, reason: str) -> dict[str, Any]:
    if operation not in OPERATIONS or reason not in REASONS:
        raise QualificationError('admit-qualification', 'representation-invalid')
    return {'schema_version': 1, 'claim': SELECTOR, 'operation': operation, 'reason': reason}


def duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError('read-candidate-data', 'representation-invalid')
        result[key] = value
    return result


def parse_declaration(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str) or len(raw.encode()) > 8192:
        raise QualificationError('read-candidate-data', 'observation-limit-exceeded')
    try:
        document = json.loads(raw, object_pairs_hook=duplicate_keys)
    except (ValueError, TypeError):
        raise QualificationError('read-candidate-data', 'representation-invalid') from None
    return admit_declaration(document)


def canonical_bytes(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def admit_declaration(document: object) -> dict[str, Any]:
    # Canonical bytes also distinguish JSON bool/number types (True != 1).
    if not isinstance(document, dict) or set(document) != set(DECLARATION):
        raise QualificationError('admit-candidate-data', 'invariant-failed')
    for key, value in DECLARATION.items():
        if key not in ('package_version', 'package_release') and canonical_bytes(document[key]) != canonical_bytes(value):
            raise QualificationError('admit-candidate-data', 'invariant-failed')
    if (not isinstance(document['package_version'], str)
            or re.fullmatch(r'18\.[0-9]{1,3}', document['package_version']) is None
            or not isinstance(document['package_release'], str)
            or re.fullmatch(r'[1-9][0-9]{0,2}\.el10_[2-9][0-9]?(?:\.[0-9]{1,3})?', document['package_release']) is None):
        raise QualificationError('admit-candidate-data', 'invariant-failed')
    return json.loads(canonical_bytes(document))


def declaration_digest(document: object) -> str:
    return hashlib.sha256(canonical_bytes(admit_declaration(document))).hexdigest()


def admit_authorization(document: object, *, control_sha: str, profile: str,
                        run_id: str, run_attempt: str, now: int, declaration: object = DECLARATION) -> dict[str, Any]:
    fields = {'schema_version', 'selector', 'repository', 'issue', 'pull_request',
              'candidate_sha', 'candidate_tree', 'candidate_blob', 'consumer_blob', 'declaration_sha256',
              'control_sha', 'probe_sha256', 'profile', 'run_id', 'run_attempt',
              'issued_at', 'expires_at'}
    if not isinstance(document, dict) or set(document) != fields:
        raise QualificationError('validate-authorization', 'representation-invalid')
    if (type(document['schema_version']) is not int or document['schema_version'] != 1 or document['selector'] != SELECTOR
            or document['repository'] != 'SecPal/deployment' or type(document['issue']) is not int or document['issue'] != 81
            or type(document['pull_request']) is not int or not 1 <= document['pull_request'] <= 1000000
            or type(document['issued_at']) is not int or type(document['expires_at']) is not int
            or not 0 < document['expires_at'] - document['issued_at'] <= 10800
            or document['issued_at'] > now or document['expires_at'] <= now):
        raise QualificationError('validate-authorization', 'expired')
    for key in ('candidate_sha', 'candidate_tree', 'candidate_blob', 'consumer_blob', 'control_sha'):
        if not isinstance(document[key], str) or SHA.fullmatch(document[key]) is None:
            raise QualificationError('validate-authorization', 'representation-invalid')
    for key in ('probe_sha256', 'declaration_sha256'):
        if not isinstance(document[key], str) or DIGEST.fullmatch(document[key]) is None:
            raise QualificationError('validate-authorization', 'representation-invalid')
    if (profile not in rpm.PROFILE_ARCHITECTURES or RUN.fullmatch(run_id) is None
            or ATTEMPT.fullmatch(run_attempt) is None
            or any(document[key] != value for key, value in {
                'control_sha': control_sha, 'profile': profile,
                'run_id': run_id, 'run_attempt': run_attempt,
                'declaration_sha256': declaration_digest(declaration),
            }.items())):
        raise QualificationError('validate-authorization', 'identity-mismatch')
    return dict(document)


def admit_postgresql_package(name: str, raw: dict[str, Any], architecture: str,
                             signer: str) -> dict[str, Any]:
    if name not in PACKAGES:
        raise QualificationError('observe-packages', 'representation-invalid')
    try:
        fact = rpm.normalize_installed_package(name, raw, architecture)
        result = rpm.admit_package(fact, signer, architecture)
    except rpm.ContractError:
        raise QualificationError('observe-packages', 'invariant-failed') from None
    if (result['resolved_repository'] != 'appstream'
            or re.fullmatch(r'18\.[0-9]+', result['version']) is None
            or result['architecture'] != architecture):
        raise QualificationError('observe-packages', 'invariant-failed')
    return result


def normalize_lifecycle_timeline(document: object) -> dict[str, int]:
    """Normalize the fixed GitHub Ready/Draft selection for select_candidate.

    GitHub totalCount describes provider-wide timeline metadata, not the
    selected nodes. Completeness and the selected-event bound are independent.
    """
    if (not isinstance(document, dict) or set(document) != {'totalCount', 'pageInfo', 'nodes'}
            or type(document['totalCount']) is not int or document['totalCount'] < 0
            or not isinstance(document['pageInfo'], dict)
            or set(document['pageInfo']) != {'hasNextPage'}
            or not isinstance(document['nodes'], list)):
        raise QualificationError('resolve-candidate', 'representation-invalid')
    nodes = document['nodes']
    if document['pageInfo']['hasNextPage'] is not False or len(nodes) > 100:
        raise QualificationError('resolve-candidate', 'observation-limit-exceeded')
    counts = {'ready_events': 0, 'draft_events': 0}
    for node in nodes:
        if (not isinstance(node, dict) or set(node) != {'__typename'}
                or node['__typename'] not in ('ReadyForReviewEvent', 'ConvertToDraftEvent')):
            raise QualificationError('resolve-candidate', 'representation-invalid')
        counts['ready_events' if node['__typename'] == 'ReadyForReviewEvent' else 'draft_events'] += 1
    return counts


def select_candidate(pulls: object) -> dict[str, Any]:
    """Admit bounded trusted GitHub observations, never caller dispatch selectors."""
    if not isinstance(pulls, list) or len(pulls) > 100:
        raise QualificationError('resolve-candidate', 'representation-invalid')
    fields = {'number', 'state', 'repository', 'head_repository', 'base', 'head',
              'body', 'closing_issues', 'draft', 'ready_events', 'draft_events', 'commits'}
    matching = []
    for pull in pulls:
        if not isinstance(pull, dict) or set(pull) != fields:
            raise QualificationError('resolve-candidate', 'representation-invalid')
        closing = pull['closing_issues']
        if not isinstance(closing, list) or len(closing) > 100:
            raise QualificationError('resolve-candidate', 'representation-invalid')
        if 'SecPal/deployment#81' in closing:
            matching.append(pull)
    if len(matching) != 1:
        raise QualificationError('resolve-candidate', 'identity-mismatch')
    pull = matching[0]
    if (type(pull['number']) is not int or not 1 <= pull['number'] <= 1000000
            or pull['state'] != 'OPEN' or pull['repository'] != 'SecPal/deployment'
            or pull['head_repository'] != 'SecPal/deployment' or pull['base'] != 'main'
            or pull['closing_issues'] != ['SecPal/deployment#81']
            or not isinstance(pull['head'], str) or SHA.fullmatch(pull['head']) is None
            or not isinstance(pull['body'], str) or len(pull['body'].encode()) > 65536
            or re.search(r'(?m)^Fixes #81\s*$', pull['body']) is None
            or type(pull['draft']) is not bool
            or type(pull['ready_events']) is not int or type(pull['draft_events']) is not int
            or pull['draft_events'] != 0
            or pull['ready_events'] != (0 if pull['draft'] else 1)):
        raise QualificationError('resolve-candidate', 'identity-mismatch')
    commits = pull['commits']
    if (not isinstance(commits, list) or not 1 <= len(commits) <= 300
            or any(not isinstance(c, dict) or set(c) != {'sha', 'verified', 'reason'}
                   or not isinstance(c['sha'], str) or SHA.fullmatch(c['sha']) is None
                   or c['verified'] is not True or c['reason'] != 'valid' for c in commits)
            or len({c['sha'] for c in commits}) != len(commits)
            or commits[-1]['sha'] != pull['head']):
        raise QualificationError('resolve-candidate', 'identity-mismatch')
    return dict(pull)


ROLE_ATTRIBUTES = ('superuser', 'create_db', 'create_role', 'inherit', 'replication', 'bypass_rls', 'login')
ROLE_POLICY = {
    'secpal_owner': [False, False, False, False, False, False, False],
    'secpal_runtime': [False, False, False, False, False, False, False],
    'secpal_migration': [False, False, False, False, False, False, False],
    'secpal_backup': [False, False, False, False, False, False, False],
    'secpal_replication': [False, False, False, False, True, False, False],
}
OBSERVATION_FIELDS = {'server_version_num', 'service', 'data_directory', 'process_label',
                      'listeners', 'settings', 'roles', 'issued_logins', 'memberships', 'password_algorithms',
                      'hba', 'probes', 'locking', 'rootless_liveness', 'container_servers',
                      'loopback_sentinel_host', 'native_cgroup', 'restart_row_count', 'tls_material', 'application'}


def normalize_json_fact(raw: str) -> Any:
    if not isinstance(raw, str) or len(raw.encode()) > 262144:
        raise QualificationError('admit-qualification', 'observation-limit-exceeded')
    try:
        result = json.loads(raw, object_pairs_hook=duplicate_keys)
        canonical_bytes(result)  # Reject non-JSON numeric constants.
        return result
    except (ValueError, TypeError):
        raise QualificationError('admit-qualification', 'representation-invalid') from None


def normalize_service(raw: str) -> tuple[dict[str, str], str]:
    if not isinstance(raw, str) or len(raw.encode()) > 4096:
        raise QualificationError('observe-native-service', 'observation-limit-exceeded')
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in fields:
            raise QualificationError('observe-native-service', 'representation-invalid')
        fields[key] = value
    if set(fields) != {'User','Group','ActiveState','UnitFileState','FragmentPath','MainPID'}:
        raise QualificationError('observe-native-service', 'representation-invalid')
    pid = fields.pop('MainPID')
    if not pid.isdecimal() or not 1 < int(pid) <= 2147483647:
        raise QualificationError('observe-native-service', 'representation-invalid')
    return fields, pid


def normalize_listeners(raw: str) -> list[str]:
    if not isinstance(raw, str) or len(raw.encode()) > 8192:
        raise QualificationError('observe-listeners', 'observation-limit-exceeded')
    rows = [line.split() for line in raw.splitlines()]
    if any(len(row) < 5 or row[0] != 'LISTEN' for row in rows):
        raise QualificationError('observe-listeners', 'representation-invalid')
    return sorted(row[3] for row in rows)


def qualification_logins(run_id: str, run_attempt: str, expires_at: int) -> dict[str, Any]:
    """Bounded test identities, never production Secret Authority issuance."""
    if (not isinstance(run_id, str) or RUN.fullmatch(run_id) is None
            or not isinstance(run_attempt, str) or ATTEMPT.fullmatch(run_attempt) is None
            or type(expires_at) is not int or not 1 <= expires_at <= 253402300799):
        raise QualificationError('validate-authorization', 'representation-invalid')
    return {kind: {'name': f'secpal_qualification_{kind}_{run_id}_{run_attempt}',
                   'attributes': [False, False, False, kind == 'runtime', False, False, True],
                   'expires_at': expires_at} for kind in ('runtime', 'migration')}


def qualification_memberships(logins: dict[str, Any]) -> list[list[Any]]:
    # Explicit ADMIN/INHERIT/SET observations prevent authority inheritance drift.
    return [['secpal_migration', logins['migration']['name'], False, True, True],
            ['secpal_owner', 'secpal_migration', False, False, True],
            ['secpal_runtime', logins['runtime']['name'], False, True, False]]


def admit_observations(raw: object, *, run_id: str, run_attempt: str, expires_at: int) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != OBSERVATION_FIELDS:
        raise QualificationError('admit-qualification', 'representation-invalid')
    admit_application(raw['application'])
    logins = qualification_logins(run_id, run_attempt, expires_at)
    expected = {
        'service': {'User': 'postgres', 'Group': 'postgres', 'ActiveState': 'active',
                    'UnitFileState': 'enabled', 'FragmentPath': '/usr/lib/systemd/system/postgresql.service'},
        'data_directory': {'owner': 'postgres', 'group': 'postgres', 'mode': '700', 'type': 'postgresql_db_t'},
        'tls_material': {name: {'owner': 'postgres', 'group': 'postgres', 'mode': '600', 'type': 'postgresql_db_t'}
                         for name in ('server.crt', 'server.key', 'ca.crt')},
        'process_label': 'postgresql_t', 'listeners': ['127.0.0.1:5432', '[::1]:5432'],
        'settings': {'listen_addresses': '127.0.0.1,::1', 'port': '5432', 'ssl': 'on',
                     'ssl_min_protocol_version': 'TLSv1.2', 'password_encryption': 'scram-sha-256',
                     'data_directory': '/var/lib/pgsql/data',
                     'ssl_cert_file': '/etc/secpal/postgresql/current/server.crt',
                     'ssl_key_file': '/etc/secpal/postgresql/current/server.key',
                     'ssl_ca_file': '/etc/secpal/postgresql/current/ca.crt'},
        'roles': ROLE_POLICY,
        'issued_logins': logins,
        'memberships': qualification_memberships(logins),
        'password_algorithms': {'runtime': 'SCRAM-SHA-256', 'migration': 'SCRAM-SHA-256'},
        'hba': [
            ['local', ['all'], ['postgres'], None, None, 'peer', None],
            ['local', ['all'], ['all'], None, None, 'reject', None],
            ['hostssl', ['secpal'], ['+secpal_runtime', '+secpal_migration'], '127.0.0.1', '255.255.255.255', 'scram-sha-256', None],
            ['hostssl', ['secpal'], ['+secpal_runtime', '+secpal_migration'], '::1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'scram-sha-256', None],
            ['host', ['all'], ['all'], '0.0.0.0', '0.0.0.0', 'reject', None],
            ['host', ['all'], ['all'], '::', '::', 'reject', None],
        ],
        'probes': PROBES, 'locking': {'row_sqlstate': '55P03', 'advisory_held': 'f', 'advisory_released': 't'},
        'rootless_liveness': True, 'container_servers': [], 'loopback_sentinel_host': 0,
        'native_cgroup': '0::/system.slice/postgresql.service', 'restart_row_count': '1',
    }
    version = raw['server_version_num']
    if not isinstance(version, str) or re.fullmatch(r'180[0-9]{3}', version) is None:
        raise QualificationError('admit-qualification', 'invariant-failed')
    if any(canonical_bytes(raw[key]) != canonical_bytes(value) for key, value in expected.items()):
        raise QualificationError('admit-qualification', 'invariant-failed')
    return json.loads(canonical_bytes(raw))


def policy_configuration(runtime_uid: int | str) -> dict[str, str]:
    """Closed reviewed normal forms; not an arbitrary configuration evaluator."""
    settings = {
        'listen_addresses': "'127.0.0.1,::1'", 'port': '5432', 'ssl': 'on',
        'ssl_min_protocol_version': "'TLSv1.2'", 'password_encryption': "'scram-sha-256'",
        'ssl_cert_file': "'/etc/secpal/postgresql/current/server.crt'",
        'ssl_key_file': "'/etc/secpal/postgresql/current/server.key'",
        'ssl_ca_file': "'/etc/secpal/postgresql/current/ca.crt'",
        'unix_socket_directories': "'/var/run/postgresql'",
        'log_statement': "'none'", 'log_parameter_max_length_on_error': '0',
        'log_connections': 'off', 'log_disconnections': 'off',
    }
    hba = (
        'local all postgres peer\nlocal all all reject\n'
        'hostssl secpal +secpal_runtime,+secpal_migration 127.0.0.1/32 scram-sha-256\n'
        'hostssl secpal +secpal_runtime,+secpal_migration ::1/128 scram-sha-256\n'
        'host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n'
    )
    rules = f'''table inet secpal_postgresql {{
  chain rootless_loopback {{
    type filter hook output priority -10; policy accept;
    meta skuid {runtime_uid} ip daddr 127.0.0.0/8 tcp dport 5432 accept
    meta skuid {runtime_uid} ip6 daddr ::1 tcp dport 5432 accept
    meta skuid {runtime_uid} ip daddr 127.0.0.0/8 reject
    meta skuid {runtime_uid} ip6 daddr ::1 reject
  }}
}}
'''
    roles = '''CREATE ROLE secpal_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE secpal_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE secpal_migration NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE secpal_backup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE secpal_replication NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT REPLICATION NOBYPASSRLS;
GRANT secpal_owner TO secpal_migration WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
CREATE DATABASE secpal OWNER secpal_owner;
REVOKE ALL ON DATABASE secpal FROM PUBLIC;
GRANT CONNECT ON DATABASE secpal TO secpal_runtime, secpal_migration;
\\connect secpal
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO secpal_owner;
GRANT USAGE ON SCHEMA public TO secpal_runtime, secpal_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secpal_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO secpal_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner IN SCHEMA public GRANT SELECT ON TABLES TO secpal_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
'''
    return {'postgresql.conf': ''.join(f'{key} = {value}\n' for key, value in settings.items()),
            'pg_hba.conf': hba, 'loopback.nft': rules, 'roles.sql': roles,
            'service.conf': '[Service]\nTimeoutStartSec=60\nTimeoutStopSec=60\nUMask=0077\n'}


# The candidate owns these exact production configuration bytes. Only the UID
# token is parameterized, by a validated local numeric account identity. Equality
# admission rejects arbitrary SQL, unit hooks, includes or firewall programs.
DECLARATION['configuration'] = policy_configuration('@RUNTIME_UID@')


def render_configuration(declaration: object, runtime_uid: int) -> dict[str, str]:
    admitted = admit_declaration(declaration)
    if type(runtime_uid) is not int or not 1 <= runtime_uid <= 2147483647:
        raise QualificationError('configure-loopback-policy', 'representation-invalid')
    return {name: text.replace('@RUNTIME_UID@', str(runtime_uid))
            for name, text in admitted['configuration'].items()}


CLEANUP_POSTCONDITIONS = {'service_stopped': True, 'nft_table_absent': True,
    'client_container_absent': True, 'client_material_absent': True,
    'server_material_absent': True, 'test_authority_absent': True, 'credentials_forgotten': True,
    'database_material_absent': True}


def bound_diagnostic(operation: str, reason: str, *, authorization: object,
                     binding: object, qualification_run_id: str,
                     qualification_run_attempt: str, host_evidence_sha256: object,
                     cleanup_complete: bool) -> dict[str, Any]:
    return dict(diagnostic(operation, reason), authorization=authorization, resource=binding,
                qualification_run_id=qualification_run_id, qualification_run_attempt=qualification_run_attempt,
                host_evidence_sha256=host_evidence_sha256, cleanup_complete=cleanup_complete)


def admit_resource_binding(raw: object) -> dict[str, str]:
    fields = {'control_sha', 'profile', 'access_run_id', 'access_run_attempt', 'instance_id', 'instance_name'}
    if (not isinstance(raw, dict) or set(raw) != fields or any(not isinstance(v, str) for v in raw.values())
            or SHA.fullmatch(raw['control_sha']) is None or raw['profile'] not in rpm.PROFILE_ARCHITECTURES
            or any(RUN.fullmatch(raw[k]) is None for k in ('access_run_id', 'instance_id'))
            or ATTEMPT.fullmatch(raw['access_run_attempt']) is None
            or re.fullmatch(r'sprk-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}-instance', raw['instance_name']) is None):
        raise QualificationError('validate-authorization', 'representation-invalid')
    return dict(raw)


def admit_diagnostic(raw: object, *, authorization: dict[str, Any], binding: dict[str, str],
                     qualification_run_id: str, qualification_run_attempt: str,
                     host_evidence_sha256: str) -> dict[str, Any]:
    if (not isinstance(raw, dict) or set(raw) != set(bound_diagnostic('write-evidence', 'command-failed',
            authorization=None, binding=None, qualification_run_id='', qualification_run_attempt='',
            host_evidence_sha256=None, cleanup_complete=False))):
        raise QualificationError('admit-qualification', 'representation-invalid')
    expected = bound_diagnostic(raw['operation'], raw['reason'], authorization=authorization,
        binding=admit_resource_binding(binding), qualification_run_id=qualification_run_id,
        qualification_run_attempt=qualification_run_attempt, host_evidence_sha256=host_evidence_sha256,
        cleanup_complete=raw['cleanup_complete'])
    # Before source/host admission, null describes unobserved authority; it never
    # supports PASS. Observed bindings must agree with independent continuation.
    for name in ('authorization', 'host_evidence_sha256'):
        if raw[name] is None:
            expected[name] = None
    if raw['resource'] is None:
        if (raw['operation'] != 'validate-authorization' or raw['authorization'] is not None
                or raw['host_evidence_sha256'] is not None or raw['cleanup_complete'] is not False):
            raise QualificationError('admit-qualification', 'identity-mismatch')
        expected['resource'] = None
    if type(raw['cleanup_complete']) is not bool or canonical_bytes(raw) != canonical_bytes(expected):
        raise QualificationError('admit-qualification', 'identity-mismatch')
    return dict(raw)


def admit_evidence(document: object, *, authorization: dict[str, Any], instance_id: str,
                   instance_name: str, qualification_run_id: str, qualification_run_attempt: str,
                   host_evidence_sha256: str, declaration: object = DECLARATION) -> dict[str, Any]:
    fields = {'schema_version', 'claim', 'authorization', 'qualification_run_id', 'qualification_run_attempt',
              'instance_id', 'instance_name', 'architecture', 'host_admission', 'packages',
              'signer_fingerprint', 'observations', 'cleanup'}
    if not isinstance(document, dict) or set(document) != fields:
        raise QualificationError('admit-qualification', 'representation-invalid')
    expected = {'schema_version': 1, 'claim': SELECTOR, 'authorization': authorization,
                'instance_id': instance_id, 'instance_name': instance_name,
                'qualification_run_id': qualification_run_id, 'qualification_run_attempt': qualification_run_attempt,
                'architecture': rpm.PROFILE_ARCHITECTURES[authorization['profile']],
                'host_admission': {'target_sha': '402c22b0a1d69a5a3dba74ffb68cf016caba606b',
                                  'harness_sha256': '436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac',
                                  'evidence_sha256': host_evidence_sha256},
                'signer_fingerprint': rpm.ROCKY_FINGERPRINT, 'cleanup': CLEANUP_POSTCONDITIONS}
    if (not isinstance(instance_id, str) or RUN.fullmatch(instance_id) is None
            or not isinstance(instance_name, str) or re.fullmatch(r'sprk-[a-z0-9-]{1,55}-instance', instance_name) is None
            or RUN.fullmatch(qualification_run_id) is None or ATTEMPT.fullmatch(qualification_run_attempt) is None
            or DIGEST.fullmatch(host_evidence_sha256) is None
            or any(canonical_bytes(document[key]) != canonical_bytes(value) for key, value in expected.items())):
        raise QualificationError('admit-qualification', 'identity-mismatch')
    packages = document['packages']
    if not isinstance(packages, dict) or set(packages) != set(PACKAGES):
        raise QualificationError('observe-packages', 'representation-invalid')
    for name, raw in packages.items():
        package = admit_postgresql_package(name, raw, document['architecture'], document['signer_fingerprint'])
        pinned = admit_declaration(declaration)
        if package['version'] != pinned['package_version'] or package['release'] != pinned['package_release']:
            raise QualificationError('observe-packages', 'identity-mismatch')
    observations = admit_observations(document['observations'], run_id=qualification_run_id,
        run_attempt=qualification_run_attempt, expires_at=authorization['expires_at'])
    minor = int(admit_declaration(declaration)['package_version'].split('.')[1])
    if observations['server_version_num'] != str(180000 + minor):
        raise QualificationError('admit-qualification', 'identity-mismatch')
    return dict(document)
