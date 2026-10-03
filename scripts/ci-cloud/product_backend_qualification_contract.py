#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure closed normalization/admission/assembly for deployment#101 proof.

Canonical responsibility owner: SecPal/.github/docs/evidence-architecture-contract.md.
The guest observes; accepted-main control independently admits the same facts.
"""

import hashlib
import csv
import io
import json
import re

from product_backend_contract import BACKENDS, admit_policy_account
from types import SimpleNamespace
import rocky_preparation_contract as rpm

SELECTOR = 'product-backend-policy'
PROFILES = {'gcp-rocky-10-2-x86-64': 'x86_64', 'gcp-rocky-10-2-arm64': 'aarch64'}
SOURCES = {
    'backend_policy': 'scripts/product-backend-policy.py',
    'backend_contract': 'scripts/product_backend_contract.py',
    'backend_service': 'config/production/host-systemd/secpal-product-backend-policy.service',
    'backend_qualifier': 'scripts/ci-cloud/qualify-product-backends.py',
    'backend_qualification_contract': 'scripts/ci-cloud/product_backend_qualification_contract.py',
    'backend_control': 'scripts/ci-cloud/product-backend-qualification-control.py',
    'backend_wrapper': 'scripts/ci-cloud/run-product-backend-qualification.sh',
    'backend_api': 'config/production/quadlet/secpal-api.container',
    'backend_frontend': 'config/production/quadlet/secpal-frontend.container',
    'backend_edge_network': 'config/production/quadlet/secpal-edge.network',
    'backend_application_network': 'config/production/quadlet/secpal-application.network',
    'collector': 'scripts/ci-cloud/collect-rocky-preparation.py',
    'preparation_contract': 'scripts/ci-cloud/rocky_preparation_contract.py',
}
OPERATIONS = (
    'validate-authorization', 'require-clean-host', 'observe-cloud-identity',
    'install-packages', 'observe-packages', 'install-policy', 'observe-booleans',
    'configure-booleans', 'activate-policy', 'observe-selinux', 'observe-port-labels',
    'observe-effective-policy', 'observe-nftables', 'observe-runtime',
    'pull-product-images', 'install-quadlets', 'start-products', 'observe-products',
    'configure-haproxy', 'start-haproxy', 'observe-haproxy-identity',
    'observe-http-readiness', 'observe-unrelated-selinux-denial',
    'probe-unrelated-uid', 'configure-external-probe', 'probe-external-interface',
    'probe-startup-barrier', 'cleanup-host', 'observe-cleanup', 'write-evidence',
    'admit-evidence',
)
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
PACKAGES = ('haproxy', 'nftables', 'selinux-policy-targeted', 'container-selinux', 'podman', 'passt', 'setools-console')
NUMBER = re.compile(r'^[1-9][0-9]{0,19}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def unique_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('duplicate fields')
    return result


def source_digests(sources):
    if set(sources) != set(SOURCES) or any(type(v) is not bytes or not 0 < len(v) <= 262144 for v in sources.values()):
        raise ValueError('source closure')
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}


def manifest(control_sha, profile, run_id, run_attempt, sources):
    result = dict(schema_version=1, selector=SELECTOR, control_sha=control_sha,
                  profile=profile, run_id=run_id, run_attempt=run_attempt,
                  source_sha256=source_digests(sources))
    return admit_manifest(result, sources)


def admit_manifest(value, sources):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'selector', 'control_sha',
            'profile', 'run_id', 'run_attempt', 'source_sha256'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['selector'] != SELECTOR or value['profile'] not in PROFILES
            or not isinstance(value['control_sha'], str) or not SHA.fullmatch(value['control_sha'])
            or any(not isinstance(value[k], str) or not NUMBER.fullmatch(value[k]) for k in ('run_id', 'run_attempt'))
            or len(value['run_attempt']) > 3 or value['source_sha256'] != source_digests(sources)):
        raise ValueError('accepted source authorization mismatch')
    return value


def required_observations():
    return {
        'selinux': 'Enforcing', 'backend_port_type': 'secpal_backend_port_t',
        'haproxy_domain': 'haproxy_t', 'runtime_bind_domain': 'container_runtime_t',
        'haproxy_connect_any': False, 'pasta_bind_all_ports': False,
        'effective_backend_connect': True, 'effective_runtime_bind': True,
        'effective_unreserved_connect': False, 'actual_unrelated_haproxy_access': False,
        'nft_rules_installed': True, 'haproxy_http_ready': True,
        'unrelated_uid_access': False, 'external_interface_access': False,
        'ipv6_backend_access': False, 'fixed_endpoint_recreation': True,
        'wildcard_product_bind': False, 'host_networking': False,
        'runtime_api_dependency': False, 'frontend_private_authority': False,
        'startup_barrier_refusal': True, 'host_cleanup_complete': True,
        'root_excluded_from_isolation': True,
    }


def admit_evidence(value, binding, source_sha256):
    fields = {'schema_version', 'selector', 'binding', 'source_sha256', 'observations',
              'haproxy_uid', 'runtime_uid', 'unrelated_uid', 'records', 'packages', 'rocky_signing_key', 'host_evidence_sha256'}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['selector'] != SELECTOR or value['binding'] != binding
            or value['source_sha256'] != source_sha256
            or not isinstance(value['observations'], dict)
            or canonical(value['observations']) != canonical(required_observations())):
        raise ValueError('closed effective proof mismatch')
    if (not isinstance(value['host_evidence_sha256'], str) or not DIGEST.fullmatch(value['host_evidence_sha256'])
            or not isinstance(value['packages'], list) or [p.get('name') for p in value['packages']] != list(PACKAGES)):
        raise ValueError('host and package observation identity')
    signer = rpm.admit_rocky_signing_key(rpm.normalize_rocky_signing_key(value['rocky_signing_key']))
    architecture = PROFILES[binding['profile']]
    for package in value['packages']:
        fact = rpm.normalize_installed_package(package['name'], package, architecture)
        rpm.admit_package(fact, signer, architecture)
    normalize_observations(value['records'], value['haproxy_uid'], value['runtime_uid'], value['unrelated_uid'])
    ids = [value[k] for k in ('haproxy_uid', 'runtime_uid', 'unrelated_uid')]
    if any(type(uid) is not int or not 1 <= uid < 2**32 - 1 for uid in ids) or len(set(ids)) != 3 or ids[0] >= 1000:
        raise ValueError('dedicated service identity mismatch')
    return value


def diagnostic(operation, reason, cleanup_complete):
    if operation not in OPERATIONS or reason not in ('command-failed', 'identity-mismatch', 'representation-invalid', 'invariant-failed', 'observation-limit-exceeded') or type(cleanup_complete) is not bool:
        raise ValueError('unclassified trusted operation')
    return dict(schema_version=1, selector=SELECTOR, operation=operation,
                reason=reason, host_cleanup_complete=cleanup_complete)


def fixture_unit(source, role):
    """Transport-only adaptation of accepted product units, never caller data.

    Publication, image, rootless hardening and separate role networks remain
    owned by the production renderer and product_backend_contract.
    """
    if role not in BACKENDS or source.count(BACKENDS[role].publication + '\n') != 1:
        raise ValueError('reviewed product publication')
    lines = [line for line in source.splitlines() if not line.startswith((
        'Requires=', 'After=', 'PartOf=', 'ExecStartPre=', 'Environment=',
        'Mount=type=bind,', 'Health', 'Notify=', 'LogDriver=', 'LogOpt='))]
    lines.insert(lines.index('Pull=never'), 'Notify=conmon')
    lines.insert(lines.index('Pull=never'), 'LogDriver=none')
    lines.insert(lines.index('[Service]') + 1,
                 'ExecStartPre=/usr/bin/python3 -I /usr/local/libexec/secpal/product-backend-policy --check')
    environment = (['APP_ENV=production', 'APP_DEBUG=false',
                    'APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
                    'CACHE_STORE=file', 'SESSION_DRIVER=array', 'LOG_CHANNEL=stderr']
                   if role == 'api' else ['SECPAL_API_URL=https://api.secpal.example.invalid'])
    for value in environment:
        lines.insert(lines.index('Pull=never'), 'Environment=' + value)
    return ('\n'.join(lines) + '\n').replace('secpal-', 'secpal-backend101-')


def admit_nftables(raw, uid):
    """Trust-boundary agreement with product_backend_contract.host_policy.

    Normalize the reviewed nft JSON representation, removing kernel handles.
    Agreement evidence compiles the owner's nft input through the real kernel.
    """
    if not isinstance(raw, dict) or set(raw) != {'nftables'} or not isinstance(raw['nftables'], list):
        raise ValueError('nft representation')
    entries = []
    for entry in raw['nftables']:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('nft representation')
        kind, value = next(iter(entry.items()))
        if kind == 'metainfo':
            if not isinstance(value, dict) or value.get('json_schema_version') != 1:
                raise ValueError('nft JSON version')
            continue
        if kind not in ('table', 'chain', 'rule') or not isinstance(value, dict):
            raise ValueError('unknown nft authority')
        entries.append({kind: {key: item for key, item in value.items() if key != 'handle'}})
    if canonical(entries) != canonical(nft_projection(uid)):
        raise ValueError('installed nft policy differs from canonical owner')
    return True


def nft_projection(uid):
    """Independent trust-boundary projection; live owner agreement is tested."""
    table = dict(family='inet', table='secpal_product_backends')
    expected = [{'table': dict(family='inet', name='secpal_product_backends')}]
    for name, hook in (('backend_input', 'input'), ('backend_output', 'output')):
        expected.append({'chain': dict(**table, name=name, type='filter', hook=hook, prio=-20, policy='accept')})
    def match(left, right, op='=='):
        return {'match': dict(op=op, left=left, right=right)}
    def payload(protocol, field):
        return {'payload': dict(protocol=protocol, field=field)}
    ports = match(payload('tcp', 'dport'), {'set': [b.host_port for b in BACKENDS.values()]})
    def reject(kind):
        return {'reject': dict(type=kind, expr='port-unreachable')}
    rules = (
        ('backend_input', [match({'meta': {'key': 'iifname'}}, 'lo', '!='), ports, reject('icmpx')]),
        ('backend_output', [match(payload('ip', 'daddr'), '127.0.0.1'), ports, match({'meta': {'key': 'skuid'}}, uid), {'accept': None}]),
        ('backend_output', [match(payload('ip', 'daddr'), {'prefix': {'addr': '127.0.0.0', 'len': 8}}), ports, reject('icmp')]),
        ('backend_output', [match(payload('ip6', 'daddr'), '::1'), ports, reject('icmpv6')]),
    )
    expected.extend({'rule': dict(**table, chain=chain, expr=expressions)} for chain, expressions in rules)
    return expected

def properties(text):
    rows = [line.split('=', 1) for line in text.splitlines()]
    if not rows or any(len(row) != 2 for row in rows) or len(dict(rows)) != len(rows):
        raise ValueError('systemd property representation')
    return dict(rows)


def normalize_observations(raw, haproxy_uid, runtime_uid, unrelated_uid):
    """Independently admit bounded observed representations, never PASS flags."""
    fields = {'enforcing', 'booleans', 'portcons', 'av', 'nftables', 'recreations', 'haproxy',
              'unrelated', 'external', 'barrier', 'cleanup', 'accounts'}
    if not isinstance(raw, dict) or set(raw) != fields or len(canonical(raw)) > 100000:
        raise ValueError('closed effective observations')
    accounts = raw['accounts']
    if (set(accounts) != {'haproxy', 'runtime', 'unrelated'} or set(accounts['haproxy']) != {'name', 'uid', 'gid', 'shell'}
            or accounts['haproxy']['name'] != 'haproxy' or accounts['haproxy']['uid'] != haproxy_uid
            or accounts['runtime'] != {'name': 'secpal-runtime', 'uid': runtime_uid}
            or accounts['unrelated'] != {'name': 'secpal-cloud', 'uid': unrelated_uid}):
        raise ValueError('observed service account identity')
    admit_policy_account(SimpleNamespace(pw_name=accounts['haproxy']['name'], pw_uid=haproxy_uid,
                         pw_gid=accounts['haproxy']['gid'], pw_shell=accounts['haproxy']['shell']), runtime_uid)
    if raw['enforcing'] != 'Enforcing' or raw['booleans'] != ['haproxy_connect_any --> off', 'pasta_bind_all_ports --> off']:
        raise ValueError('enforcing narrow policy')
    if set(raw['portcons']) != set(BACKENDS):
        raise ValueError('exact port labels')
    for role, backend in BACKENDS.items():
        if not re.search(r'portcon tcp ' + str(backend.host_port) + r' system_u:object_r:secpal_backend_port_t:s0(?:\s|$)', raw['portcons'][role]):
            raise ValueError('effective backend port type')
    expected_av = [('haproxy_t', 'secpal_backend_port_t', 'name_connect', True),
                   ('container_runtime_t', 'secpal_backend_port_t', 'name_bind', True),
                   ('haproxy_t', 'unreserved_port_t', 'name_connect', False)]
    if not isinstance(raw['av'], list) or len(raw['av']) != 3:
        raise ValueError('effective AV representation')
    for fact, (source, target, permission, allowed) in zip(raw['av'], expected_av):
        if set(fact) != {'source', 'target', 'permission', 'decision'} or (fact['source'], fact['target'], fact['permission']) != (source, target, permission):
            raise ValueError('effective AV identity')
        decision = fact['decision']
        if (set(decision) != {'class', 'requested', 'result', 'allowed', 'decided', 'flags'}
                or any(type(value) is not int or value < 0 for value in decision.values())
                or not decision['class'] or not decision['requested'] or decision['result'] != 0
                or decision['flags'] != 0 or decision['decided'] & decision['requested'] != decision['requested']
                or (decision['allowed'] & decision['requested'] == decision['requested']) != allowed):
            raise ValueError('effective non-permissive AV decision')
    admit_nftables(raw['nftables'], haproxy_uid)
    hp = raw['haproxy']
    if set(hp) != {'unit', 'package_owners', 'processes', 'all_pids', 'stats_inode', 'stats_holders'}:
        raise ValueError('HAProxy service representation')
    unit = properties(hp['unit'])
    if (set(unit) != {'FragmentPath', 'DropInPaths', 'ExecStart', 'ControlGroup', 'ActiveState', 'Result'}
            or unit['FragmentPath'] != '/usr/lib/systemd/system/haproxy.service' or unit['DropInPaths']
            or 'path=/usr/sbin/haproxy ;' not in unit['ExecStart']
            or unit['ControlGroup'] != '/system.slice/haproxy.service'
            or unit['ActiveState'] != 'active' or unit['Result'] != 'success'
            or hp['package_owners'] != ['haproxy', 'haproxy']):
        raise ValueError('packaged HAProxy service authority')
    processes = hp['processes']
    if not isinstance(processes, list) or not 1 <= len(processes) <= 16:
        raise ValueError('HAProxy worker cardinality')
    pids, workers = set(), set()
    for process in processes:
        if (set(process) != {'pid', 'uids', 'context', 'exe', 'cgroup'} or type(process['pid']) is not int or process['pid'] <= 0
                or process['pid'] in pids or not isinstance(process['uids'], list) or len(process['uids']) != 4
                or any(type(value) is not int for value in process['uids'])
                or process['uids'][1] not in (0, haproxy_uid) or ':haproxy_t:' not in process['context']
                or process['exe'] != '/usr/sbin/haproxy' or process['cgroup'] != '0::/system.slice/haproxy.service'):
            raise ValueError('actual HAProxy worker identity')
        pids.add(process['pid'])
        if process['uids'][1] == haproxy_uid:
            workers.add(process['pid'])
    if (not workers or sorted(pids) != sorted(hp['all_pids']) or type(hp['stats_inode']) is not int or hp['stats_inode'] <= 0
            or not hp['stats_holders'] or not set(hp['stats_holders']) <= pids):
        raise ValueError('HAProxy stats socket service binding')
    if not isinstance(raw['recreations'], list) or len(raw['recreations']) != 3:
        raise ValueError('native recreation evidence')
    for iteration in raw['recreations']:
        if set(iteration) != {'products', 'runtime', 'http_stats'} or set(iteration['products']) != set(BACKENDS):
            raise ValueError('product iteration representation')
        runtime = iteration['runtime']
        if (set(runtime) != {'host', 'unit_states', 'manager_override_keys', 'enforcing', 'booleans'} or runtime['host']['security']['rootless'] is not True
                or runtime['host']['serviceIsRemote'] is not False or runtime['manager_override_keys'] != []
                or runtime['enforcing'] != 'Enforcing' or runtime['booleans'] != ['haproxy_connect_any --> off', 'pasta_bind_all_ports --> off']
                or runtime['unit_states'] != ['inactive', 'inactive', 'inactive', 'inactive']):
            raise ValueError('local rootless runtime without API authority')
        for role, backend in BACKENDS.items():
            product = iteration['products'][role]
            if (set(product) != {'listeners', 'forwarder_context', 'container_context', 'network_mode', 'networks', 'environment_keys', 'mount_types', 'unit'}
                    or product['listeners'] != [backend.endpoint] or ':container_runtime_t:' not in product['forwarder_context']
                    or ':container_t:' not in product['container_context'] or product['network_mode'] == 'host'):
                raise ValueError('exact rootless product listener')
            generated = properties(product['unit'])
            if (set(generated) != {'FragmentPath', 'SourcePath', 'DropInPaths', 'ExecStart', 'ExecStartPre'}
                    or generated['SourcePath'] != f'/etc/containers/systemd/users/{runtime_uid}/secpal-backend101-{role}.container'
                    or not generated['FragmentPath'].startswith(f'/run/user/{runtime_uid}/systemd/generator/')
                    or generated['DropInPaths'] or 'path=/usr/bin/podman ;' not in generated['ExecStart']
                    or backend.endpoint + ':8080/tcp' not in generated['ExecStart']
                    or any(value in generated['ExecStart'] for value in ('--network host', '--network=host', '--privileged', 'label=disable', 'podman.sock', 'docker.sock'))
                    or '/usr/local/libexec/secpal/product-backend-policy --check' not in generated['ExecStartPre']):
                raise ValueError('effective Quadlet authority')
            if role == 'frontend' and (product['networks'] != ['secpal-backend101-edge']
                    or any(key.startswith(('DB_', 'AWS_', 'APP_KEY', 'SECPAL_SECRET_', 'FILESYSTEM_')) for key in product['environment_keys'])
                    or 'bind' in product['mount_types']):
                raise ValueError('frontend private authority')
        rows = list(csv.DictReader(io.StringIO(iteration['http_stats'].removeprefix('# '))))
        for role in BACKENDS:
            selected = [row for row in rows if row['pxname'] == 'secpal_' + role and row['svname'] == role]
            if len(selected) != 1 or any(selected[0][key] != expected for key, expected in (('status', 'UP'), ('check_status', 'L7OK'), ('check_code', '200'))):
                raise ValueError('actual HAProxy HTTP readiness')
    unrelated = raw['unrelated']
    if set(unrelated) != {'local_statuses', 'ipv6_statuses', 'positive_http_code', 'avc'} or any(type(v) is not int or v not in (7, 28, 52, 56) for v in unrelated['local_statuses'] + unrelated['ipv6_statuses']) or len(unrelated['local_statuses']) != 2 or len(unrelated['ipv6_statuses']) != 2 or unrelated['positive_http_code'] != '200':
        raise ValueError('effective unrelated access denial')
    avc = unrelated['avc']
    pid = re.search(r'\bpid=([1-9][0-9]*)\b', avc)
    if (not pid or int(pid.group(1)) not in workers or any(value not in avc for value in ('denied', 'name_connect', 'dest=18082', ':haproxy_t:', ':unreserved_port_t:'))):
        raise ValueError('unrelated HAProxy effective SELinux denial')
    if set(raw['external']) != set(BACKENDS):
        raise ValueError('external probe representation')
    for probe in raw['external'].values():
        if set(probe) != {'positive_http_code', 'ingress_status'} or probe['positive_http_code'] != '200' or type(probe['ingress_status']) is not int or probe['ingress_status'] not in (7, 28, 52, 56):
            raise ValueError('effective external nft denial')
    if raw['barrier'] != {'missing_start_status': 1, 'stale_start_status': 1, 'missing_pre_status': 1, 'stale_pre_status': 1}:
        raise ValueError('mandatory missing/stale startup barrier')
    admit_cleanup(raw['cleanup'])
    return required_observations()


def admit_cleanup(raw):
    fields = {'remaining_paths', 'remaining_containers', 'remaining_networks', 'remaining_images', 'service_states',
              'runtime_unit_states', 'nft_table_status', 'module_names', 'netns_names', 'link_names', 'listeners',
              'haproxy_config_sha256', 'original_haproxy_config_sha256', 'pasta_boolean', 'original_pasta_boolean'}
    if (not isinstance(raw, dict) or set(raw) != fields
            or any(raw[key] != [] for key in ('remaining_paths', 'remaining_containers', 'remaining_networks', 'remaining_images', 'module_names', 'netns_names', 'link_names', 'listeners'))
            or raw['service_states'] != ['inactive', 'inactive'] or raw['runtime_unit_states'] != ['inactive'] * 4
            or type(raw['nft_table_status']) is not int or raw['nft_table_status'] != 1
            or not isinstance(raw['haproxy_config_sha256'], str) or not DIGEST.fullmatch(raw['haproxy_config_sha256'])
            or raw['haproxy_config_sha256'] != raw['original_haproxy_config_sha256']
            or raw['pasta_boolean'] not in ('pasta_bind_all_ports --> on', 'pasta_bind_all_ports --> off')
            or raw['pasta_boolean'] != raw['original_pasta_boolean']):
        raise ValueError('effective complete host cleanup')
    return True
