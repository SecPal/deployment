#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Closed #220 decoder isolation; #101 continues to own product backends."""

import hashlib
import json
import ipaddress

from haproxy_direct_contract import Direct, DECODER_PORTS


def host_policy(spec, uid):
    if type(spec) is not Direct or spec.topology != 'ha' or type(uid) is not int or not 0 < uid < 1000:
        raise ValueError('admit-direct-policy-identity')
    ports = ', '.join(str(port) for port in DECODER_PORTS.values())
    ingress, local = [], []
    for row in spec.listeners:
        family = 'ip6' if ':' in row.socket.address else 'ip'
        probe = '::1' if family == 'ip6' else '127.0.0.1'
        peers = [value for value in row.trusted_peers if (':' in value) == (family == 'ip6')]
        peers = sorted(set(peers + [probe]), key=ipaddress.ip_address)
        selector = f'{family} daddr {row.socket.address} tcp dport {row.socket.port}'
        ingress.append(f'    iifname != \"lo\" {selector} {family} saddr != {{ {", ".join(peers)} }} reject')
        # Every local caller is UID-bound, including one able to bind an
        # allowlisted loopback source. Remote peers traverse input, not output.
        local.append(f'    {selector} meta skuid != {{ 0, {uid} }} reject')
    nft = f'''table inet secpal_direct {{
  chain decoder_input {{
    type filter hook input priority -21; policy accept;
    iifname != "lo" tcp dport {{ {ports} }} reject
{chr(10).join(ingress)}
  }}
  chain decoder_output {{
    type filter hook output priority -21; policy accept;
    ip daddr 127.0.0.0/8 tcp dport {{ {ports} }} meta skuid != {{ 0, {uid} }} reject
    ip6 daddr ::1 tcp dport {{ {ports} }} reject
{chr(10).join(local)}
  }}
}}
'''
    cil = '''(type secpal_direct_decoder_port_t)
(typeattributeset port_type (secpal_direct_decoder_port_t))
(roletype object_r secpal_direct_decoder_port_t)
(allow haproxy_t secpal_direct_decoder_port_t (tcp_socket (name_bind name_connect)))
'''
    cil += ''.join(f'(portcon tcp {port} (system_u object_r secpal_direct_decoder_port_t ((s0) (s0))))\n'
                   for port in DECODER_PORTS.values())
    return {'nft': nft, 'cil': cil}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normalize_table(document):
    # Native nft JSON owns rule semantics. Remove observation-only metadata,
    # never rule expressions, order, UID selectors, hooks or verdicts.
    if type(document) is not dict or set(document) != {'nftables'} or type(document['nftables']) is not list:
        raise ValueError('admit-direct-table-observation')
    result = []
    for row in document['nftables']:
        if type(row) is not dict or len(row) != 1:
            raise ValueError('admit-direct-table-entry')
        kind, value = next(iter(row.items()))
        if kind == 'metainfo':
            if type(value) is not dict or value.get('json_schema_version') != 1:
                raise ValueError('admit-direct-table-version')
            continue
        if kind not in ('table', 'chain', 'rule') or type(value) is not dict:
            raise ValueError('admit-direct-table-authority')
        result.append({kind: {key: item for key, item in value.items() if key != 'handle'}})
    return result


def table_projection(spec, uid):
    """Independent native-JSON projection; real-kernel agreement is required."""
    host_policy(spec, uid)  # Consume the typed admission owner.
    table = {'family': 'inet', 'table': 'secpal_direct'}
    result = [{'table': {'family': 'inet', 'name': 'secpal_direct'}}]
    for name, hook in (('decoder_input', 'input'), ('decoder_output', 'output')):
        result.append({'chain': dict(**table, name=name, type='filter', hook=hook, prio=-21, policy='accept')})
    def match(left, right, op='=='):
        return {'match': {'op': op, 'left': left, 'right': right}}
    def payload(protocol, field):
        return {'payload': {'protocol': protocol, 'field': field}}
    def reject(family):
        return {'reject': {'type': family, 'expr': 'port-unreachable'}}
    def rule(chain, expressions):
        result.append({'rule': dict(**table, chain=chain, expr=expressions)})
    ports = match(payload('tcp', 'dport'), {'set': list(DECODER_PORTS.values())})
    owner = match({'meta': {'key': 'skuid'}}, {'set': [0, uid]}, '!=')
    rule('decoder_input', [match({'meta': {'key': 'iifname'}}, 'lo', '!='), ports, reject('icmpx')])
    for row in spec.listeners:
        family = 'ip6' if ':' in row.socket.address else 'ip'
        probe = '::1' if family == 'ip6' else '127.0.0.1'
        peers = sorted(set([value for value in row.trusted_peers if (':' in value) == (family == 'ip6')] + [probe]), key=ipaddress.ip_address)
        rule('decoder_input', [match({'meta': {'key': 'iifname'}}, 'lo', '!='), match(payload(family, 'daddr'), str(ipaddress.ip_address(row.socket.address))),
            match(payload('tcp', 'dport'), row.socket.port),
            match(payload(family, 'saddr'), peers[0] if len(peers) == 1 else {'set': peers}, '!='),
            reject('icmpv6' if family == 'ip6' else 'icmp')])
    rule('decoder_output', [match(payload('ip', 'daddr'), {'prefix': {'addr': '127.0.0.0', 'len': 8}}),
         ports, owner, reject('icmp')])
    rule('decoder_output', [match(payload('ip6', 'daddr'), '::1'), ports, reject('icmpv6')])
    for row in spec.listeners:
        family = 'ip6' if ':' in row.socket.address else 'ip'
        rule('decoder_output', [match(payload(family, 'daddr'), str(ipaddress.ip_address(row.socket.address))),
            match(payload('tcp', 'dport'), row.socket.port), owner, reject('icmpv6' if family == 'ip6' else 'icmp')])
    return result


def admit_table(document, spec, uid):
    if normalize_table(document) != table_projection(spec, uid):
        raise ValueError('admit-effective-direct-table')
