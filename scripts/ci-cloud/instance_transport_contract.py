# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure representation, admission and assembly for diagnostic TCP observations.

Canonical evidence architecture: SecPal/.github/docs/evidence-architecture-contract.md.
This module owns transport invariants; it owns no provider or cleanup authority.
"""
from __future__ import annotations

import ipaddress
import json
import struct

from jsonschema import Draft202012Validator

RESPONSIBILITY = 'normalization,admission,assembly'
MAX_DOCUMENT_BYTES = 131072
MAX_CONNECTIONS = 64
MAX_WINDOW_NS = 3600_000_000_000
MAX_COUNTER = (1 << 63) - 1
OPERATIONS = ('NONE','UNKNOWN','OPEN_DIAGNOSTIC_SOCKET','BOUND_DIAGNOSTIC_BUFFER',
              'ADMIT_NOTIFICATION_SCOPE','SUBSCRIBE_SOCKET_DESTRUCTION',
              'VERIFY_PROCESS_IDENTITY','CORRELATE_PROVIDER_PROCESS',
              'VERIFY_NETWORK_NAMESPACE','CORRELATE_PROVIDER_SOCKET',
              'QUERY_TCP_COUNTERS','NORMALIZE_SOCKET_METADATA',
              'FOLD_COUNTER_OBSERVATIONS','RECEIVE_FINAL_COUNTERS',
              'FINALIZE_OBSERVATION')
IDENTITY_FIELDS = ('repository', 'trusted_control_sha', 'target_sha',
                   'workflow_run_id', 'workflow_run_attempt', 'provider_profile',
                   'project', 'zone', 'expected_instance_name')
STATES = {1:'ESTABLISHED', 2:'SYN_SENT', 3:'SYN_RECV', 4:'FIN_WAIT1',
          5:'FIN_WAIT2', 6:'TIME_WAIT', 7:'CLOSE', 8:'CLOSE_WAIT',
          9:'LAST_ACK', 10:'LISTEN', 11:'CLOSING', 12:'NEW_SYN_RECV',
          13:'BOUND_INACTIVE'}
ESTABLISHED_STATES = {'ESTABLISHED','FIN_WAIT1','FIN_WAIT2','TIME_WAIT',
                      'CLOSE_WAIT','LAST_ACK','CLOSING'}


class TransportError(ValueError):
    pass


def schema():
    """Authoritative closed shape, also exported as the independently checked schema."""
    counter = {'type':'integer','minimum':0,'maximum':MAX_COUNTER}
    timestamp = dict(counter)
    positive = {'type':'integer','minimum':1,'maximum':MAX_COUNTER}
    state = {'enum':list(STATES.values())}
    snapshot_fields = {'at':timestamp, 'state':state, 'bytes_sent':counter,
                       'bytes_received':counter, 'retransmissions':counter}
    connection_fields = {
        'ordinal':{'type':'integer','minimum':1,'maximum':MAX_CONNECTIONS},
        'process_id':positive, 'process_start_ticks':counter,
        'socket_cookie':{'type':'string','pattern':'^[0-9a-f]{16}$'},
        'local_address':{'type':'string','minLength':2,'maxLength':45},
        'remote_address':{'type':'string','minLength':2,'maxLength':45},
        'local_port':{'type':'integer','minimum':1,'maximum':65535},
        'remote_port':{'const':443},
        'first':{'$ref':'#/$defs/snapshot'}, 'last':{'$ref':'#/$defs/snapshot'},
        'sample_count':{'type':'integer','minimum':1,'maximum':100000},
        'max_sample_gap_ns':{'type':'integer','minimum':0,'maximum':MAX_WINDOW_NS},
        'states_seen':{'type':'array','minItems':1,'maxItems':len(STATES),
                       'uniqueItems':True,'items':state},
        'last_send_increase_sample':{'anyOf':[timestamp,{'type':'null'}]},
        'last_receive_increase_sample':{'anyOf':[timestamp,{'type':'null'}]},
        'final_snapshot_kind':{'enum':['LIVE_SOCKET','DESTROY_NOTIFICATION',
                                      'NO_DESTROY_NOTIFICATION_OBSERVED']},
        'secure_transport_progress':{'const':'UNKNOWN'},
        'http_request_attribution':{'const':'UNKNOWN'},
        'reset_origin':{'const':'UNKNOWN'},
        'fin_observation':{'enum':['PEER_FIN_OBSERVED','LOCAL_FIN_OBSERVED','BOTH_FIN_OBSERVED','UNKNOWN']},
    }
    properties = {
        'schema_version':{'const':1},
        'kind':{'const':'INSTANCE_INSERT_TRANSPORT_EVIDENCE'},
        'collector':{'const':'LINUX_EXACT_INET_DIAG_TCP_INFO_V1'},
        'repository':{'const':'SecPal/deployment'},
        'trusted_control_sha':{'type':'string','pattern':'^[0-9a-f]{40}$'},
        'target_sha':{'type':'string','pattern':'^[0-9a-f]{40}$'},
        'workflow_run_id':{'type':'string','pattern':'^[1-9][0-9]{0,19}$'},
        'workflow_run_attempt':{'type':'string','pattern':'^[1-9][0-9]{0,2}$'},
        'provider_profile':{'enum':['gcp-rocky-10-2-arm64','gcp-rocky-10-2-x86-64']},
        'project':{'const':'secpal-dev'}, 'zone':{'const':'europe-west3-a'},
        'expected_instance_name':{'type':'string','pattern':'^sprk-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}-instance$'},
        'opentofu_version':{'const':'1.12.5'}, 'google_provider_version':{'const':'7.40.0'},
        'observation_start':timestamp, 'observation_end':timestamp,
        'collection_status':{'enum':['COMPLETE','UNAVAILABLE','FAILED_STARTUP',
                                     'FAILED_RUNTIME','FAILED_SHUTDOWN','LIMIT_EXCEEDED']},
        'failure_operation':{'enum':list(OPERATIONS)},
        'visibility':{'const':'SAMPLED_SOCKETS_WITH_FILTERED_DESTRUCTION'},
        'dns_completion':{'const':'UNKNOWN'},
        'endpoint_observation':{'enum':['NUMERIC_TCP_ENDPOINT_OBSERVED','UNKNOWN']},
        'connection_progress':{'enum':['TCP_ESTABLISHMENT_OBSERVED','SYN_SENT_OBSERVED','UNKNOWN']},
        'terminal_provider_result':{'enum':['SUCCESS','OTHER','NOT_RUN']},
        'provider_exit_code':{'anyOf':[{'type':'integer','minimum':-255,'maximum':255},{'type':'null'}]},
        'connections':{'type':'array','maxItems':MAX_CONNECTIONS,'items':{'$ref':'#/$defs/connection'}},
    }
    closed = lambda fields: {'type':'object','additionalProperties':False,
                             'required':list(fields),'properties':fields}
    return {'$schema':'https://json-schema.org/draft/2020-12/schema',
            '$comment':'SPDX-FileCopyrightText: 2026 SecPal Contributors; SPDX-License-Identifier: MIT',
            'title':'Diagnostic Rocky instance insertion TCP observations',
            **closed(properties), '$defs':{'snapshot':closed(snapshot_fields),
                                          'connection':closed(connection_fields)}}


def unique_object(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise TransportError('duplicate document member')
        result[key] = value
    return result


def decode_document(raw):
    if not isinstance(raw,bytes) or len(raw)>MAX_DOCUMENT_BYTES:
        raise TransportError('document size bound exceeded')
    try:
        return json.loads(raw,object_pairs_hook=unique_object)
    except (ValueError,UnicodeError,RecursionError) as error:
        raise TransportError('invalid transport document') from error


def normalize_diag(body, at):
    """Linux inet_diag_msg/TCP_INFO UAPI -> typed counters. No application data."""
    if not isinstance(body,bytes) or not 72<=len(body)<=4096:
        raise TransportError('invalid diagnostic size')
    family,state = body[:2]
    if family not in (2,10) or state not in STATES:
        raise TransportError('unsupported socket representation')
    local_port,remote_port = struct.unpack_from('!HH',body,4)
    size = 4 if family==2 else 16
    local = str(ipaddress.ip_address(body[8:8+size]))
    remote = str(ipaddress.ip_address(body[24:24+size]))
    cookie = struct.unpack_from('=II',body,44)
    tcp_info = None
    offset = 72
    while offset<len(body):
        if offset+4>len(body):
            raise TransportError('short diagnostic attribute')
        length,kind = struct.unpack_from('=HH',body,offset)
        if length<4 or offset+length>len(body):
            raise TransportError('invalid diagnostic attribute')
        if kind==2:
            if tcp_info is not None:
                raise TransportError('duplicate TCP_INFO')
            tcp_info = body[offset+4:offset+length]
        offset += (length+3)&~3
    if offset!=len(body):
        raise TransportError('diagnostic attribute padding rejected')
    if tcp_info is None or len(tcp_info)<216 or tcp_info[0]!=state:
        raise TransportError('TCP_INFO unavailable or inconsistent')
    snapshot = {'at':at,'state':STATES[state],
                'bytes_sent':struct.unpack_from('=Q',tcp_info,200)[0],
                'bytes_received':struct.unpack_from('=Q',tcp_info,128)[0],
                'retransmissions':struct.unpack_from('=I',tcp_info,100)[0]}
    return {'family':family,'local_address':local,'remote_address':remote,
            'local_port':local_port,'remote_port':remote_port,
            'inode':struct.unpack_from('=I',body,68)[0],
            'cookie_words':cookie,'socket_cookie':''.join(f'{word:08x}' for word in cookie),
            'snapshot':snapshot}


def fin_observation(states):
    peer = bool(set(states)&{'CLOSE_WAIT','LAST_ACK','CLOSING'})
    local = bool(set(states)&{'FIN_WAIT1','FIN_WAIT2','LAST_ACK','CLOSING','TIME_WAIT'})
    return 'BOTH_FIN_OBSERVED' if peer and local else 'PEER_FIN_OBSERVED' if peer else 'LOCAL_FIN_OBSERVED' if local else 'UNKNOWN'


def connection_progress(connections):
    states = {state for connection in connections for state in connection['states_seen']}
    return 'TCP_ESTABLISHMENT_OBSERVED' if states & ESTABLISHED_STATES else 'SYN_SENT_OBSERVED' if 'SYN_SENT' in states else 'UNKNOWN'


def new_connection(raw, pid, ticks, ordinal):
    return {key:raw[key] for key in ('local_address','remote_address','local_port',
                                    'remote_port','socket_cookie')} | {
        'ordinal':ordinal,'process_id':pid,'process_start_ticks':ticks,
        'first':dict(raw['snapshot']),'last':dict(raw['snapshot']),
        'sample_count':1,'max_sample_gap_ns':0,
        'states_seen':[raw['snapshot']['state']],
        'last_send_increase_sample':None,'last_receive_increase_sample':None,
        'final_snapshot_kind':'LIVE_SOCKET','secure_transport_progress':'UNKNOWN',
        'http_request_attribution':'UNKNOWN','reset_origin':'UNKNOWN',
        'fin_observation':fin_observation([raw['snapshot']['state']])}


def add_sample(connection, snapshot, kind):
    """Pure bounded fold; no synthetic events and no wall-clock interpretation."""
    previous = connection['last']
    if snapshot['at']<previous['at']:
        raise TransportError('nonmonotonic observations')
    for counter in ('bytes_sent','bytes_received','retransmissions'):
        if snapshot[counter]<previous[counter]:
            raise TransportError('counter regressed')
    for counter,field in (('bytes_sent','last_send_increase_sample'),
                          ('bytes_received','last_receive_increase_sample')):
        if snapshot[counter]>previous[counter]:
            connection[field] = snapshot['at']
    connection['max_sample_gap_ns'] = max(connection['max_sample_gap_ns'],snapshot['at']-previous['at'])
    connection['sample_count'] += 1
    connection['last'] = dict(snapshot)
    connection['states_seen'] = sorted(set(connection['states_seen'])|{snapshot['state']})
    connection['final_snapshot_kind'] = kind
    connection['fin_observation'] = fin_observation(connection['states_seen'])


def assemble(identity,start,end,status,result,exit_code,connections,failure_operation=None):
    """Construct from supplied observations; admission remains a separate surface."""
    return dict(identity, schema_version=1,kind='INSTANCE_INSERT_TRANSPORT_EVIDENCE',
                collector='LINUX_EXACT_INET_DIAG_TCP_INFO_V1',opentofu_version='1.12.5',
                google_provider_version='7.40.0',observation_start=start,observation_end=end,
                collection_status=status,
                failure_operation=failure_operation or ('NONE' if status=='COMPLETE' else 'UNKNOWN'),
                visibility='SAMPLED_SOCKETS_WITH_FILTERED_DESTRUCTION',
                dns_completion='UNKNOWN',
                endpoint_observation='NUMERIC_TCP_ENDPOINT_OBSERVED' if connections else 'UNKNOWN',
                connection_progress=connection_progress(connections),
                terminal_provider_result=result,
                provider_exit_code=exit_code,connections=connections)


def admit(document,expected_identity):
    """Sole transport invariant owner; external admission reuses this pure surface."""
    if not isinstance(document,dict) or len(json.dumps(document).encode())>MAX_DOCUMENT_BYTES:
        raise TransportError('document size bound exceeded')
    if any(Draft202012Validator(schema()).iter_errors(document)):
        raise TransportError('closed transport shape rejected')
    if set(expected_identity)!=set(IDENTITY_FIELDS) or any(document[key]!=expected_identity[key] for key in IDENTITY_FIELDS):
        raise TransportError('transport identity mismatch')
    expected_name = f"sprk-{document['workflow_run_id']}-{document['workflow_run_attempt']}-instance"
    if document['expected_instance_name']!=expected_name:
        raise TransportError('instance identity mismatch')
    if (document['collection_status']=='COMPLETE') != (document['failure_operation']=='NONE'):
        raise TransportError('collection failure identity inconsistent')
    start,end = document['observation_start'],document['observation_end']
    if not start<=end<=start+MAX_WINDOW_NS:
        raise TransportError('observation window rejected')
    result,code = document['terminal_provider_result'],document['provider_exit_code']
    if (result=='SUCCESS' and code!=0) or (result=='OTHER' and (code is None or code==0)) or (result=='NOT_RUN' and code is not None):
        raise TransportError('provider result inconsistent')
    if document['endpoint_observation']!=('NUMERIC_TCP_ENDPOINT_OBSERVED' if document['connections'] else 'UNKNOWN') or document['connection_progress']!=connection_progress(document['connections']):
        raise TransportError('unsupported progress inference')
    seen = set()
    for ordinal,connection in enumerate(document['connections'],1):
        if connection['ordinal']!=ordinal or connection['socket_cookie'] in seen:
            raise TransportError('connection ordering or identity rejected')
        seen.add(connection['socket_cookie'])
        first,last = connection['first'],connection['last']
        if not start<=first['at']<=last['at']<=end:
            raise TransportError('socket time outside observation window')
        for key in ('bytes_sent','bytes_received','retransmissions'):
            if first[key]>last[key]:
                raise TransportError('counter regressed')
        states = connection['states_seen']
        if states!=sorted(states) or not {first['state'],last['state']}<=set(states):
            raise TransportError('state observations inconsistent')
        if connection['fin_observation']!=fin_observation(states):
            raise TransportError('unsupported close inference')
        samples = connection['sample_count']
        if samples==1 and (first!=last or connection['max_sample_gap_ns']!=0):
            raise TransportError('single sample inconsistent')
        if connection['max_sample_gap_ns']>last['at']-first['at']:
            raise TransportError('sample gap inconsistent')
        for address in ('local_address','remote_address'):
            try:
                if str(ipaddress.ip_address(connection[address]))!=connection[address]:
                    raise ValueError()
            except ValueError as error:
                raise TransportError('noncanonical endpoint') from error
        if ipaddress.ip_address(connection['local_address']).version!=ipaddress.ip_address(connection['remote_address']).version:
            raise TransportError('endpoint address families differ')
        for counter,field in (('bytes_sent','last_send_increase_sample'),
                              ('bytes_received','last_receive_increase_sample')):
            activity = connection[field]
            if (last[counter]>first[counter]) != (activity is not None):
                raise TransportError('activity counter inconsistent')
            if activity is not None and not first['at']<=activity<=last['at']:
                raise TransportError('activity timestamp inconsistent')
        if connection['final_snapshot_kind']=='DESTROY_NOTIFICATION' and last['state']!='CLOSE':
            raise TransportError('destruction state inconsistent')
    return document
