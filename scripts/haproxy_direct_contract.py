#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Closed DIRECT Viewer composition owned by deployment#220, consuming #219.

TLS material at the fixed pathname belongs to #103. This module neither issues
certificates nor activates host sockets. No operator snippets or module paths.
"""

from dataclasses import dataclass
import hashlib
import ipaddress
import json

from haproxy_base_contract import (Listener, Routing, decode_json_document,
    forwarding_sanitization, routing_sections, runtime_preamble)

VIEWER_PEM = '/etc/haproxy/secpal-viewer.pem'
DECODER_PORTS = {'http': 18082, 'https': 18083}


def private_address(value):
    address = ipaddress.ip_address(value)
    networks = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')
    return address.is_loopback or any(address in ipaddress.ip_network(net) for net in networks)


@dataclass(frozen=True)
class ViewerListener:
    socket: Listener
    transport: str

    def __post_init__(self):
        if type(self.socket) is not Listener or self.transport not in ('http', 'https'):
            raise ValueError('admit-direct-listener')
        if getattr(ipaddress.ip_address(self.socket.address), 'scope_id', None) is not None:
            raise ValueError('admit-unscoped-direct-address')
        if (not ipaddress.ip_address(self.socket.address).is_loopback
                and self.socket.port != {'http': 80, 'https': 443}[self.transport]):
            raise ValueError('admit-direct-public-port')


@dataclass(frozen=True)
class ProxyListener:
    socket: Listener
    transport: str
    trusted_peers: tuple[str, ...]

    def __post_init__(self):
        ViewerListener(self.socket, self.transport)
        if (not private_address(self.socket.address)
                or self.socket.port in DECODER_PORTS.values()
                or type(self.trusted_peers) is not tuple
                or not 1 <= len(self.trusted_peers) <= 32
                or len(set(self.trusted_peers)) != len(self.trusted_peers)):
            raise ValueError('admit-private-proxy-listener')
        for value in self.trusted_peers:
            if application_proxy_peer(value) != value or not private_address(value):
                raise ValueError('admit-trusted-physical-peer')
        family = ipaddress.ip_address(self.socket.address).version
        if not any(ipaddress.ip_address(peer).version == family for peer in self.trusted_peers):
            raise ValueError('admit-trusted-peer-address-family')


@dataclass(frozen=True)
class Direct:
    routing: Routing
    listeners: tuple[ViewerListener | ProxyListener, ...]

    def __post_init__(self):
        if (type(self.routing) is not Routing or type(self.listeners) is not tuple
                or not 1 <= len(self.listeners) <= 8
                or type(self.listeners[0]) not in (ViewerListener, ProxyListener)
                or any(type(row) is not type(self.listeners[0]) for row in self.listeners)):
            raise ValueError('admit-direct-input')
        if (type(self.listeners[0]) is ProxyListener
                and len(self.listeners) + len({row.transport for row in self.listeners}) > 8):
            raise ValueError('admit-composed-listener-budget')
        for index, row in enumerate(self.listeners):
            address = ipaddress.ip_address(row.socket.address)
            for other in self.listeners[:index]:
                peer = ipaddress.ip_address(other.socket.address)
                if (row.socket.port == other.socket.port and address.version == peer.version
                        and (address == peer or address.is_unspecified or peer.is_unspecified)):
                    raise ValueError('admit-direct-distinct-sockets')

    @property
    def sockets(self):
        return tuple(row.socket for row in self.listeners)

    @property
    def topology(self):
        return 'ha' if type(self.listeners[0]) is ProxyListener else 'single'

    @property
    def bound_sockets(self):
        return self.sockets + (tuple(Listener('127.0.0.1', DECODER_PORTS[transport])
            for transport in sorted({row.transport for row in self.listeners}))
            if self.topology == 'ha' else ())


def from_document(document) -> Direct:
    if (type(document) is not dict or set(document) != {
            'topology', 'frontend_host', 'api_host', 'listeners'}
            or document['topology'] not in ('single', 'ha')):
        raise ValueError('admit-direct-fields')
    rows = document['listeners']
    if type(rows) is not list or not 1 <= len(rows) <= 8:
        raise ValueError('admit-direct-listener-count')
    listeners = []
    for row in rows:
        fields = {'address', 'port', 'transport'}
        if document['topology'] == 'ha':
            fields.add('trusted_peers')
        if type(row) is not dict or set(row) != fields:
            raise ValueError('admit-direct-listener-fields')
        socket = Listener(row['address'], row['port'])
        if document['topology'] == 'ha':
            if type(row['trusted_peers']) is not list:
                raise ValueError('admit-trusted-physical-peers')
            listeners.append(ProxyListener(socket, row['transport'], tuple(row['trusted_peers'])))
        else:
            listeners.append(ViewerListener(socket, row['transport']))
    return Direct(Routing(document['frontend_host'], document['api_host']), tuple(listeners))


def decode_document(data: bytes) -> Direct:
    return from_document(decode_json_document(data))


def document(spec: Direct):
    return {'topology': spec.topology, 'frontend_host': spec.routing.frontend_host,
            'api_host': spec.routing.api_host, 'listeners': [
                {'address': row.socket.address, 'port': row.socket.port,
                 'transport': row.transport,
                 **({'trusted_peers': list(row.trusted_peers)} if type(row) is ProxyListener else {})}
                for row in spec.listeners]}


def preface_sections(spec):
    text = ''
    for index, row in enumerate(spec.listeners):
        text += f'''frontend secpal_preface_{index}
    mode tcp
    bind {row.socket.endpoint}{' v6only' if ':' in row.socket.address else ''}
    tcp-request connection reject unless {{ src {' '.join(row.trusted_peers)} 127.0.0.1 ::1 {row.socket.address} }}
    tcp-request inspect-delay 1s
    acl v4 req.payload(0,16) -m bin 0d0a0d0a000d0a515549540a2111000c
    acl v6 req.payload(0,16) -m bin 0d0a0d0a000d0a515549540a21210024
    acl complete_v4 req.payload(0,28) -m found
    acl complete_v6 req.payload(0,52) -m found
    acl mapped_v6 req.payload(16,12) -m bin 00000000000000000000ffff
    tcp-request content reject if v6 complete_v6 mapped_v6
    tcp-request content accept if v4 complete_v4
    tcp-request content accept if v6 complete_v6
    tcp-request content reject if WAIT_END
    option logasap
    log-format "stage=admission worker=%pid peer=%ci edge=%[bc_src]:%[bc_src_port]>%[bc_dst]:%[bc_dst_port] termination=%ts"
    default_backend secpal_decoder_{row.transport}
'''
    for transport in sorted({row.transport for row in spec.listeners}):
        text += f'''backend secpal_decoder_{transport}
    mode tcp
    server decoder 127.0.0.1:{DECODER_PORTS[transport]}
'''
    return text


def _render(spec: Direct, generation=None) -> str:
    if type(spec) is not Direct:
        raise ValueError('admit-direct-input')
    text = '# secpal-direct ' + json.dumps(document(spec), sort_keys=True, separators=(',', ':')) + '\n'
    # Same package/runtime/limits as #219; the identity owner adds both facts.
    text += runtime_preamble().replace('peer=%ci ', 'peer=%[fc_src] client=%ci ')
    if spec.topology == 'ha':
        text = text.replace('peer=%[fc_src] client=%ci ',
                            'stage=http worker=%pid edge=%[fc_src]:%[fc_src_port]>%[fc_dst]:%[fc_dst_port] client=%ci ')
    text += 'frontend secpal_ingress\n'
    rows = (tuple(ViewerListener(Listener('127.0.0.1', DECODER_PORTS[transport]), transport)
                  for transport in sorted({row.transport for row in spec.listeners}))
            if spec.topology == 'ha' else spec.listeners)
    for row in rows:
        options = ' accept-proxy' if spec.topology == 'ha' else ''
        options += ' v6only' if ':' in row.socket.address else ''
        if row.transport == 'https':
            options += f' ssl crt {VIEWER_PEM} ssl-min-ver TLSv1.2 alpn h2,http/1.1'
        text += f'    bind {row.socket.endpoint}{options}\n'
    text += '''    http-request set-var(txn.security) str(rejected)
    http-request set-var(txn.method) str(unavailable)
    http-request set-var(txn.origin) str(unavailable)
'''
    # Compose the reviewed sanitization seam, then one canonical set. The
    # replacement target is source-owned, never supplied by an operator.
    sanitization = ''.join(f'    {rule}\n' for rule in forwarding_sanitization())
    canonical = '''    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Host %[req.hdr(host),lower,field(1,:)]
    http-request set-header X-Forwarded-Proto http
    http-request set-header X-Forwarded-Port 80
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Port 443 if { ssl_fc }
'''
    if spec.topology == 'ha':
        # Reject invalid native identity before even the read-only generation
        # witness. Caller metadata has no role in these transport facts.
        text += '''    http-request deny deny_status 400 if { src 0.0.0.0 :: 224.0.0.0/4 ff00::/8 }
    http-request deny deny_status 400 unless { src_port gt 0 }
'''
    text += routing_sections(spec.routing, generation).replace(sanitization, sanitization + canonical, 1)
    if spec.topology == 'ha':
        text += preface_sections(spec)
    return text


def generation_id(spec: Direct) -> str:
    return hashlib.sha256(_render(spec).encode()).hexdigest()


def render(spec: Direct) -> str:
    return _render(spec, generation_id(spec))


def from_config(data: bytes) -> Direct:
    # Closed JSON plus byte equality binds TLS/listener/identity and the full
    # serving generation independently of any rejected desired document.
    from haproxy_base_contract import MAX_CONFIG_BYTES
    if type(data) is not bytes or not 0 < len(data) <= MAX_CONFIG_BYTES:
        raise ValueError('admit-direct-serving-size')
    line = data.split(b'\n', 1)[0]
    prefix = b'# secpal-direct '
    if not line.startswith(prefix):
        raise ValueError('admit-direct-serving-input')
    spec = decode_document(line[len(prefix):])
    if render(spec).encode() != data:
        raise ValueError('admit-direct-serving-regeneration')
    return spec


def application_proxy_peer(value: str) -> str:
    """Exact observed rootless forwarding peer; no wildcard/CIDR/REMOTE_ADDR."""
    try:
        peer = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError('admit-application-proxy-peer') from error
    if (str(peer) != value or not private_address(value) or peer.is_multicast or peer.is_unspecified
            or getattr(peer, 'scope_id', None) is not None):
        raise ValueError('admit-application-proxy-peer')
    return value


@dataclass(frozen=True)
class ApplicationAuthority:
    """One HAProxy authority observed on up to two existing private interfaces."""
    peers: tuple[str, ...]

    def __post_init__(self):
        if (type(self.peers) is not tuple or not 1 <= len(self.peers) <= 2
                or any(type(peer) is not str for peer in self.peers)
                or len(set(self.peers)) != len(self.peers)):
            raise ValueError('admit-application-proxy-authority')
        for peer in self.peers:
            application_proxy_peer(peer)


def application_proxy_peers(peers: tuple[str, ...]) -> str:
    return ','.join(ApplicationAuthority(peers).peers)
