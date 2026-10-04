#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure mode-neutral HTTP routing primitives owned by deployment#219.

#101 alone owns addresses and host backend permissions. Listener placement and
canonical identity are separate reviewed consumers, never an operator snippet.
"""

from dataclasses import dataclass
import ipaddress
import hashlib
import json
import re
from product_backend_contract import BACKENDS

MAX_CONFIG_BYTES = 65536
METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')


def hostname(value: str) -> str:
    if (not isinstance(value, str) or not 3 <= len(value) <= 253
            or value != value.lower() or '.' not in value
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in value.split('.'))):
        raise ValueError('admit-origin-hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('admit-origin-hostname')


@dataclass(frozen=True)
class Routing:
    frontend_host: str
    api_host: str

    def __post_init__(self):
        hostname(self.frontend_host)
        hostname(self.api_host)
        if self.frontend_host == self.api_host:
            raise ValueError('admit-distinct-origins')


@dataclass(frozen=True)
class Listener:
    """Socket coordinates only; no identity, PROXY, TLS, auth, or mode selector.

    A consumer owns placement/admission. This type grants no public-listener
    qualification. Production public ingress needs its separate listener owner.
    """
    address: str
    port: int

    def __post_init__(self):
        if not isinstance(self.address, str):
            raise ValueError('admit-listener-address')
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValueError('admit-listener-address') from error
        if (str(address) != self.address or address.is_multicast
                or type(self.port) is not int or not 1 <= self.port <= 65535
                or self.port in {backend.host_port for backend in BACKENDS.values()}):
            raise ValueError('admit-listener-socket')

    @property
    def endpoint(self):
        address = f'[{self.address}]' if ':' in self.address else self.address
        return f'{address}:{self.port}'


def from_document(document):
    if (not isinstance(document, dict)
            or set(document) != {'frontend_host', 'api_host', 'listeners'}):
        raise ValueError('admit-routing-fields')
    routing = Routing(document['frontend_host'], document['api_host'])
    rows = document['listeners']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
        raise ValueError('admit-listener-count')
    listeners = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'address', 'port'}:
            raise ValueError('admit-listener-fields')
        listeners.append(Listener(**row))
    if len(set(listeners)) != len(listeners):
        raise ValueError('admit-listener-uniqueness')
    return routing, tuple(listeners)


def decode_document(data: bytes):
    if not 0 < len(data) <= MAX_CONFIG_BYTES:
        raise ValueError('admit-routing-size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('admit-routing-duplicate-key')
            result[key] = value
        return result
    try:
        document = json.loads(data, object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('admit-json-number')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('decode-routing-document') from error
    return from_document(document)


def forwarding_sanitization() -> tuple[str, ...]:
    """Consumer seam: sanitize before a separately owned identity boundary.

    No inbound forwarding or internal Origin header acquires authority here.
    Later consumers authenticate their transport before invoking this seam and
    emit their own canonical fields afterward. No runtime-loaded extension.
    """
    return ('http-request del-header Forwarded',
            'http-request del-header X-Forwarded- -m beg',
            'http-request del-header X-Real-IP',
            'http-request del-header X-SecPal- -m beg',
            'http-request del-header X-Request-ID')


def routing_sections(routing: Routing, generation: str | None = None) -> str:
    """Fixed origins/backends for reviewed listener/identity consumers."""
    rules = f'''    acl supported_method method {' '.join(METHODS)}
    http-request set-var(txn.security) str(method_rejected) unless supported_method
    http-request deny deny_status 405 unless supported_method
    http-request set-var(txn.method) method
    acl origin_form url_beg /
    acl options_star method OPTIONS
    acl star_target url -m str *
    http-request set-var(txn.security) str(target_rejected) if !origin_form !options_star
    http-request deny deny_status 400 if !origin_form !options_star
    http-request set-var(txn.security) str(target_rejected) if !origin_form !star_target
    http-request deny deny_status 400 if !origin_form !star_target
    acl one_host req.hdr_cnt(host) eq 1
    http-request set-var(txn.security) str(host_rejected) unless one_host
    http-request deny deny_status 400 unless one_host
    acl frontend_origin req.hdr(host),lower -m str {routing.frontend_host} {routing.frontend_host}:80 {routing.frontend_host}:443
    acl api_origin req.hdr(host),lower -m str {routing.api_host} {routing.api_host}:80 {routing.api_host}:443
    http-request set-var(txn.security) str(origin_rejected) if !frontend_origin !api_origin
    http-request deny deny_status 421 if !frontend_origin !api_origin
    http-request set-var(txn.origin) str(frontend) if frontend_origin
    http-request set-var(txn.origin) str(api) if api_origin
    http-request set-var(txn.security) str(uri_rejected) if {{ url,length gt 8192 }}
    http-request return status 414 content-type text/plain string "URI too long" if {{ url,length gt 8192 }}
'''
    if generation is not None:
        if not re.fullmatch(r'[0-9a-f]{64}', generation):
            raise ValueError('admit-generation-fingerprint')
        # A read-only runtime diagnostic, not product readiness or identity.
        # Existing origin/method/header bounds still apply. No secret or
        # administrative mutation is accessible through this HTTP response.
        rules += f'''    acl generation_probe method GET
    acl generation_path path -m str /_secpal/proxy-generation
    acl generation_header req.hdr_cnt(X-SecPal-Runtime-Probe) eq 1
    acl generation_value req.hdr(X-SecPal-Runtime-Probe) -m str {generation}
    http-request set-var(txn.security) str(generation_probe) if generation_probe generation_path generation_header generation_value
    http-request return status 204 hdr X-SecPal-Generation {generation} hdr X-SecPal-Worker %pid if generation_probe generation_path generation_header generation_value
'''
    rules += ''.join(f'    {rule}\n' for rule in forwarding_sanitization())
    rules += '''    http-request set-var(txn.security) str(accepted)
    use_backend secpal_frontend if frontend_origin
    use_backend secpal_api if api_origin
'''
    # The static frontend has no separate /health/ready product route. Its
    # immutable server starts after entrypoint initialization. API data-state
    # readiness explicitly differs from #101's HTTP transport-only check.
    for role, backend in BACKENDS.items():
        path = '/health/ready' if role == 'api' else backend.readiness_path
        rules += f'''
backend secpal_{role}
    option httpchk
    http-check send meth GET uri {path} ver HTTP/1.1 hdr Host localhost
    http-check expect status 200 on-error str(readiness_rejected) on-success str(ready)
    server {role} {backend.endpoint} check inter 1s fastinter 1s downinter 1s fall 1 rise 2
'''
    return rules


def _render(routing: Routing, listeners: tuple[Listener, ...], generation: str | None = None) -> str:
    if (not isinstance(routing, Routing) or not isinstance(listeners, tuple)
            or not 1 <= len(listeners) <= 8 or len(set(listeners)) != len(listeners)
            or not all(isinstance(listener, Listener) for listener in listeners)):
        raise ValueError('admit-render-input')
    text = '''# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
# Reviewed shared base; listener placement and canonical identity have separate owners.
global
    user haproxy
    group haproxy
    log stdout format raw local0 info
    maxconn 4096
    nbthread 2
    tune.bufsize 16384
    tune.maxrewrite 1024
    tune.http.maxhdr 64
    hard-stop-after 35s

defaults
    mode http
    log global
    timeout connect 3s
    timeout client 30s
    timeout server 30s
    timeout http-request 5s
    timeout http-keep-alive 5s
    timeout queue 3s
    timeout check 3s
    timeout tunnel 30s
    retries 0
    unique-id-format %[uuid()]
    log-format "peer=%ci request_id=%ID method=%[var(txn.method)] origin=%[var(txn.origin)] backend=%b server=%s status=%ST bytes=%B duration_ms=%Ta termination=%tsc security=%[var(txn.security)]"

frontend secpal_ingress
'''
    text += ''.join(f'    bind {listener.endpoint}\n' for listener in listeners)
    text += '''    http-request set-var(txn.security) str(rejected)
    http-request set-var(txn.method) str(unavailable)
    http-request set-var(txn.origin) str(unavailable)
'''
    text += routing_sections(routing, generation)
    document = {'frontend_host': routing.frontend_host, 'api_host': routing.api_host,
                'listeners': [{'address': listener.address, 'port': listener.port} for listener in listeners]}
    return '# secpal-routing ' + json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n' + text


def listener_constraints(listeners: tuple[Listener, ...]) -> str:
    if not isinstance(listeners, tuple) or not 1 <= len(listeners) <= 8:
        raise ValueError('admit-listener-unit')
    # REUSE-IgnoreStart
    rules = ['# SPDX-FileCopyrightText: 2026 SecPal Contributors',
             '# SPDX-License-Identifier: MIT', '[Service]', 'SocketBindAllow=']
    # REUSE-IgnoreEnd
    for listener in sorted(listeners, key=lambda item: item.endpoint):
        if not isinstance(listener, Listener):
            raise ValueError('admit-listener-unit')
        family = 'ipv6' if ':' in listener.address else 'ipv4'
        rules.append(f'SocketBindAllow={family}:tcp:{listener.port}')
    return '\n'.join(rules) + '\n'


def from_config(data: bytes):
    """Authenticate accepted bytes independently of a pending desired spec.

    The closed embedded reviewed inputs are immutable config comments, never a
    runtime snapshot. Exact regeneration excludes arbitrary directives and
    permits startup of last-known-good after a rejected desired configuration.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CONFIG_BYTES:
        raise ValueError('admit-serving-size')
    line = data.split(b'\n', 1)[0]
    prefix = b'# secpal-routing '
    if not line.startswith(prefix):
        raise ValueError('admit-serving-inputs')
    routing, listeners = decode_document(line[len(prefix):])
    if render(routing, listeners).encode() != data:
        raise ValueError('admit-serving-regeneration')
    return routing, listeners


def generation_id(routing: Routing, listeners: tuple[Listener, ...]) -> str:
    return hashlib.sha256(_render(routing, listeners).encode()).hexdigest()


def render(routing: Routing, listeners: tuple[Listener, ...]) -> str:
    return _render(routing, listeners, generation_id(routing, listeners))
