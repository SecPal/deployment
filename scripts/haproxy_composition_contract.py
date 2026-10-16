#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fixed compile-time #219/#220 composition for the existing installed helper.

No module name, runtime extension, raw fragment, backend or command is input.
"""

import ipaddress

import haproxy_base_contract as base
import haproxy_direct_contract as direct


def neutral_private(routing, listeners):
    # #219's neutral private qualification is not public Viewer authority.
    # Prevent the pre-identity document shape from activating public ingress.
    if any(not ipaddress.ip_address(row.address).is_loopback
           or getattr(ipaddress.ip_address(row.address), 'scope_id', None) is not None for row in listeners):
        raise ValueError('admit-neutral-loopback-only')
    return routing, listeners


def decode_document(data):
    document = base.decode_json_document(data)
    if type(document) is dict and 'topology' in document:
        spec = direct.from_document(document)
        return spec.routing, spec.listeners
    return neutral_private(*base.from_document(document))


def direct_spec(routing, listeners):
    if type(listeners) is tuple and listeners and type(listeners[0]) in (direct.ViewerListener, direct.ProxyListener):
        return direct.Direct(routing, listeners)
    return None


def render(routing, listeners):
    spec = direct_spec(routing, listeners)
    return direct.render(spec) if spec else base.render(routing, listeners)


def generation_id(routing, listeners):
    spec = direct_spec(routing, listeners)
    return direct.generation_id(spec) if spec else base.generation_id(routing, listeners)


def listener_constraints(listeners):
    if (listeners and type(listeners[0]) is direct.ViewerListener
            and listeners[0].tls_lifecycle != 'legacy'):
        return ('[Unit]\nBindsTo=secpal-acme-policy.service\nAfter=secpal-acme-policy.service\n\n'
                + base.listener_constraints(tuple(coordinates(row) for row in listeners)))
    if listeners and type(listeners[0]) is direct.ProxyListener:
        sockets = tuple(coordinates(row) for row in listeners)
        sockets += tuple(base.Listener('127.0.0.1', direct.DECODER_PORTS[transport])
                         for transport in sorted({row.transport for row in listeners}))
        return '[Unit]\nBindsTo=secpal-direct-policy.service\nAfter=secpal-direct-policy.service\n\n' + base.listener_constraints(sockets)
    return base.listener_constraints(tuple(coordinates(row) for row in listeners))


def coordinates(row):
    if type(row) in (direct.ViewerListener, direct.ProxyListener):
        return row.socket
    if type(row) is base.Listener:
        return row
    raise ValueError('admit-composed-listener')


def from_config(data):
    if type(data) is bytes and data.startswith(b'# secpal-direct '):
        spec = direct.from_config(data)
        return spec.routing, spec.listeners
    return neutral_private(*base.from_config(data))
