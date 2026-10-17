#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Preview closed DIRECT configuration; no host activation or TLS lifecycle."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from haproxy_direct_contract import decode_document, render, application_proxy_peers
from haproxy_composition_contract import listener_constraints


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('routing', type=Path)
    output = parser.add_mutually_exclusive_group()
    output.add_argument('--listener-unit', action='store_true')
    output.add_argument('--application-peer', metavar='OBSERVED_TCP_PEER', action='append',
                        help='Emit bounded exact API proxy trust; repeat for the two observed private interface peers')
    args = parser.parse_args()
    spec = decode_document(args.routing.read_bytes())
    if args.application_peer is not None:
        print('Environment=TRUSTED_PROXIES=' + application_proxy_peers(tuple(args.application_peer)))
    else:
        print(listener_constraints(spec.listeners) if args.listener_unit else render(spec), end='')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError):
        print('FAIL: render-direct-haproxy-input', file=sys.stderr)
        raise SystemExit(1)
