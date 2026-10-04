#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Preview shared HAProxy configuration or exact systemd listener constraints."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from haproxy_base_contract import decode_document, render, listener_constraints


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('routing', type=Path)
    parser.add_argument('--listener-unit', action='store_true')
    args = parser.parse_args()
    routing, listeners = decode_document(args.routing.read_bytes())
    print(listener_constraints(listeners) if args.listener_unit else render(routing, listeners), end='')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError):
        print('FAIL: render-shared-haproxy-input', file=sys.stderr)
        raise SystemExit(1)
