#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Accepted-main-only backend preparation authorization and proof admission.

No PR/candidate lookup or execution capability. GitHub dispatch main authority
owns this fixed checkout; all provider operations stay in the Rocky workflow.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import product_backend_qualification_contract as contract


def read(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 131072:
        raise ValueError('bounded representation')
    return json.loads(path.read_text(), object_pairs_hook=contract.unique_keys)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'reconfirm', 'admit', 'admit-diagnostic'))
    parser.add_argument('--control-sha', required=True)
    parser.add_argument('--profile', required=True, choices=tuple(contract.PROFILES))
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    parser.add_argument('--prepared', type=Path)
    parser.add_argument('--continuation', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--host-evidence', type=Path)
    parser.add_argument('--qualification-run-id')
    parser.add_argument('--qualification-run-attempt')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    operation = 'validate-authorization'
    try:
        sources = {}
        for name, relative in contract.SOURCES.items():
            path = ROOT / relative
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 262144:
                raise ValueError('source closure')
            sources[name] = path.read_bytes()
        expected = contract.manifest(options.control_sha, options.profile, options.run_id, options.run_attempt, sources)
        if options.operation == 'prepare':
            result = expected
        else:
            if read(options.prepared) != expected:
                raise ValueError('preparation source identity')
            result = expected
            if options.operation in ('admit', 'admit-diagnostic'):
                continuation = read(options.continuation)
                for key, value in dict(trusted_control_sha=options.control_sha, profile=options.profile,
                                       run_id=options.run_id, run_attempt=options.run_attempt).items():
                    if continuation.get(key) != value:
                        raise ValueError('resource identity')
                binding = dict(control_sha=options.control_sha, profile=options.profile,
                    preparation_run_id=options.run_id, preparation_run_attempt=options.run_attempt,
                    run_id=options.qualification_run_id, run_attempt=options.qualification_run_attempt,
                    instance_id=continuation['instance_id'], instance_name=continuation['instance_name'])
                if any(not isinstance(binding[k], str) or not contract.NUMBER.fullmatch(binding[k])
                       for k in ('run_id', 'run_attempt')) or len(binding['run_attempt']) > 3:
                    raise ValueError('qualification identity')
                operation = 'admit-evidence'
                result = read(options.evidence)
                if options.operation == 'admit':
                    contract.admit_evidence(result, binding, expected['source_sha256'])
                    if options.host_evidence.is_symlink() or not options.host_evidence.is_file() or not 0 < options.host_evidence.stat().st_size <= 131072 or result['host_evidence_sha256'] != hashlib.sha256(options.host_evidence.read_bytes()).hexdigest():
                        raise ValueError('host evidence identity')
                elif (set(result) != {'binding', 'source_sha256', 'diagnostic', 'cleanup'} or result['binding'] != binding
                      or result['source_sha256'] != expected['source_sha256']
                      or result['diagnostic'] != contract.diagnostic(result['diagnostic']['operation'],
                          result['diagnostic']['reason'], result['diagnostic']['host_cleanup_complete'])):
                    raise ValueError('diagnostic binding')
                if options.operation == 'admit-diagnostic' and result['diagnostic']['host_cleanup_complete']:
                    contract.admit_cleanup(result['cleanup'])
        if options.output.is_symlink():
            raise ValueError('output representation')
        options.output.write_bytes(contract.canonical(result) + b'\n')
        options.output.chmod(0o600)
        return 0
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        print(json.dumps(contract.diagnostic(operation, 'identity-mismatch', False)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
