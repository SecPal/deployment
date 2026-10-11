#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Admit the immutable #219 host record, consuming the canonical evidence owner.

Observation remains trusted controller/real-host work; this bounded local reader
cannot qualify a host or obtain provider/administrator authority. Closed JSON
Schema admission and exact signed-source payload binding preserve that boundary.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = {
    'haproxy-config': 'scripts/haproxy-config.py',
    'haproxy_base_contract.py': 'scripts/haproxy_base_contract.py',
    'haproxy_config_lifecycle.py': 'scripts/haproxy_config_lifecycle.py',
    'haproxy_supply_contract.py': 'scripts/haproxy_supply_contract.py',
    'product_backend_contract.py': 'scripts/product_backend_contract.py',
    'secpal_haproxy_runtime.cil': 'config/production/host-selinux/secpal_haproxy_runtime.cil',
}


def admit(document, root):
    schema = json.loads((root / 'docs/evidence/haproxy-rocky-reference.schema.json').read_bytes())
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as error:
        raise ValueError('admit-haproxy-reference-schema') from error
    # The immutable reviewed target is historical evidence, not mutable live
    # state or a claim that a later source correction was already exercised.
    for name, path in SOURCE_PATHS.items():
        result = subprocess.run(['git', '-C', str(root), 'show', document['target_sha'] + ':' + path],
                                capture_output=True, timeout=10)
        if result.returncode or not 0 < len(result.stdout) <= 65536:
            raise ValueError('observe-haproxy-reference-source')
        digest = hashlib.sha256(result.stdout).hexdigest()
        if any(host['runtime_source_sha256'].get(name) != digest for host in document['hosts']):
            raise ValueError('admit-haproxy-reference-source')
    correction_paths = {
        '/usr/local/libexec/secpal/haproxy-config': 'scripts/haproxy-config.py',
        '/usr/local/libexec/secpal/haproxy_config_lifecycle.py': 'scripts/haproxy_config_lifecycle.py',
        '/usr/local/libexec/secpal/haproxy_supply_contract.py': 'scripts/haproxy_supply_contract.py',
        '/usr/local/libexec/secpal/product-backend-policy': 'scripts/product-backend-policy.py',
        '/etc/systemd/system/haproxy.service.d/secpal.conf': 'config/production/host-systemd/haproxy.service.d/secpal.conf',
    }
    for host, correction in zip(document['hosts'], document['remediation_qualification'], strict=True):
        if (correction['server_id'] != host['server_id']
                or correction['reviewed_source_parent'] != document['target_sha']):
            raise ValueError('admit-haproxy-correction-target')
        for installed_path, source_path in correction_paths.items():
            digest = hashlib.sha256((root / source_path).read_bytes()).hexdigest()
            if (correction['installed_source_sha256'].get(installed_path) != digest
                    or correction['negative_admission_and_fault_injection']['source_sha256'].get(installed_path) != digest):
                raise ValueError('admit-haproxy-correction-source')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('admit-haproxy-reference-duplicate')
        result[key] = value
    return result


def main():
    try:
        path = ROOT / 'docs/evidence/haproxy-rocky-reference.json'
        if not 0 < path.stat().st_size <= 512 * 1024:
            raise ValueError('admit-haproxy-reference-size')
        document = json.loads(path.read_bytes(), object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('admit-haproxy-reference-number')))
        admit(document, ROOT)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('FAIL: shared HAProxy historical reference evidence admission', file=sys.stderr)
        return 1
    print('Shared HAProxy closed reference record and target-source binding passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
