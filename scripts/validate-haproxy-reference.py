#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Admit the immutable #219 host record, consuming the canonical evidence owner.

Observation remains trusted controller/real-host work; this bounded local reader
cannot qualify a host or obtain provider/administrator authority. Closed JSON
Schema admission and exact signed-source payload binding preserve that boundary.
"""

import json
from pathlib import Path
import sys

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def admit(document, root):
    schema = json.loads((root / 'docs/evidence/haproxy-rocky-reference.schema.json').read_bytes())
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as error:
        raise ValueError('admit-haproxy-reference-schema') from error
    # The closed record schema binds its independently authenticated historical
    # target and exact payload expectations. No Git history/ref, network call or
    # caller-provided source lookup participates in local admission.
    # Accepted #304 payload identities are historical provenance. Comparing
    # them to today's mutable source prevents every legitimate later consumer
    # from evolving the shared runtime and wrongly relabels current source as
    # having been executed on these historical hosts. Keep the record unchanged.
    correction_payloads = {
        '/usr/local/libexec/secpal/haproxy-config':
            '5a7913e4c11167d565ee0c39c05a801fbdf051629482ea86cff94c44da87212e',
        '/usr/local/libexec/secpal/haproxy_config_lifecycle.py':
            'e75eee23c1afe8763db824da2306c457fd800dfca0093ecba69e777a7ed8b0c1',
        '/usr/local/libexec/secpal/haproxy_supply_contract.py':
            'af73d93ace53cfb839932e83999d13acbea0fb543a5c42177ffba8920067be24',
        '/usr/local/libexec/secpal/product-backend-policy':
            'd615f95aa97756be55cf8ac2e7431d7bfc69288a1f9504df58c383f7553a5bda',
        '/etc/systemd/system/haproxy.service.d/secpal.conf':
            '6b9fecdbfbe547826aa56bacc2132bcb860e232dfbe63425c53447c484fde276',
    }
    for host, correction in zip(document['hosts'], document['remediation_qualification'], strict=True):
        if (correction['server_id'] != host['server_id']
                or correction['reviewed_source_parent'] != document['target_sha']):
            raise ValueError('admit-haproxy-correction-target')
        for installed_path, digest in correction_payloads.items():
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
    except (OSError, ValueError, KeyError, TypeError):
        print('FAIL: shared HAProxy historical reference evidence admission', file=sys.stderr)
        return 1
    print('Shared HAProxy historical closed record and accepted payload binding passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
