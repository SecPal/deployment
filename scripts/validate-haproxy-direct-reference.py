#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Admit historical #220 observations, consuming the canonical evidence owner.

This reader neither executes hosts nor admits today's source as host-qualified.
Historical source pins were independently verified from the signed implementation
and trusted-controller archive before inclusion; shallow clones need no Git history.
"""

import json
from pathlib import Path
import sys

import jsonschema

from haproxy_base_contract import decode_json_document

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_HEAD = 'd48e22ce8b9bbfe6be6ff8b0c0359ad2ea211ee2'
IMPLEMENTATION_TREE = '67d01fdcd3a6794b61d12a05735609eb6a922082'
INSTALLED_SOURCE = {
    'haproxy-config': '1ca7ed3046a36c968e7918059071fcf7d4cec86d03450acfdce1ad97dd4bdefe',
    'haproxy-direct-policy': '037459237e4690d2d855ee7b7556e0218e213965b34a99f69faef1202351305c',
    'haproxy_base_contract.py': 'abbceee6a18122271dfd361f05dd7b4e7e5719ca7ce66b375ea41cbb8b9269c7',
    'haproxy_composition_contract.py': '14dbf14ea46d694bde95f4103619c59c094461c0a19217a844b3332c321afa58',
    'haproxy_config_lifecycle.py': 'e75eee23c1afe8763db824da2306c457fd800dfca0093ecba69e777a7ed8b0c1',
    'haproxy_direct_contract.py': '5d9a805ce97eac826289a75436b78d6609cf3c45820f76f8a3ce5b2360b38049',
    'haproxy_direct_policy.py': '0be4a2f3eddcaba4ccf2658c076bb2e419ae8f840a788dfd689b06e0d834c273',
    'haproxy_supply_contract.py': 'af73d93ace53cfb839932e83999d13acbea0fb543a5c42177ffba8920067be24',
    'product_backend_contract.py': '585459cf79cd950e4a47ed8ffbb0094a5d54664dd66fd6f5b6291236557fd56e',
}

CORRECTED_SOURCE = {
    '/usr/local/libexec/secpal/haproxy-direct-policy': '435a8071c4d196af0ad710384627effdb058cd552a0aff87d1c811429468d2af',
    '/usr/local/libexec/secpal/haproxy_direct_contract.py': '57d79a90a4b7351e343dff1ada07b7943a03a1c13f515cfd6b89555743351cdb',
    '/etc/systemd/system/secpal-direct-policy.service': '1e5dbc11215cdc059f6f8431fb0c74877c3edbb5f2c7d58327b24630985fea00',
}


def admit(document, root):
    schema = json.loads((root / 'docs/evidence/haproxy-direct-viewer.schema.json').read_bytes())
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as error:
        raise ValueError('admit-direct-reference-schema') from error
    if (document['implementation_head'] != IMPLEMENTATION_HEAD
            or document['implementation_tree'] != IMPLEMENTATION_TREE
            or document['installed_source_sha256'] != INSTALLED_SOURCE):
        raise ValueError('admit-direct-reference-historical-source')


def admit_remediation(document, root):
    schema = json.loads((root / 'docs/evidence/haproxy-direct-remediation.schema.json').read_bytes())
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as error:
        raise ValueError('admit-direct-remediation-schema') from error
    if document['installed_source_sha256'] != CORRECTED_SOURCE:
        raise ValueError('admit-direct-remediation-observed-source')


def main():
    try:
        path = ROOT / 'docs/evidence/haproxy-direct-viewer.json'
        if not 0 < path.stat().st_size <= 65536:
            raise ValueError('admit-direct-reference-size')
        admit(decode_json_document(path.read_bytes()), ROOT)
        path = ROOT / 'docs/evidence/haproxy-direct-remediation.json'
        if not 0 < path.stat().st_size <= 65536:
            raise ValueError('admit-direct-remediation-size')
        admit_remediation(decode_json_document(path.read_bytes()), ROOT)
    except (OSError, ValueError, KeyError, TypeError):
        print('FAIL: DIRECT historical reference evidence admission', file=sys.stderr)
        return 1
    print('DIRECT closed historical/correction records and observed source bindings passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
