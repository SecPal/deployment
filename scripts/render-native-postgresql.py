#!/usr/bin/env -S python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Render the admitted production PostgreSQL bundle, without host mutation.

This exact consumer is authenticated by the accepted-main qualification resolver.
Production trust issuance remains #100; general host construction remains #92.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts/ci-cloud'))
import postgresql_qualification_contract as contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-uid', required=True, type=int)
    options = parser.parse_args()
    path = ROOT / contract.CANDIDATE_PATH
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise contract.QualificationError('read-candidate-data', 'representation-invalid')
        data = contract.parse_declaration(path.read_text())
        # JSON is a transport envelope for exact file bytes, never a shell program.
        print(json.dumps(contract.render_configuration(data, options.runtime_uid), sort_keys=True))
        return 0
    except (OSError, UnicodeError, contract.QualificationError):
        print('PostgreSQL configuration admission failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
