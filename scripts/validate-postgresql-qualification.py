#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Deployment-specific agreement gate, subordinate to canonical evidence authority."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import postgresql_qualification_contract as contract

spec = importlib.util.spec_from_file_location('rocky_architecture', ROOT / 'scripts/validate-rocky-evidence-architecture.py')
rocky = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rocky)


def validate(root: Path):
    pure = root / 'scripts/ci-cloud/postgresql_qualification_contract.py'
    source = pure.read_text()
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(item.name.split('.')[0] for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or '').split('.')[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in rocky.FORBIDDEN_PURE_CALLS:
                raise ValueError('pure admission acquires execution capability')
        elif isinstance(node, ast.Attribute) and node.attr in {'read_text', 'read_bytes', 'write_text', 'write_bytes', 'resolve', 'exists'}:
            raise ValueError('pure admission acquires filesystem capability')
    if imports != {'__future__', 'base64', 'hashlib', 'ipaddress', 'json', 're', 'typing', 'rocky_preparation_contract'} or imports & rocky.FORBIDDEN_PURE_IMPORTS:
        raise ValueError('pure admission import closure changed')
    # The shared RPM authority has its existing architecture gate; do not redefine it.
    rocky.validate_pure_contract(root / 'scripts/ci-cloud/rocky_preparation_contract.py')
    if contract.INVARIANT_OWNERS['evidence-architecture'] != 'SecPal/.github/docs/evidence-architecture-contract.md':
        raise ValueError('canonical evidence owner missing')
    failure = json.loads((root / 'schemas/postgresql-qualification-diagnostic.schema.json').read_text())
    if (failure.get('additionalProperties') is not False
            or set(failure['properties']['operation']['enum']) != contract.OPERATIONS
            or set(failure['properties']['reason']['enum']) != contract.REASONS):
        raise ValueError('closed semantic diagnostic schema disagrees with trusted operations')
    if len(contract.rpm.PACKAGES) != 22:
        raise ValueError('frozen host package claim widened')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    options = parser.parse_args()
    try:
        validate(options.root)
    except (ValueError, KeyError, OSError, SyntaxError, rocky.ArchitectureError) as error:
        print(f'PostgreSQL qualification architecture rejected: {error}', file=sys.stderr)
        return 1
    print('PostgreSQL qualification architecture validation passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
