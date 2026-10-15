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
    if imports != {'__future__', 'hashlib', 'json', 're', 'typing', 'rocky_preparation_contract'} or imports & rocky.FORBIDDEN_PURE_IMPORTS:
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
    runner = (root / 'scripts/ci-cloud/qualify-native-postgresql.py').read_text()
    control = (root / 'scripts/ci-cloud/postgresql-qualification-control.py').read_text()
    workflow = (root / '.github/workflows/rocky-cloud-qualification.yml').read_text()
    for source in (runner, control):
        parsed = ast.parse(source)
        for node in ast.walk(parsed):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec', 'compile', '__import__'}:
                raise ValueError('trusted operation has arbitrary execution')
            if isinstance(node, ast.Call) and any(k.arg == 'shell' and not isinstance(k.value, ast.Constant) or k.arg == 'shell' and k.value.value is not False for k in node.keywords):
                raise ValueError('trusted command acquires shell execution')
    if 'subprocess.run(' in runner or 'capture_output=True' in runner:
        raise ValueError('trusted observation bypasses bounded process collection')
    if 'http://169.254.169.254' in runner:
        raise ValueError('test guest attempts metadata access')
    for required in ('bound_diagnostic(', 'observer.cleanup()', 'CLEANUP_POSTCONDITIONS', 'resource_binding()', 'bounded_process('):
        if required not in runner:
            raise ValueError('guest failure/resource/cleanup boundary missing')
    for required in ('contract.admit_diagnostic(', 'consumer !=', "'candidate_tree': tree", 'NoRedirect'):
        if required not in control:
            raise ValueError('trusted source/diagnostic binding missing')
    for required in ('scripts/validate-postgresql-qualification.py', 'admit-diagnostic', 'confirm_postgresql:', 'postgresql-failure-'):
        if required not in workflow:
            raise ValueError('pre-provider admission or diagnostic transport missing')
    import yaml
    jobs = yaml.safe_load(workflow)['jobs']
    if jobs['confirm_postgresql']['permissions'].get('id-token') == 'write':
        raise ValueError('source observer has provider authority')
    if any(key in jobs['provision']['permissions'] for key in ('issues', 'pull-requests')):
        raise ValueError('provider controller has source graph authority')
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
