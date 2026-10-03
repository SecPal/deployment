#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail closed before provider authority on #101's fixed observation surface."""

import ast
from pathlib import Path
import sys
import symtable

ROOT = Path(__file__).resolve().parents[1]


def validate(root):
    directory = root / 'scripts/ci-cloud'
    tree = ast.parse((directory / 'product_backend_qualification_contract.py').read_text())
    allowed_imports = {'hashlib', 'json', 're', 'csv', 'io', 'types', 'product_backend_contract', 'rocky_preparation_contract'}
    operations = None
    sources = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and not {item.name for item in node.names} <= allowed_imports:
            raise ValueError('admission gained external observation authority')
        if isinstance(node, ast.ImportFrom) and node.module not in allowed_imports:
            raise ValueError('admission gained external observation authority')
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'open', 'eval', 'exec', '__import__'}:
            raise ValueError('admission gained external observation authority')
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == 'OPERATIONS':
                operations = ast.literal_eval(node.value)
            if node.targets[0].id == 'SOURCES':
                sources = ast.literal_eval(node.value)
    if not isinstance(operations, tuple) or not operations or len(set(operations)) != len(operations):
        raise ValueError('closed diagnostic operations absent')
    if not isinstance(sources, dict) or not sources or len(set(sources.values())) != len(sources):
        raise ValueError('closed accepted source closure absent')
    for relative in sources.values():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or not (root / path).is_file() or (root / path).is_symlink():
            raise ValueError('source closure path invalid')
    runner_text = (directory / 'qualify-product-backends.py').read_text()
    runner = ast.parse(runner_text)
    symbols = symtable.symtable(runner_text, 'qualify-product-backends.py', 'exec')
    if not symbols.lookup('subprocess').is_imported():
        raise ValueError('process authority is not the standard library module')
    process_scope = next(scope for scope in symbols.get_children() if scope.get_name() == 'process')
    observer_scope = next(scope for scope in symbols.get_children() if scope.get_name() == 'Observer')
    child_scope = next(scope for scope in observer_scope.get_children() if scope.get_name() == 'start_child')
    for scope in (process_scope, child_scope):
        if not scope.lookup('subprocess').is_global():
            raise ValueError('process authority is shadowed')
    expected_launches = {
        'process': 'subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENVIRONMENT, start_new_session=True)',
        'start_child': 'subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENVIRONMENT, start_new_session=True)',
        'run': 'process(arguments, timeout=timeout)',
    }
    allowed_calls = set()
    for owner, expression in expected_launches.items():
        definitions = [node for node in (runner.body if owner == 'process' else next(node for node in runner.body if isinstance(node, ast.ClassDef) and node.name == 'Observer').body) if isinstance(node, ast.FunctionDef) and node.name == owner]
        if len(definitions) != 1:
            raise ValueError('fixed execution helper absent or duplicated')
        expected = ast.dump(ast.parse(expression, mode='eval').body)
        calls = [node for node in ast.walk(definitions[0]) if isinstance(node, ast.Call) and ast.dump(node) == expected]
        if len(calls) != 1:
            raise ValueError('fixed execution helper shape changed')
        if owner != 'process':
            guard = ast.parse("if operation not in contract.OPERATIONS:\n raise Failure('validate-authorization', 'identity-mismatch')").body[0]
            if ast.dump(definitions[0].body[0]) != ast.dump(guard):
                raise ValueError('execution operation is not admitted before launch')
        allowed_calls.add(calls[0])
    launch_functions = {node.func for node in allowed_calls}
    for node in ast.walk(runner):
        if isinstance(node, ast.Name) and node.id == 'subprocess' and not isinstance(node.ctx, ast.Load):
            raise ValueError('process module authority is reassigned')
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'getattr' and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == 'subprocess':
            raise ValueError('dynamic process authority')
        if isinstance(node, ast.ImportFrom) and node.module == 'subprocess':
            raise ValueError('aliased process authority')
        if isinstance(node, ast.Import) and any(item.name == 'subprocess' and item.asname for item in node.names):
            raise ValueError('aliased process authority')
        if ((isinstance(node, ast.Name) and node.id == 'process') or
                (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'subprocess' and node.attr in {'Popen', 'run', 'call', 'check_call', 'check_output'})) and node not in launch_functions:
            raise ValueError('unclassified process authority')
    for node in ast.walk(runner):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec', '__import__'}:
                raise ValueError('arbitrary privileged execution')
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'system', 'popen'}:
                raise ValueError('arbitrary privileged execution')
            execution_call = (isinstance(node.func, ast.Attribute) and node.func.attr in {'Popen', 'run', 'call', 'check_call', 'check_output'}) or (isinstance(node.func, ast.Name) and node.func.id == 'process')
            if execution_call and node not in allowed_calls and not (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'self' and node.func.attr == 'run'):
                raise ValueError('unclassified privileged execution')
            if execution_call and any(keyword.arg == 'shell' and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False) for keyword in node.keywords):
                raise ValueError('arbitrary privileged execution')
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'run', 'start_child'}:
                if not node.args or not isinstance(node.args[0], ast.Constant) or node.args[0].value not in operations:
                    raise ValueError('trusted operation lacks bounded semantic diagnostic')
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == 'operation':
                    dynamic_guarded = (isinstance(node.value, ast.Name) and node.value.id == 'operation'
                                       and 'if operation not in contract.OPERATIONS:' in (directory / 'qualify-product-backends.py').read_text())
                    if not dynamic_guarded and (not isinstance(node.value, ast.Constant) or node.value.value not in operations):
                        raise ValueError('unclassified trusted operation')
    text = (root / '.github/workflows/rocky-cloud-qualification.yml').read_text()
    required = ('native-postgresql-18 | product-backend-policy)', '[[ -z "$RAW_TARGET_SHA" ]]',
                '[[ "$IS_DEFAULT_BRANCH" == true ]]', 'RAW_TARGET_SHA="$expected_target_sha"',
                'product-backend-qualification-control.py reconfirm', 'product-backend-qualification-control.py "$operation"',
                'sudo /usr/local/sbin/secpal-qualify-product-backends', 'Enforce product backend policy qualification result')
    if any(value not in text for value in required):
        raise ValueError('accepted-main dispatch/admission boundary absent')
    metadata = (root / 'infra/ci-cloud/gcp-rocky/metadata.tf').read_text()
    bootstrap = (directory / 'bootstrap-rocky-host.tftpl').read_text()
    for name, relative in sources.items():
        if f'file("${{path.module}}/../../../{relative}")' not in metadata:
            raise ValueError('exact source closure not transported')
        if f'/opt/secpal-control/{relative}' not in bootstrap:
            raise ValueError('source closure not installed through trusted path')


def main():
    try:
        validate(ROOT)
    except (ValueError, OSError, SyntaxError, TypeError, StopIteration, KeyError):
        print('FAIL: product backend qualification trust/diagnostic boundary', file=sys.stderr)
        return 1
    print('Product backend qualification trust/diagnostic boundary passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
