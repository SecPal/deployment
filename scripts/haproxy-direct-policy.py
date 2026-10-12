#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Administrator-owned private DIRECT seam. No public-ingress activation."""

import argparse
import json
import os
from pathlib import Path
import pwd
import runpy
import stat
import subprocess
import sys
import tempfile

HELPER = Path('/usr/local/libexec/secpal/haproxy-direct-policy')
LIBRARIES = ('haproxy_direct_contract.py', 'haproxy_direct_policy.py', 'haproxy_base_contract.py', 'product_backend_contract.py')
SPEC = Path('/etc/haproxy/secpal-routing.json')
SERVING = Path('/etc/haproxy/secpal.cfg')
STATE = Path('/run/secpal-direct-policy')
READY = STATE / 'ready.json'


def trusted(path, *, regular=True):
    for item in (path, *path.parents):
        info = item.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('admit-direct-policy-path')
    info = path.lstat()
    if regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError('admit-direct-policy-file')


def admit_source_before_import():
    if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError('admit-installed-administrator-helper')
    for path in (HELPER, *(HELPER.parent / name for name in LIBRARIES)):
        trusted(path)


if __name__ == '__main__':
    try:
        admit_source_before_import()
        # Compile admitted source, never an adjacent cache whose ownership was
        # not admitted. This private per-process namespace starts empty.
        temporary = Path('/tmp').lstat()
        if (temporary.st_uid != 0 or not stat.S_ISDIR(temporary.st_mode)
                or (temporary.st_mode & 0o022 and not temporary.st_mode & stat.S_ISVTX)):
            raise ValueError('admit-administrator-temporary-path')
        _source_cache = tempfile.TemporaryDirectory(prefix='secpal-haproxy-imports-', dir='/tmp')
        sys.pycache_prefix = _source_cache.name
        sys.dont_write_bytecode = True
    except (ValueError, OSError):
        print('FAIL: admit-installed-source', file=sys.stderr)
        raise SystemExit(1)

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from haproxy_direct_contract import decode_document, from_config
from haproxy_direct_policy import host_policy, digest, admit_table
from product_backend_contract import admit_policy_account


def observe(operation, args, *, input_text=None, accepted=(0,)):
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=60,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(operation) from error
    if result.returncode not in accepted or len(result.stdout.encode()) > 65536 or len(result.stderr.encode()) > 65536:
        raise ValueError(operation)
    return result


def table():
    return json.loads(observe('observe-direct-table',
        ['/usr/sbin/nft', '--json', 'list', 'table', 'inet', 'secpal_direct']).stdout)


def authority(*, desired=False):
    if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError('admit-installed-direct-policy')
    source = SPEC if desired else SERVING
    for path in (HELPER, source, HELPER.parent / 'product-backend-policy', *(HELPER.parent / name for name in LIBRARIES)):
        trusted(path)
    if not 0 < source.stat().st_size <= 65536:
        raise ValueError('admit-direct-policy-spec-size')
    account = pwd.getpwnam('haproxy')
    uid = admit_policy_account(account, 0)
    # Consume the accepted #101 effective policy and account boundary unchanged.
    observe('admit-backend-policy', ['/usr/bin/python3', '-I', str(HELPER.parent / 'product-backend-policy'), '--check'])
    spec = decode_document(source.read_bytes()) if desired else from_config(source.read_bytes())
    return spec, uid, host_policy(spec, uid)


def effective_decoder_policy():
    # Fixed, already ownership-admitted #101 platform observer. Reuse its
    # libselinux kernel decision primitive; #220 owns only these new facts.
    native = runpy.run_path(str(HELPER.parent / 'product-backend-policy'))
    for permission in ('name_bind', 'name_connect'):
        if not native['effective_access']('haproxy_t', 'secpal_direct_decoder_port_t', permission):
            raise ValueError('admit-effective-decoder-selinux')
        # Stock container domains already have generic port_type authority.
        # Do not claim exclusivity that the installed policy does not provide,
        # or expand their preexisting unreserved-port decisions. nftables owns
        # the complementary host UID/peer isolation.
        for source in ('container_runtime_t', 'container_t'):
            if native['effective_access'](source, 'secpal_direct_decoder_port_t', permission) != native['effective_access'](source, 'unreserved_port_t', permission):
                raise ValueError('admit-unchanged-container-selinux')
    # SETools observes the installed kernel policy; it is already supplied by
    # the accepted Rocky setools-console package, not a new runtime dependency.
    import setools
    policy = setools.SELinuxPolicy()
    for port in (18082, 18083):
        rows = [row for row in policy.portcons() if str(row.protocol) == 'tcp'
                and row.ports.low <= port <= row.ports.high]
        if not rows or str(min(rows, key=lambda row: row.ports.high - row.ports.low).context.type_) != 'secpal_direct_decoder_port_t':
            raise ValueError('admit-effective-decoder-port-label')

def check(spec, uid, policy, *, kernel=True):
    trusted(READY)
    if not 0 < READY.stat().st_size <= 1024:
        raise ValueError('admit-direct-marker-size')
    marker = json.loads(READY.read_bytes())
    if type(marker) is not dict or marker != {'policy_sha256': digest(policy)}:
        raise ValueError('admit-direct-policy-marker')
    if kernel:
        admit_table(table(), spec, uid)
    if observe('observe-direct-selinux', ['/usr/sbin/getenforce']).stdout.strip() != 'Enforcing':
        raise ValueError('admit-direct-enforcing')
    effective_decoder_policy()


def activate(spec, uid, policy):
    if observe('observe-direct-service-state', ['/usr/bin/systemctl', 'show', 'haproxy.service',
                '--property=ActiveState', '--value']).stdout.strip() != 'inactive':
        raise ValueError('admit-direct-stopped-service')
    STATE.mkdir(mode=0o755, exist_ok=True)
    trusted(STATE, regular=False)
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('admit-direct-state-directory')
    READY.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='activate-', dir=STATE) as directory:
        module = Path(directory) / 'secpal_direct_decoder.cil'
        module.write_text(policy['cil'])
        observe('install-direct-decoder-selinux', ['/usr/sbin/semodule', '-i', str(module), '-e', 'secpal_direct_decoder'])
    previous = observe('observe-existing-direct-table', ['/usr/sbin/nft', 'list', 'table', 'inet', 'secpal_direct'], accepted=(0, 1))
    rules = ('delete table inet secpal_direct\n' if previous.returncode == 0 else '') + policy['nft']
    observe('validate-direct-table', ['/usr/sbin/nft', '--check', '-f', '-'], input_text=rules)
    observe('activate-direct-table', ['/usr/sbin/nft', '-f', '-'], input_text=rules)
    descriptor, name = tempfile.mkstemp(prefix='ready-', dir=STATE)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            admit_table(table(), spec, uid)
            json.dump({'policy_sha256': digest(policy)}, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o444)
        os.replace(name, READY)
    finally:
        Path(name).unlink(missing_ok=True)
    check(spec, uid, policy)


def direct_table_present():
    document = json.loads(observe('observe-direct-table-inventory',
        ['/usr/sbin/nft', '--json', 'list', 'tables']).stdout)
    if type(document) is not dict or set(document) != {'nftables'} or type(document['nftables']) is not list:
        raise ValueError('admit-direct-table-inventory')
    return any(row.get('table', {}).get('family') == 'inet'
               and row.get('table', {}).get('name') == 'secpal_direct'
               for row in document['nftables'])


def decoder_module_present():
    return any(row.split()[0] == 'secpal_direct_decoder' for row in
               observe('observe-decoder-module-inventory', ['/usr/sbin/semodule', '-l']).stdout.splitlines()
               if row.split())


def withdraw():
    # Installed-source admission precedes imports. Withdrawal deliberately does
    # not consume desired/serving input or #101's marker: either may be invalid
    # or already withdrawn after partial startup or a managed firewall restart.
    # BindsTo + After on the HA listener orders its shutdown before this action.
    state = observe('observe-direct-withdrawal-service', ['/usr/bin/systemctl', 'show',
                    'haproxy.service', '--property=ActiveState', '--value']).stdout.strip()
    if state not in ('inactive', 'failed'):
        raise ValueError('admit-direct-withdrawal-stopped-service')
    if STATE.exists():
        trusted(STATE, regular=False)
        READY.unlink(missing_ok=True)
    listeners = observe('observe-direct-withdrawal-listeners', ['/usr/sbin/ss', '-H', '-lnt']).stdout
    if any(row.split()[3].rsplit(':', 1)[-1] in {'18082', '18083'} for row in listeners.splitlines()):
        raise ValueError('admit-direct-withdrawal-empty-decoders')
    if direct_table_present():
        observe('withdraw-direct-table', ['/usr/sbin/nft', 'delete', 'table', 'inet', 'secpal_direct'])
    if decoder_module_present():
        observe('withdraw-direct-decoder-module', ['/usr/sbin/semodule', '-r', 'secpal_direct_decoder'])
    if READY.exists() or direct_table_present() or decoder_module_present():
        raise ValueError('admit-direct-withdrawal-empty-state')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--activate', action='store_true')
    action.add_argument('--check', action='store_true')
    action.add_argument('--withdraw', action='store_true')
    action.add_argument('--check-marker', action='store_true', help='Source-bound barrier after the policy service kernel check')
    parser.add_argument('--desired', action='store_true', help='Explicit stopped-host construction from the fixed desired document')
    args = parser.parse_args()
    if args.withdraw:
        if args.desired:
            raise ValueError('admit-direct-withdrawal-input')
        withdraw()
        return
    spec, uid, policy = authority(desired=args.desired)
    activate(spec, uid, policy) if args.activate else check(spec, uid, policy, kernel=not args.check_marker)


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print(f'FAIL: {error}', file=sys.stderr)
        raise SystemExit(1)
    except (OSError, KeyError, TypeError, ImportError, AttributeError, RuntimeError, subprocess.SubprocessError):
        print('FAIL: direct-private-policy-authority', file=sys.stderr)
        raise SystemExit(1)
