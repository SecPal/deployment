#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Real pinned producer regression; apply runs in a loopback-only namespace.

Initialization alone has package-network access. The endpoint accepts TCP but
never reads application data. No credentials or caller environment are inherited.
Use --required to reject unavailable Linux namespace/inet_diag capabilities.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci-cloud'))
import instance_transport_contract as contract

spec = importlib.util.spec_from_file_location('transport_observer', ROOT / 'scripts/ci-cloud/observe-instance-transport.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)

INSTALL = Path('.terraform/providers/registry.opentofu.org/hashicorp/google/7.40.0/linux_amd64')
EXECUTABLE_SHA256 = '70351ed626f69ac84315e8ed5149986eafd7628c8d4b0eda4422f82665ec41e9'
LOCK_SHA256 = '76f52a817f68fcb058bf499482070b4ff39098628c497a95ff8de2b42363e94c'
CONFIG = '''terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "= 7.40.0"
    }
  }
}
provider "google" {
  project = "local-observer-test"
  access_token = "synthetic-local-only"
  universe_domain = "local.invalid"
  compute_custom_endpoint = "http://127.0.0.1:443/compute/v1/"
}
resource "google_compute_network" "local" {
  name = "local-observer-test"
  auto_create_subnetworks = false
}
'''


def identity():
    return dict(repository='SecPal/deployment', trusted_control_sha='a'*40,
                target_sha='b'*40, workflow_run_id='12345', workflow_run_attempt='1',
                provider_profile='gcp-rocky-10-2-x86-64', project='secpal-dev',
                zone='europe-west3-a', expected_instance_name='sprk-12345-1-instance')


def isolated_topology(fixture, tofu):
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    assert socket.if_nameindex() == [(1, 'lo')], 'non-local interface present'
    assert Path('/proc/self/net/route').read_text().count('\n') == 1, 'external route present'
    actual = fixture / INSTALL / 'terraform-provider-google'
    assert hashlib.sha256(actual.read_bytes()).hexdigest() == EXECUTABLE_SHA256
    assert not actual.with_name('terraform-provider-google_v7.40.0_x5').exists()
    server = socket.socket()
    server.bind(('127.0.0.1', 443))
    server.listen(4)
    server.settimeout(30)
    # A similarly named unrelated executable owns port-443 traffic in the same
    # namespace and descendant tree. Neither its name nor its socket is authority.
    spoof = fixture/'terraform-provider-google'
    shutil.copyfile(Path(sys.executable).resolve(), spoof)
    spoof.chmod(0o755)
    unrelated = subprocess.Popen([str(spoof), '-c',
        "import socket,sys; c=socket.socket(); c.connect(('127.0.0.1',443)); "
        "print('READY',flush=True); sys.stdin.read()"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    other_peer, _ = server.accept()
    assert unrelated.stdout.readline() == 'READY\n'
    unrelated_rows = [row for row in observer.socket_rows(unrelated.pid, observer.owned_inodes(unrelated.pid)) if row['remote_port'] == 443]
    assert len(unrelated_rows) == 1
    collectors, producers, errors = [], [], []
    popen = subprocess.Popen
    original = observer.Observer

    class RecordingObserver(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            collectors.append(self)

    def launch(argv):
        assert argv == ['tofu', 'apply', '--auto-approve', '--input=false']
        process = popen([str(tofu), *argv[1:]], cwd=fixture,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        producers.append(process)
        return process

    def run():
        try:
            observer.observe_apply(identity(), fixture/'transport.json')
        except Exception as exc:
            errors.append(type(exc).__name__)

    previous = Path.cwd()
    peer = None
    independent = None
    try:
        os.chdir(fixture)
        with patch.object(observer, 'Observer', RecordingObserver), patch.object(observer.subprocess, 'Popen', launch):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            peer, _ = server.accept()
            assert len(producers) == len(collectors) == 1
            producer, selected = producers[0], collectors[0]
            genuine = observer.provider_processes(producer.pid, {actual})
            assert len(genuine) == 1, 'genuine provider independently absent'
            pid, ticks = genuine[0]
            assert Path(os.readlink(f'/proc/{pid}/exe')) == actual
            rows = [row for row in observer.socket_rows(pid, observer.owned_inodes(pid)) if row['remote_port'] == 443]
            assert len(rows) == 1, 'genuine owned socket independently absent'
            query = observer.exact_query(rows[0])
            assert query is not None and query['state'] == 'ESTABLISHED'
            independent = original(producer.pid, {actual})
            independent.prepare()
            independent.sample()
            assert len(independent.connections) == 1, 'unchanged authentic correlation failed'
            assert observer.provider_processes(producer.pid, {actual.with_name('wrong-identity')}) == []
            start = time.monotonic()
            time.sleep(13)
            assert producer.poll() is None and observer.process_ticks(pid) == ticks
            assert rows[0]['inode'] in observer.owned_inodes(pid)
            production_processes = observer.provider_processes(producer.pid, selected.provider_paths)
            assert production_processes == genuine, (
                'WRONG_PINNED_PROVIDER_EXECUTABLE_IDENTITY: genuine provider and '
                '13-second owned socket present, production selection excluded both')
            selected.installation.verify_process(pid)
            with_exception = False
            try:
                selected.installation.verify_process(unrelated.pid)
            except contract.TransportError:
                with_exception = True
            assert with_exception, 'same-basename spoof admitted'
            assert len(selected.connections) == 1
            connection = next(iter(selected.connections.values()))
            assert connection['process_id'] == pid
            assert connection['socket_cookie'] == query['socket_cookie']
            assert connection['local_port'] != unrelated_rows[0]['local_port']
            print('PASS: real OpenTofu 1.12.5 / Google 7.40.0 executable, process, '
                  'owned socket, inet_diag and unrelated connection exclusion; '
                  f'socket retained {time.monotonic()-start:.2f}s', flush=True)
    finally:
        for process in producers:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if 'thread' in locals():
            thread.join(5)
        if independent is not None:
            independent.finish()
        unrelated.stdin.close()
        unrelated.wait(5)
        unrelated.stdout.close()
        for stream in (peer, other_peer, server):
            if stream is not None:
                stream.close()
        os.chdir(previous)
    assert not errors, errors
    document = contract.decode_document((fixture/'transport.json').read_bytes())
    contract.admit(document, identity())
    assert document['collection_status'] == 'COMPLETE'
    assert len(document['connections']) == 1


def installation_negatives(fixture):
    """Substitute paths around the real admitted package; never patch its bytes."""
    executable = fixture/INSTALL/'terraform-provider-google'
    lock = fixture/'.terraform.lock.hcl'
    original_lock = lock.read_bytes()
    for case in ('missing', 'nonexecutable', 'ambiguous', 'basename', 'symlink',
                 'directory-symlink', 'version', 'source', 'lock-version', 'lock-source'):
        restore = lambda: None
        try:
            if case in ('missing', 'basename', 'symlink'):
                retained = fixture/'retained-provider'
                executable.rename(retained)
                def restore():
                    executable.unlink(missing_ok=True)
                    retained.rename(executable)
                if case == 'basename':
                    shutil.copyfile(Path(sys.executable).resolve(), executable)
                    executable.chmod(0o755)
                if case == 'symlink': executable.symlink_to(retained)
            elif case == 'nonexecutable':
                executable.chmod(0o644)
                restore = lambda: executable.chmod(0o755)
            elif case == 'ambiguous':
                extra = executable.with_name('terraform-provider-google_v7.40.0_x5')
                extra.write_bytes(b'unrelated'); extra.chmod(0o755)
                restore = extra.unlink
            elif case in ('directory-symlink', 'version', 'source'):
                path = executable.parent if case == 'directory-symlink' else executable.parent.parent if case == 'version' else fixture/'.terraform/providers/registry.opentofu.org/hashicorp'
                retained = fixture/'retained-directory'
                path.rename(retained)
                def restore():
                    if path.is_symlink(): path.unlink()
                    retained.rename(path)
                if case == 'directory-symlink': path.symlink_to(retained, target_is_directory=True)
            else:
                lock.write_bytes(original_lock.replace(b'7.40.0', b'7.40.1') if case == 'lock-version' else original_lock.replace(b'hashicorp/google', b'hashicorp/unrelated'))
                restore = lambda: lock.write_bytes(original_lock)
            try:
                admitted = observer.PinnedGoogleProvider(fixture)
            except (OSError, contract.TransportError):
                pass
            else:
                admitted.close()
                raise AssertionError('substitution admitted: '+case)
        finally:
            restore()
    authenticated = observer.PinnedGoogleProvider(fixture)
    authenticated.close()
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == EXECUTABLE_SHA256
    print('PASS: real pinned-package missing/ambiguous/executable/path/symlink/version/source substitutions rejected; binary contents unchanged')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--required', action='store_true')
    parser.add_argument('--tofu', type=Path, default=shutil.which('tofu'))
    parser.add_argument('--installed-package', type=Path,
                        help='reuse an exact package previously installed by readonly tofu init')
    parser.add_argument('--isolated-fixture', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.isolated_fixture:
        isolated_topology(args.isolated_fixture, args.tofu)
        installation_negatives(args.isolated_fixture)
        return 0
    unavailable = platform.system() != 'Linux' or platform.machine() != 'x86_64' or not args.tofu or not shutil.which('unshare') or not shutil.which('ip')
    if unavailable:
        print(('FAIL' if args.required else 'SKIP') + ': requires Linux x86_64, OpenTofu 1.12.5, unshare and ip')
        return 1 if args.required else 0
    tofu = args.tofu.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='transport-provider-') as directory:
        fixture = Path(directory)
        (fixture/'home').mkdir(mode=0o700)
        (fixture/'cli.tfrc').write_text('')
        env = {'PATH':'/usr/sbin:/usr/bin:/bin', 'HOME':str(fixture/'home'),
               'TF_CLI_CONFIG_FILE':str(fixture/'cli.tfrc'), 'CHECKPOINT_DISABLE':'1'}
        version = subprocess.run([str(tofu), 'version', '-json'], env=env, capture_output=True, check=True, timeout=10)
        assert json.loads(version.stdout)['terraform_version'] == '1.12.5'
        (fixture/'main.tf').write_text(CONFIG)
        lock = (ROOT/'infra/ci-cloud/gcp-rocky/.terraform.lock.hcl').read_bytes()
        assert hashlib.sha256(lock).hexdigest() == LOCK_SHA256
        (fixture/'.terraform.lock.hcl').write_bytes(lock)
        if args.installed_package:
            shutil.copytree(args.installed_package.resolve(strict=True), fixture/INSTALL)
        else:
            # Only initialization can reach the package registry, before isolation.
            subprocess.run([str(tofu), 'init', '-backend=false', '-input=false', '-lockfile=readonly'],
                           cwd=fixture, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True, timeout=120)
        assert (fixture/'.terraform.lock.hcl').read_bytes() == lock
        capability = subprocess.run(['unshare', '--user', '--map-root-user', '--net', 'true'],
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if capability.returncode:
            print(('FAIL' if args.required else 'SKIP') + ': network namespace isolation unavailable')
            return 1 if args.required else 0
        result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable,
                                 str(Path(__file__).resolve()), '--isolated-fixture', str(fixture),
                                 '--tofu', str(tofu)], env=env, timeout=75)
        return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
