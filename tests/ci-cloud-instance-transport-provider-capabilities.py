#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Capability admission must precede package access and never hide regressions."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location(
    'provider_harness', Path(__file__).with_name('ci-cloud-instance-transport-provider.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class CapabilityOrdering(unittest.TestCase):
    def invoke(self, *, required=False, installed=False, namespace=0, kernel=0,
               producer=0):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            tofu = Path(directory)/'tofu'
            tofu.touch()
            argv = ['provider-test', '--tofu', str(tofu)]
            if required:
                argv.append('--required')
            if installed:
                argv.extend(['--installed-package', directory])

            def run(command, **kwargs):
                if command[0] == 'unshare':
                    if command[-1] == 'true':
                        events.append('namespace')
                        code = namespace
                    elif '--probe-capabilities' in command:
                        events.append('capabilities')
                        code = kernel
                    else:
                        self.assertIn('--isolated-fixture', command)
                        events.append('producer')
                        code = producer
                    return subprocess.CompletedProcess(command, code)
                if command[1] == 'version':
                    return subprocess.CompletedProcess(command, 0,
                        json.dumps({'terraform_version':'1.12.5'}).encode())
                self.assertEqual(command[1], 'init')
                events.append('init')
                return subprocess.CompletedProcess(command, 0)

            out = io.StringIO()
            with patch.object(sys, 'argv', argv), \
                    patch.object(harness.platform, 'system', return_value='Linux'), \
                    patch.object(harness.platform, 'machine', return_value='x86_64'), \
                    patch.object(harness.shutil, 'which', side_effect=lambda name: '/usr/bin/'+name), \
                    patch.object(harness.subprocess, 'run', side_effect=run), \
                    patch.object(harness.shutil, 'copytree', side_effect=lambda *a: events.append('copy')), \
                    contextlib.redirect_stdout(out):
                result = harness.main()
            return result, out.getvalue(), events

    def test_namespace_denied_before_init_or_installed_package(self):
        for required in (False, True):
            for installed in (False, True):
                with self.subTest(required=required, installed=installed):
                    result, output, events = self.invoke(
                        required=required, installed=installed, namespace=1)
                    self.assertEqual(result, int(required))
                    self.assertIn('FAIL' if required else 'SKIP', output)
                    self.assertEqual(events, ['namespace'])

    def test_kernel_capability_denied_before_acquisition_and_producer(self):
        for required in (False, True):
            for installed in (False, True):
                with self.subTest(required=required, installed=installed):
                    result, output, events = self.invoke(
                        required=required, installed=installed, kernel=77)
                    self.assertEqual(result, int(required))
                    self.assertIn('FAIL' if required else 'SKIP', output)
                    self.assertEqual(events, ['namespace', 'capabilities'])

    def test_supported_environment_admitted_before_each_package_path(self):
        for installed in (False, True):
            result, _, events = self.invoke(installed=installed)
            self.assertEqual(result, 0)
            self.assertEqual(events, ['namespace', 'capabilities',
                                     'copy' if installed else 'init', 'producer'])

    def test_probe_implementation_failure_is_not_an_environment_skip(self):
        result, output, events = self.invoke(kernel=1)
        self.assertEqual(result, 1)
        self.assertNotIn('SKIP', output)
        self.assertNotIn('init', events)
        self.assertNotIn('producer', events)

    def test_producer_observer_failure_after_capability_pass_is_not_skip(self):
        result, output, events = self.invoke(producer=1)
        self.assertEqual(result, 1)
        self.assertNotIn('SKIP', output)
        self.assertEqual(events, ['namespace', 'capabilities', 'init', 'producer'])

    def test_inner_observer_failure_cannot_be_classified_as_unsupported(self):
        def broken_observer(*args):
            harness.observer.Observer.prepare(None)
        with patch.object(sys, 'argv', ['provider-test', '--isolated-fixture', '/unused']), \
                patch.object(harness, 'probe_capabilities', create=True), \
                patch.object(harness, 'isolated_topology', side_effect=broken_observer), \
                patch.object(harness.observer.Observer, 'prepare', side_effect=PermissionError(1, 'induced observer regression')), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(PermissionError, 'induced observer regression'):
                harness.main()
            self.assertNotIn('SKIP', out.getvalue())

    def test_reported_startup_failure_fails_before_waiting_for_socket(self):
        server, thread = Mock(), Mock()
        thread.is_alive.return_value = False
        with self.assertRaisesRegex(AssertionError, 'after capability admission'):
            harness.accept_provider(server, thread)
        server.accept.assert_not_called()

    def test_only_known_platform_failures_can_be_unsupported(self):
        with patch.object(harness, 'probe_capabilities', side_effect=PermissionError(1, 'denied')):
            self.assertEqual(harness.capability_probe_result(), 77)
        for error in (OSError(5, 'unexpected I/O'), AssertionError('probe regression')):
            with self.subTest(error=type(error).__name__), \
                    patch.object(harness, 'probe_capabilities', side_effect=error):
                with self.assertRaises(type(error)):
                    harness.capability_probe_result()


if __name__ == '__main__':
    unittest.main()
