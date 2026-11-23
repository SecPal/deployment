# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keep deployment automation restricted to qualified CI, hook, Python, and gateway inputs."""
import json
from pathlib import Path
import unittest
import yaml


class EnrollmentContract(unittest.TestCase):
    def test_pip_preserves_the_five_environments_and_groups_by_dependency_name(self):
        expected = ['build', 'integration', 'qualification', 'quality', 'schema']
        directories = [f'/requirements/{directory}' for directory in expected]
        config = yaml.safe_load(Path('.github/dependabot.yml').read_text())
        pip, = [entry for entry in config['updates'] if entry['package-ecosystem'] == 'pip']
        self.assertEqual(pip['directories'], directories)
        self.assertEqual(pip['groups'], {'deployment-python': {
            'group-by': 'dependency-name', 'update-types': ['patch', 'minor'],
        }})
        caller = yaml.load(Path('.github/workflows/dependabot-auto-merge.yml').read_text(),
                           Loader=yaml.BaseLoader)
        inputs = caller['jobs']['auto-merge']['with']
        self.assertEqual(json.loads(inputs['pip-plain-manifest-paths']),
                         [f'{directory[1:]}/requirements.txt' for directory in directories])

    def test_only_accepted_paths_and_gateway_rule_can_enroll(self):
        path = Path('.github/workflows/dependabot-auto-merge.yml')
        self.assertTrue(path.is_file(), 'native immutable caller must exist')
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        trigger = workflow['on']['pull_request_target']
        self.assertNotIn('branches', trigger)
        for event in ['opened', 'synchronize', 'reopened', 'ready_for_review',
                      'labeled', 'unlabeled', 'edited', 'converted_to_draft']:
            self.assertIn(event, trigger['types'])
        self.assertNotIn('pull_request', workflow['on'])
        self.assertEqual(workflow['concurrency']['cancel-in-progress'], 'true')
        job = workflow['jobs']['auto-merge']
        for key in ['if', 'steps', 'secrets']:
            self.assertNotIn(key, job)
        self.assertRegex(
            job['uses'],
            r'\ASecPal/\.github/\.github/workflows/reusable-dependabot-auto-merge\.yml@[0-9a-f]{40}\Z',
        )
        self.assertEqual(job['with']['phase'], '2')
        self.assertEqual(job['with']['merge-method'], 'squash')
        self.assertEqual(job['with']['allowed-ecosystems'], 'github_actions,npm_and_yarn,pre_commit,docker,pip')
        self.assertEqual(json.loads(job['with']['docker-rules']), [{
            'image': 'library/caddy',
            'paths': ['containers/phase-b-gateway/Containerfile'],
            'line': '2.11',
            'suffix': '-alpine',
            'digestRefresh': True,
        }])
        self.assertEqual(job['with']['pre-commit-path'], '.pre-commit-config.yaml')
        self.assertEqual(json.loads(job['with']['workflow-paths']), [
            '.github/workflows/quality.yml',
            '.github/workflows/local-integration.yml',
            '.github/workflows/rocky-evidence-architecture.yml',
        ])
        self.assertEqual(workflow['permissions'], {'contents': 'write', 'pull-requests': 'write', 'checks': 'read', 'statuses': 'read'})


if __name__ == '__main__':
    unittest.main()
