# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keep deployment automation restricted to qualified CI-only Actions updates."""
import json
from pathlib import Path
import unittest
import yaml


class EnrollmentContract(unittest.TestCase):
    def test_only_accepted_ci_workflows_can_enroll(self):
        path = Path('.github/workflows/dependabot-auto-merge.yml')
        self.assertTrue(path.is_file(), 'native immutable caller must exist')
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        trigger = workflow['on']['pull_request_target']
        self.assertEqual(trigger['branches'], ['main'])
        for event in ['opened', 'synchronize', 'reopened', 'ready_for_review',
                      'labeled', 'unlabeled', 'edited', 'converted_to_draft']:
            self.assertIn(event, trigger['types'])
        self.assertNotIn('pull_request', workflow['on'])
        self.assertEqual(workflow['cache-mode'], 'none')
        self.assertEqual(workflow['concurrency']['cancel-in-progress'], 'true')
        job = workflow['jobs']['auto-merge']
        for key in ['if', 'steps', 'secrets']:
            self.assertNotIn(key, job)
        self.assertRegex(job['uses'], r'^SecPal/\.github/\.github/workflows/reusable-dependabot-auto-merge\.yml@[0-9a-f]{40}$')
        self.assertEqual(job['with']['phase'], '1')
        self.assertEqual(job['with']['merge-method'], 'squash')
        self.assertEqual(job['with']['allowed-ecosystems'], 'github_actions')
        self.assertEqual(json.loads(job['with']['workflow-paths']), [
            '.github/workflows/quality.yml',
            '.github/workflows/local-integration.yml',
            '.github/workflows/rocky-evidence-architecture.yml',
        ])
        self.assertEqual(workflow['permissions'], {'contents': 'write', 'pull-requests': 'write'})


if __name__ == '__main__':
    unittest.main()
