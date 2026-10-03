#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Read the canonical OpenTofu size decision before provider authentication."""

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2] / 'infra/ci-cloud/gcp-rocky'


def main():
    try:
        result = subprocess.run(
            ['tofu', '-chdir=' + str(ROOT), 'console', '-no-color'],
            input='jsonencode(local.rocky_metadata_admission)\n',
            capture_output=True, text=True, timeout=30, check=True)
        if len(result.stdout.encode()) > 8192:
            raise ValueError()
        report = json.loads(json.loads(result.stdout))
        fields = {'values', 'value_limit', 'value_safe_maximum', 'key_limit',
                  'aggregate_bytes', 'aggregate_limit', 'aggregate_safe_maximum',
                  'decoded_bytes', 'decoded_limit', 'admitted'}
        if (not isinstance(report, dict) or set(report) != fields
                or type(report['admitted']) is not bool
                or any(type(report[key]) is not int for key in fields - {'values', 'admitted'})
                or not isinstance(report['values'], dict) or len(report['values']) != 12):
            raise ValueError()
        for key, size in report['values'].items():
            if (not isinstance(key, str) or len(key) > 128
                    or not all(char in 'abcdefghijklmnopqrstuvwxyz-' for char in key)
                    or not isinstance(size, dict) or set(size) != {'key_bytes', 'value_bytes'}
                    or any(type(value) is not int or value < 0 for value in size.values())):
                raise ValueError()
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # OpenTofu stderr can contain variable/source material. Never relay it.
        print('ROCKY_METADATA_ADMISSION_UNAVAILABLE', file=sys.stderr)
        return 1
    print('ROCKY_METADATA_ADMISSION ' + json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['admitted'] else 1


if __name__ == '__main__':
    sys.exit(main())
