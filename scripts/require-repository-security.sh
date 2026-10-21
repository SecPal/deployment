#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# The organization action owns evidence validation and policy classification.
# Deployment admits only its successful CLEAN result, including at required CI.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'Repository source security admission requires a result and gate state.\n' >&2
  exit 1
fi
if [ "$1" != success ] || [ "$2" != CLEAN ]; then
  printf 'Repository source security did not admit successful CLEAN evidence.\n' >&2
  exit 1
fi
