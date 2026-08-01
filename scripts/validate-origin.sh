#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'ERROR: expected exactly one origin URL.\n' >&2
  exit 1
fi

case "$1" in
  git@github.com:SecPal/deployment.git | \
    https://github.com/SecPal/deployment | \
    https://github.com/SecPal/deployment.git)
    ;;
  *)
    printf 'ERROR: origin must point to the canonical SecPal/deployment repository.\n' >&2
    exit 1
    ;;
esac
