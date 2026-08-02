#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'ERROR: expected exactly one origin URL.\n' >&2
  exit 1
fi

remote_url="${1%/}"
remote_url="${remote_url%.git}"

case "$remote_url" in
  git@github.com:SecPal/deployment | \
    ssh://git@github.com/SecPal/deployment | \
    https://github.com/SecPal/deployment)
    ;;
  *)
    printf 'ERROR: origin must point to the canonical SecPal/deployment repository.\n' >&2
    exit 1
    ;;
esac
