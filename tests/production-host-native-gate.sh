#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

if [[ "$(awk -F= '$1 == "ID" {gsub(/^"|"$/, "", $2); print $2; exit}' /etc/os-release)" == rocky ]]; then
  printf 'Native gate fixture is intended for generic non-Rocky development hosts.\n'
  exit 0
fi

set +e
output="$(scripts/qualify-production-host.sh 2>&1)"
status=$?
set -e
if ((status != 2)); then
  printf 'Expected native qualification to report NOT RUN with status 2; got %d.\n%s\n' "$status" "$output" >&2
  exit 1
fi
if [[ "$output" != NOT\ RUN:* ]]; then
  printf 'Native qualification did not clearly report NOT RUN.\n%s\n' "$output" >&2
  exit 1
fi

printf 'Production-host native gate correctly reported NOT RUN on this non-Rocky host.\n'
