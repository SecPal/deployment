#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  printf 'ERROR: cleanup initialization accepts no arguments.\n' >&2
  exit 2
fi

max_attempts=3
last_status=1

for ((attempt = 1; attempt <= max_attempts; attempt += 1)); do
  if timeout --signal=TERM --kill-after=15s 90s \
    tofu init -input=false -lockfile=readonly; then
    exit 0
  else
    last_status=$?
  fi
  if ((attempt == max_attempts)); then
    break
  fi
  delay=$((attempt * 10))
  printf 'WARNING: locked cleanup initialization attempt %d failed; retrying in %d seconds.\n' \
    "$attempt" "$delay" >&2
  sleep "$delay"
done

printf 'ERROR: locked cleanup initialization failed after %d attempts.\n' \
  "$max_attempts" >&2
exit "$last_status"
