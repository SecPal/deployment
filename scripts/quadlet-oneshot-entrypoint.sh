#!/bin/sh
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -eu

release=/tmp/secpal-inspection-release
attempt=0

while [ ! -f "$release" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -gt 1800 ]; then
    printf 'ERROR: one-shot runtime inspection was not released.\n' >&2
    exit 1
  fi
  sleep 0.1
done

# Let the releasing podman exec return before a deliberately failing command
# can terminate and auto-remove the one-shot container.
sleep 1
rm -f -- "$release"
exec "$@"
