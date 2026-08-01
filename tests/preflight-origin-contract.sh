#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
VALIDATOR="$ROOT_DIR/scripts/validate-origin.sh"
failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

expect_accepted() {
  local remote_url="$1"

  if ! "$VALIDATOR" "$remote_url" >/dev/null 2>&1; then
    fail "canonical origin was rejected: $remote_url"
  fi
}

expect_rejected() {
  local remote_url="$1"

  if "$VALIDATOR" "$remote_url" >/dev/null 2>&1; then
    fail "non-canonical origin was accepted: $remote_url"
  fi
}

if [ ! -x "$VALIDATOR" ]; then
  fail "the origin validator is missing or not executable"
else
  expect_accepted 'git@github.com:SecPal/deployment.git'
  expect_accepted 'https://github.com/SecPal/deployment'
  expect_accepted 'https://github.com/SecPal/deployment.git'

  expect_rejected 'https://github.com/SecPal/deployment-fork'
  expect_rejected 'https://example.invalid/SecPal/deployment.git'
  expect_rejected 'git@github.com:Other/deployment.git'
fi

if [ "$failures" -ne 0 ]; then
  printf 'Preflight origin contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Preflight origin contract passed.\n'
