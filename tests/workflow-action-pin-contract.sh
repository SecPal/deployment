#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
VALIDATOR="$ROOT_DIR/scripts/validate-workflow-action-pins.sh"
umask 077
TEMP_DIR="$(mktemp -d -t secpal-workflow-action-pins.XXXXXXXXXX)"
failures=0

cleanup() {
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

expect_accepted() {
  local name="$1"
  local uses_line="$2"
  local workflow="$TEMP_DIR/$name.yml"

  printf '%s\n' 'jobs:' '  contract:' '    steps:' "      - $uses_line" > "$workflow"
  if ! "$VALIDATOR" "$workflow" >/dev/null 2>&1; then
    fail "valid workflow action reference was rejected: $name"
  fi
}

expect_rejected() {
  local name="$1"
  local uses_line="$2"
  local workflow="$TEMP_DIR/$name.yml"

  printf '%s\n' 'jobs:' '  contract:' '    steps:' "      - $uses_line" > "$workflow"
  if "$VALIDATOR" "$workflow" >/dev/null 2>&1; then
    fail "invalid workflow action reference was accepted: $name"
  fi
}

if [ ! -x "$VALIDATOR" ]; then
  fail "the workflow action pin validator is missing or not executable"
else
  sha='0123456789abcdef0123456789abcdef01234567'

  expect_accepted pinned-tag "uses: actions/checkout@$sha # v7.0.1"
  expect_accepted pinned-branch "uses: SecPal/.github/.github/workflows/reuse.yml@$sha # main"
  expect_accepted quoted-pin "uses: \"actions/checkout@$sha\" # v7.0.1"
  expect_accepted local-action 'uses: ./.github/actions/local'

  expect_rejected mutable-tag 'uses: actions/checkout@v7 # v7.0.1'
  expect_rejected sha-in-comment "uses: actions/checkout@v7 # decoy @$sha # v7.0.1"
  expect_rejected sha-prefix "uses: actions/checkout@${sha}suffix # v7.0.1"
  expect_rejected short-sha 'uses: actions/checkout@0123456789abcdef # v7.0.1'
  expect_rejected missing-source-comment "uses: actions/checkout@$sha"
  expect_rejected empty-source-comment "uses: actions/checkout@$sha #"
  expect_rejected nested-comment "uses: actions/checkout@$sha # # v7.0.1"
  expect_rejected quoted-key "\"uses\": actions/checkout@v7 # @$sha # v7.0.1"
  expect_rejected flow-mapping "{ uses: actions/checkout@v7, name: Checkout } # @$sha # v7.0.1"
fi

if [ "$failures" -ne 0 ]; then
  printf 'Workflow action pin contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Workflow action pin contract passed.\n'
