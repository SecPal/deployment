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

expect_document_accepted() {
  local name="$1"
  local document="$2"
  local workflow="$TEMP_DIR/$name.yml"

  printf '%s\n' "$document" > "$workflow"
  if ! "$VALIDATOR" "$workflow" >/dev/null 2>&1; then
    fail "valid workflow document was rejected: $name"
  fi
}

expect_document_rejected() {
  local name="$1"
  local document="$2"
  local workflow="$TEMP_DIR/$name.yml"

  printf '%s\n' "$document" > "$workflow"
  if "$VALIDATOR" "$workflow" >/dev/null 2>&1; then
    fail "invalid workflow document was accepted: $name"
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
  expect_accepted scalar-containing-flow-syntax 'run: "echo '\''{ uses: not-an-action }'\''"'
  expect_document_accepted block-scalar-content $'jobs:\n  contract:\n    steps:\n      - run: |\n          "https://example.invalid/{ uses: not-an-action }"'
  expect_document_accepted quoted-list-value $'on:\n  push:\n    branches:\n      - "main"'
  expect_document_accepted quoted-flow-scalar $'env:\n  EXAMPLE: ["uses: not-an-action"]'

  expect_document_rejected implicit-flow-sequence $'jobs:\n  contract:\n    steps: [uses: actions/checkout@v7]'
  expect_document_rejected multiline-implicit-flow-sequence $'jobs:\n  contract:\n    steps:\n      [uses: actions/checkout@v7]'
  expect_document_rejected anchored-flow-mapping $'shared: &step { uses: actions/checkout@v7 }\njobs:\n  contract:\n    steps:\n      - *step'
  expect_document_rejected explicit-block-key $'jobs:\n  contract:\n    steps:\n      - ? >-\n          uses\n        : actions/checkout@v7'
  expect_document_rejected continued-quoted-key $'jobs:\n  contract:\n    steps:\n      - "us\\\n          es": actions/checkout@v7'

  expect_rejected mutable-tag 'uses: actions/checkout@v7 # v7.0.1'
  expect_rejected sha-in-comment "uses: actions/checkout@v7 # decoy @$sha # v7.0.1"
  expect_rejected sha-prefix "uses: actions/checkout@${sha}suffix # v7.0.1"
  expect_rejected short-sha 'uses: actions/checkout@0123456789abcdef # v7.0.1'
  expect_rejected missing-source-comment "uses: actions/checkout@$sha"
  expect_rejected empty-source-comment "uses: actions/checkout@$sha #"
  expect_rejected nested-comment "uses: actions/checkout@$sha # # v7.0.1"
  expect_rejected quoted-key "\"uses\": actions/checkout@v7 # @$sha # v7.0.1"
  expect_rejected escaped-uses-key '"us\x65s": actions/checkout@v7 # v7.0.1'
  expect_rejected flow-mapping "{ uses: actions/checkout@v7, name: Checkout } # @$sha # v7.0.1"
fi

if [ "$failures" -ne 0 ]; then
  printf 'Workflow action pin contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Workflow action pin contract passed.\n'
