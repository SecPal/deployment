#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
VALIDATOR="$ROOT_DIR/scripts/validate-workflow-action-pins.py"
failures=0

check_document() {
  local expectation="$1"
  local name="$2"
  local document="$3"

  if python3 "$VALIDATOR" <(printf '%s\n' "$document") >/dev/null 2>&1; then
    [ "$expectation" = accept ] || {
      printf 'FAIL: invalid workflow was accepted: %s\n' "$name" >&2
      failures=$((failures + 1))
    }
  elif [ "$expectation" = accept ]; then
    printf 'FAIL: valid workflow was rejected: %s\n' "$name" >&2
    failures=$((failures + 1))
  fi
}

sha='0123456789abcdef0123456789abcdef01234567'
digest='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

check_document accept pinned-action $'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@'"$sha"$' # v7.0.1'
check_document accept pinned-workflow $'jobs:\n  test:\n    uses: owner/repository/.github/workflows/test.yml@'"$sha"$' # main'
check_document accept pinned-docker $'jobs:\n  test:\n    steps:\n      - uses: docker://example.invalid/action@sha256:'"$digest"$' # v1.2.3'
check_document accept local-action $'jobs:\n  test:\n    steps:\n      - uses: ./.github/actions/local'
check_document accept multiline-quoted $'jobs:\n  test:\n    steps:\n      - uses: "actions/checkout@\\\n          '"$sha"$'" # v7.0.1'
check_document accept flow-comment $'jobs: { test: { steps: [{ uses: actions/checkout@'"$sha"$' }] } } # v7.0.1'

check_document reject mutable-action $'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v7 # v7.0.1'
check_document reject missing-source $'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@'"$sha"
check_document reject mutable-flow $'jobs: { test: { steps: [{ uses: actions/checkout@v7 }] } }'
check_document reject yaml-1-2-job-ids $'jobs:\n  on:\n    steps:\n      - uses: actions/checkout@v7\n  yes:\n    steps:\n      - uses: actions/checkout@'"$sha"$' # v7.0.1'

mapfile -d '' workflow_files < <(
  find "$ROOT_DIR/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z
)
if ! python3 "$VALIDATOR" "${workflow_files[@]}" >/dev/null; then
  printf 'FAIL: repository workflows violate the action pin contract\n' >&2
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  printf 'Workflow action pin contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Workflow action pin contract passed.\n'
