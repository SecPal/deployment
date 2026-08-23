#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
VALIDATOR="$ROOT_DIR/scripts/validate-compose-prohibition.sh"
TEMP_DIR="$(mktemp -d -t secpal-compose-prohibition.XXXXXXXXXX)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

if [ ! -x "$VALIDATOR" ]; then
  fail "Compose-prohibition validator is missing or not executable"
fi

new_fixture() {
  local name="$1"
  local fixture="$TEMP_DIR/$name"

  install -d -m 0700 \
    "$fixture/scripts" "$fixture/.github/workflows"
  install -m 0700 "$VALIDATOR" \
    "$fixture/scripts/validate-compose-prohibition.sh"
  printf '%s\n' "$fixture"
}

expect_rejected() {
  local name="$1"
  local fixture="$2"

  if "$VALIDATOR" "$fixture" >/dev/null 2>&1; then
    fail "$name Compose invocation was accepted"
  fi
}

fixture="$(new_fixture shell-runner)"
printf '%s\n' '#!/usr/bin/env bash' 'docker compose up --detach' \
  >"$fixture/scripts/run.sh"
chmod 0700 "$fixture/scripts/run.sh"
expect_rejected "shell runner" "$fixture"

fixture="$(new_fixture python-runner)"
printf '%s\n' '#!/usr/bin/env python3' 'import subprocess' \
  'subprocess.run(["docker", "compose", "up"], check=True)' \
  >"$fixture/scripts/run.py"
chmod 0700 "$fixture/scripts/run.py"
expect_rejected "Python runner" "$fixture"

fixture="$(new_fixture workflow)"
printf '%s\n' 'name: forbidden' 'jobs:' '  integration:' \
  '    steps:' '      - run: docker-compose up --detach' \
  >"$fixture/.github/workflows/forbidden.yml"
expect_rejected "workflow" "$fixture"

fixture="$(new_fixture validator-denylist)"
if ! "$VALIDATOR" "$fixture" >/dev/null; then
  fail "the validator rejected its own intentional denylist text"
fi

printf 'Compose prohibition contract passed (3 negative mutations, 1 self-exclusion).\n'
