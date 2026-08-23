#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT_DIR/scripts/reject-sensitive-paths.sh"
failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

if [ ! -x "$CHECKER" ]; then
  fail "the sensitive-path checker is missing or not executable"
else
  forbidden_paths=(
    .env
    .env.example
    config/.env.production
    nested/server.pem
    nested/client.key
    nested/backup.p12
    nested/archive.pfx
    nested/server.crt
    terraform.tfstate
    infra/terraform.tfstate.backup
    secrets/example
    nested/secrets/example
    private/example
    nested/credentials/example
  )

  for path in "${forbidden_paths[@]}"; do
    if printf '%s\0' "$path" | "$CHECKER" >/dev/null 2>&1; then
      fail "forbidden path was accepted: $path"
    fi
  done

  if ! printf '%s\0' \
    README.md \
    docs/architecture/state-machine.md \
    config/quadlet/Caddyfile \
    tests/fixtures/example.invalid | "$CHECKER"; then
    fail "public non-sensitive paths were rejected"
  fi
fi

if [ "$failures" -ne 0 ]; then
  printf 'Sensitive path contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Sensitive path contract passed.\n'
