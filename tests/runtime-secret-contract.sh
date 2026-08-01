#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d)"
FAKE_BIN="$TEMP_DIR/bin"
CURRENT_UID="$(id -u)"
CURRENT_GID="$(id -g)"
failures=0
test_number=0

cleanup() {
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

expect_failure() {
  local description="$1"
  local output
  shift
  test_number=$((test_number + 1))
  output="$TEMP_DIR/failure-$test_number.log"
  if "$@" >"$output" 2>&1; then
    fail "$description unexpectedly succeeded"
  fi
}

make_secret_set() {
  local directory="$1"

  install -d -m 0700 "$directory"
  printf 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' >"$directory/app-key"
  printf '%064d\n' 0 >"$directory/postgres-password"
  printf '%064d\n' 0 >"$directory/valkey-password"
  printf '12345678901234567890123456789012' >"$directory/tenant-kek"
  chmod 0400 "$directory/app-key" "$directory/tenant-kek"
  chmod 0440 "$directory/postgres-password" "$directory/valkey-password"
}

run_initializer() {
  local secret_directory="$1"
  local api_uid="${2:-$CURRENT_UID}"

  env \
    PATH="$FAKE_BIN:$PATH" \
    SECPAL_API_GID="$CURRENT_GID" \
    SECPAL_API_UID="$api_uid" \
    SECPAL_POSTGRES_DATA_DIR="$TEMP_DIR/postgres-data" \
    SECPAL_POSTGRES_UID="$CURRENT_UID" \
    SECPAL_SECRET_DIR="$secret_directory" \
    SECPAL_VALKEY_UID="$CURRENT_UID" \
    bash "$ROOT_DIR/scripts/init-local-secrets.sh"
}

install -d -m 0700 "$FAKE_BIN"
printf '%s\n' '#!/bin/sh' \
  "if [ \"\${1:-}\" = \"-u\" ]; then printf '0\\n'; else exec /usr/bin/id \"\$@\"; fi" \
  >"$FAKE_BIN/id"
chmod 0700 "$FAKE_BIN/id"

expect_failure "a missing secret set" \
  env SECPAL_SECRET_DIR="$TEMP_DIR/missing" \
  bash "$ROOT_DIR/scripts/container-entrypoint.sh" true

partial="$TEMP_DIR/partial"
install -d -m 0700 "$partial"
printf 'partial\n' >"$partial/app-key"
expect_failure "a partial secret set" run_initializer "$partial"

symlinked="$TEMP_DIR/symlinked"
make_secret_set "$symlinked"
rm "$symlinked/app-key"
ln -s tenant-kek "$symlinked/app-key"
expect_failure "a symlinked secret" run_initializer "$symlinked"

wrong_mode="$TEMP_DIR/wrong-mode"
make_secret_set "$wrong_mode"
chmod 0644 "$wrong_mode/app-key"
expect_failure "an overly broad secret mode" run_initializer "$wrong_mode"

wrong_owner="$TEMP_DIR/wrong-owner"
make_secret_set "$wrong_owner"
expect_failure "an unexpected secret owner" run_initializer "$wrong_owner" "$((CURRENT_UID + 1))"

malformed="$TEMP_DIR/malformed"
make_secret_set "$malformed"
chmod 0600 "$malformed/app-key"
printf 'base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB!\n' >"$malformed/app-key"
chmod 0400 "$malformed/app-key"
expect_failure "a malformed secret value" \
  env SECPAL_SECRET_DIR="$malformed" \
  bash "$ROOT_DIR/scripts/container-entrypoint.sh" true

valid="$TEMP_DIR/valid"
make_secret_set "$valid"
missing_command_output="$TEMP_DIR/missing-command.log"
if env SECPAL_SECRET_DIR="$valid" \
  bash "$ROOT_DIR/scripts/container-entrypoint.sh" >"$missing_command_output" 2>&1; then
  fail "a missing role command unexpectedly succeeded"
elif ! grep -Fq 'ERROR: no container role command was provided.' "$missing_command_output"; then
  fail "a missing role command did not fail with the documented error"
fi

if [ "$failures" -ne 0 ]; then
  printf 'Runtime secret contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Runtime secret contract passed.\n'
