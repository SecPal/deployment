#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d)"
FAKE_BIN="$TEMP_DIR/bin"
COMMAND_LOG="$TEMP_DIR/docker.log"
CURL_LOG="$TEMP_DIR/curl.log"
children=()
failures=0

cleanup() {
  local child
  for child in "${children[@]}"; do
    kill "$child" >/dev/null 2>&1 || true
    wait "$child" >/dev/null 2>&1 || true
  done
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

wait_for_file() {
  local path="$1"
  local _attempt
  for _attempt in $(seq 1 200); do
    if [ -e "$path" ]; then
      return 0
    fi
    /usr/bin/sleep 0.01
  done
  return 1
}

wait_for_exit() {
  local pid="$1"
  local state
  local _attempt

  for _attempt in $(seq 1 200); do
    if [ ! -r "/proc/$pid/stat" ]; then
      return 0
    fi
    state="$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null || true)"
    if [ -z "$state" ]; then
      return 0
    fi
    if [ "$state" = Z ]; then
      return 0
    fi
    /usr/bin/sleep 0.01
  done
  return 1
}

install -d -m 0700 "$FAKE_BIN"
cp "$ROOT_DIR/tests/fixtures/fake-docker.sh" "$FAKE_BIN/docker"
cp "$ROOT_DIR/tests/fixtures/fake-curl.sh" "$FAKE_BIN/curl"
chmod 0700 "$FAKE_BIN/docker" "$FAKE_BIN/curl"
: >"$COMMAND_LOG"
: >"$CURL_LOG"

for invalid_port in invalid 80 65536; do
  if env \
    PATH="$FAKE_BIN:$PATH" \
    SECPAL_PHASE_B_PORT="$invalid_port" \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID=invalid-port \
    bash "$ROOT_DIR/scripts/local-integration.sh" >/dev/null 2>&1; then
    fail "invalid loopback port was accepted: $invalid_port"
  fi
done

pause_marker="$TEMP_DIR/paused"
release_marker="$TEMP_DIR/release"
env \
  PATH="$FAKE_BIN:$PATH" \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_PAUSE_MARKER="$pause_marker" \
  SECPAL_TEST_RELEASE_MARKER="$release_marker" \
  SECPAL_TEST_RUN_ID=signal \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/signal.out" 2>&1 &
signal_pid=$!
children+=("$signal_pid")

if ! wait_for_file "$pause_marker"; then
  fail "the signal fixture did not reach its controlled pause"
else
  kill -TERM "$signal_pid"
  : >"$release_marker"
  if ! wait_for_exit "$signal_pid"; then
    kill -KILL "$signal_pid" >/dev/null 2>&1 || true
    wait "$signal_pid" >/dev/null 2>&1 || true
    fail "the integration script did not terminate after SIGTERM"
  elif wait "$signal_pid"; then
    fail "the integration script returned success after SIGTERM"
  fi
  if grep -Fq -- '--profile tools run --rm migrate' "$COMMAND_LOG"; then
    fail "the integration script executed work after handling SIGTERM"
  fi
fi
children=()

: >"$COMMAND_LOG"
: >"$CURL_LOG"
parallel_pids=()
for specification in one:18443 two:18444; do
  run_id="${specification%%:*}"
  port="${specification##*:}"
  env \
    PATH="$FAKE_BIN:$PATH" \
    SECPAL_PHASE_B_PORT="$port" \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID="$run_id" \
    bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/$run_id.out" 2>&1 &
  parallel_pids+=("$!")
done
children=("${parallel_pids[@]}")

for child in "${parallel_pids[@]}"; do
  if ! wait "$child"; then
    fail "a parallel integration fixture failed"
  fi
done
children=()

for specification in one:18443 two:18444; do
  run_id="${specification%%:*}"
  port="${specification##*:}"
  run_curl_log="$TEMP_DIR/$run_id.curl"
  grep -F "$run_id"$'\t' "$CURL_LOG" >"$run_curl_log" || true
  if ! grep -Fq "$run_id"$'\t' "$COMMAND_LOG" ||
    ! grep -Fq "secpal.example.invalid:$port:127.0.0.1" "$run_curl_log"; then
    fail "parallel run $run_id did not use its isolated loopback port"
  fi
done

one_images="$(awk -F '\t' '$1 == "one" { print $2 FS $3 FS $4; exit }' "$COMMAND_LOG")"
two_images="$(awk -F '\t' '$1 == "two" { print $2 FS $3 FS $4; exit }' "$COMMAND_LOG")"
if [ -z "$one_images" ] || [ -z "$two_images" ] || [ "$one_images" = "$two_images" ]; then
  fail "parallel runs did not use distinct project-scoped image tags"
fi

one_project="$(awk -F '\t' '$1 == "one" { count = split($5, part, " "); for (position = 1; position <= count; position++) if (part[position] == "--project-name") { print part[position + 1]; exit } }' "$COMMAND_LOG")"
two_project="$(awk -F '\t' '$1 == "two" { count = split($5, part, " "); for (position = 1; position <= count; position++) if (part[position] == "--project-name") { print part[position + 1]; exit } }' "$COMMAND_LOG")"
if [ -z "$one_project" ] || [ -z "$two_project" ] || [ "$one_project" = "$two_project" ]; then
  fail "parallel runs did not use distinct random Compose projects"
fi

if [ "$failures" -ne 0 ]; then
  printf '%s\n' '--- curl.log' >&2
  sed -n '1,120p' "$CURL_LOG" >&2
  for output in "$TEMP_DIR"/*.out; do
    if [ -f "$output" ]; then
      printf '%s\n' "--- ${output##*/}" >&2
      sed -n '1,120p' "$output" >&2
    fi
  done
  printf 'Local integration lifecycle contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Local integration lifecycle contract passed.\n'
