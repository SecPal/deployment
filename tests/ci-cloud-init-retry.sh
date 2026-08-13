#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RETRY_SCRIPT="$ROOT_DIR/scripts/ci-cloud/init-cleanup-root.sh"
TEMP_DIR="$(mktemp -d)"
FAKE_BIN="$TEMP_DIR/bin"
CALLS="$TEMP_DIR/calls"
SLEEPS="$TEMP_DIR/sleeps"

cleanup() {
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

install -d -m 0700 "$FAKE_BIN"

cat >"$FAKE_BIN/tofu" <<'FAKE_TOFU'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$SECPAL_TEST_CALLS" ]]; then
  count="$(wc -l <"$SECPAL_TEST_CALLS")"
fi
printf '%s\n' "$*" >>"$SECPAL_TEST_CALLS"
count=$((count + 1))
if [[ "$SECPAL_TEST_SUCCESS_ON" -ne 0 &&
  "$count" -ge "$SECPAL_TEST_SUCCESS_ON" ]]; then
  exit 0
fi
exit 42
FAKE_TOFU
chmod 0700 "$FAKE_BIN/tofu"

cat >"$FAKE_BIN/sleep" <<'FAKE_SLEEP'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 1 && "$1" =~ ^[0-9]+$ ]]
printf '%s\n' "$1" >>"$SECPAL_TEST_SLEEPS"
FAKE_SLEEP
chmod 0700 "$FAKE_BIN/sleep"

run_retry() {
  PATH="$FAKE_BIN:/usr/bin:/bin" \
    SECPAL_TEST_CALLS="$CALLS" \
    SECPAL_TEST_SLEEPS="$SLEEPS" \
    SECPAL_TEST_SUCCESS_ON="$1" \
    "$RETRY_SCRIPT"
}

: >"$CALLS"
: >"$SLEEPS"
run_retry 3
[[ "$(wc -l <"$CALLS")" -eq 3 ]]
[[ "$(sort -u "$CALLS")" == "init -input=false -lockfile=readonly" ]]
[[ "$(printf '10\n20\n')" == "$(<"$SLEEPS")" ]]

: >"$CALLS"
: >"$SLEEPS"
set +e
run_retry 0
status=$?
set -e
[[ "$status" -eq 42 ]]
[[ "$(wc -l <"$CALLS")" -eq 3 ]]
[[ "$(printf '10\n20\n')" == "$(<"$SLEEPS")" ]]

: >"$CALLS"
: >"$SLEEPS"
run_retry 1
[[ "$(wc -l <"$CALLS")" -eq 1 ]]
[[ ! -s "$SLEEPS" ]]

printf 'Cloud cleanup init retry contract passed.\n'
