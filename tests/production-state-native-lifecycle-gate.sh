#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
SOURCE="$ROOT_DIR/tests/production-state-native-lifecycle.sh"
FIXTURE_ROOT="$(mktemp -d /tmp/secpal-d2-native-gate.XXXXXX)"

cleanup() {
  case "$(realpath "$FIXTURE_ROOT")" in
    /tmp/secpal-d2-native-gate.*) rm -rf -- "$FIXTURE_ROOT" ;;
    *) printf 'ERROR: native lifecycle gate fixture root escaped its boundary.\n' >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

render_with_generator() {
  local generator="$1"
  local output="$2"

  sed "s|^GENERATOR=.*$|GENERATOR=$generator|" "$SOURCE" >"$output"
  chmod 0700 "$output"
}

missing_generator="$FIXTURE_ROOT/missing-generator"
missing_test="$FIXTURE_ROOT/missing.sh"
missing_output="$FIXTURE_ROOT/missing.out"
render_with_generator "$missing_generator" "$missing_test"
if ! "$missing_test" >"$missing_output" 2>&1; then
  printf 'ERROR: absent native generator must be reported as unavailable.\n' >&2
  exit 1
fi
grep -Fxq \
  'SKIP: Production state native lifecycle unavailable: native Quadlet user generator is not installed.' \
  "$missing_output"
if grep -Fq 'passed.' "$missing_output"; then
  printf 'ERROR: unavailable native capability must not be reported as lifecycle evidence.\n' >&2
  exit 1
fi

required_missing_output="$FIXTURE_ROOT/required-missing.out"
if SECPAL_REQUIRE_NATIVE_LIFECYCLE=1 "$missing_test" \
  >"$required_missing_output" 2>&1; then
  printf 'ERROR: required native lifecycle must not skip an absent generator.\n' >&2
  exit 1
fi
grep -Fxq \
  'ERROR: Production state native lifecycle requires an admitted native Quadlet user generator.' \
  "$required_missing_output"

invalid_generator="$FIXTURE_ROOT/invalid-generator"
invalid_test="$FIXTURE_ROOT/invalid.sh"
invalid_output="$FIXTURE_ROOT/invalid.out"
install -m 0755 /dev/null "$invalid_generator"
render_with_generator "$invalid_generator" "$invalid_test"
if "$invalid_test" >"$invalid_output" 2>&1; then
  printf 'ERROR: untrusted native generator must fail admission.\n' >&2
  exit 1
fi
grep -Fxq \
  'ERROR: Production state native lifecycle requires an admitted native Quadlet user generator.' \
  "$invalid_output"

cleanup_target="$FIXTURE_ROOT/cleanup-target"
cleanup_link="$FIXTURE_ROOT/cleanup-link"
cleanup_test="$FIXTURE_ROOT/cleanup.sh"
cleanup_output="$FIXTURE_ROOT/cleanup.out"
install -d -m 0700 "$cleanup_target"
printf 'preserve\n' >"$cleanup_target/proof"
ln -s "$cleanup_target" "$cleanup_link"
sed \
  -e 's|^admit_native_generator$|:|' \
  -e "s|^FIXTURE_ROOT=.*$|FIXTURE_ROOT=$cleanup_link|" \
  -e '/^trap cleanup EXIT$/a exit 0' \
  "$SOURCE" >"$cleanup_test"
chmod 0700 "$cleanup_test"
if "$cleanup_test" >"$cleanup_output" 2>&1; then
  printf 'ERROR: symlinked native lifecycle fixture cleanup must fail.\n' >&2
  exit 1
fi
grep -Fxq 'ERROR: native lifecycle fixture root became a symbolic link.' "$cleanup_output"
grep -Fxq 'preserve' "$cleanup_target/proof"

signal_root="$(mktemp -d /tmp/secpal-d2-native.signal.XXXXXX)"
signal_test="$FIXTURE_ROOT/signal.sh"
signal_output="$FIXTURE_ROOT/signal.out"
sed \
  -e 's|^admit_native_generator$|:|' \
  -e "s|^FIXTURE_ROOT=.*$|FIXTURE_ROOT=$signal_root|" \
  -e '/^trap interrupted HUP INT TERM$/a kill -TERM $$' \
  "$SOURCE" >"$signal_test"
chmod 0700 "$signal_test"
signal_status=0
"$signal_test" >"$signal_output" 2>&1 || signal_status=$?
if [ "$signal_status" -ne 143 ] || [ -e "$signal_root" ]; then
  printf 'ERROR: handled lifecycle signal must clean its fixture and exit 143.\n' >&2
  exit 1
fi

printf 'Production state native lifecycle capability gate passed.\n'
