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

printf 'Production state native lifecycle capability gate passed.\n'
