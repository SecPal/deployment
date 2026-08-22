#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
FRONTEND_IMAGE='ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
GENERATOR=/usr/lib/systemd/user-generators/podman-user-generator

native_unavailable() {
  if [ "${SECPAL_REQUIRE_NATIVE_LIFECYCLE:-0}" = 1 ]; then
    native_failure
  fi
  printf 'SKIP: Production state native lifecycle unavailable: native Quadlet user generator is not installed.\n'
  exit 0
}

native_failure() {
  printf 'ERROR: Production state native lifecycle requires an admitted native Quadlet user generator.\n' >&2
  exit 1
}

trusted_directory() {
  local directory="$1"
  local metadata
  local uid
  local gid
  local mode

  while :; do
    if [ -L "$directory" ] || [ ! -d "$directory" ]; then
      return 1
    fi
    metadata="$(stat -Lc '%u:%g:%a' -- "$directory")" || return 1
    IFS=: read -r uid gid mode <<<"$metadata"
    if [ "$uid" != 0 ] || [ "$gid" != 0 ] || (( (8#$mode & 8#022) != 0 )); then
      return 1
    fi
    if [ "$directory" = / ]; then
      return 0
    fi
    directory="$(dirname -- "$directory")"
  done
}

admit_native_generator() {
  local resolved
  local metadata
  local uid
  local gid
  local mode
  local generator_version
  local podman_version

  if [ ! -e "$GENERATOR" ] && [ ! -L "$GENERATOR" ]; then
    native_unavailable
  fi
  if ! trusted_directory "$(dirname -- "$GENERATOR")"; then
    native_failure
  fi
  resolved="$(realpath -e -- "$GENERATOR")" || native_failure
  if ! trusted_directory "$(dirname -- "$resolved")" || [ -L "$resolved" ] || [ ! -f "$resolved" ]; then
    native_failure
  fi
  metadata="$(stat -Lc '%u:%g:%a' -- "$resolved")" || native_failure
  IFS=: read -r uid gid mode <<<"$metadata"
  if [ "$uid" != 0 ] || [ "$gid" != 0 ] || (( (8#$mode & 8#022) != 0 )) \
    || (( (8#$mode & 8#001) == 0 )); then
    native_failure
  fi
  generator_version="$("$resolved" --version 2>/dev/null | sed -n '1p')" || native_failure
  podman_version="$(podman --version 2>/dev/null | awk '{print $3}')" || native_failure
  if [ -z "$generator_version" ] || [ -z "$podman_version" ] \
    || ! python3 -c '
import importlib.util
import sys

specification = importlib.util.spec_from_file_location("runtime_contract", sys.argv[1])
module = importlib.util.module_from_spec(specification)
assert specification.loader is not None
sys.modules[specification.name] = module
specification.loader.exec_module(module)
generator_version, podman_version = sys.argv[2:]
sys.exit(
    0
    if module.podman_version_supported(podman_version)
    and module.podman_versions_compatible(generator_version, podman_version)
    else 1
)
' "$ROOT_DIR/scripts/integration_runtime_contract.py" "$generator_version" "$podman_version" \
      >/dev/null 2>&1; then
    native_failure
  fi
  GENERATOR="$resolved"
}

admit_native_generator

FIXTURE_ROOT="$(mktemp -d /tmp/secpal-d2-native.XXXXXX)"
STATE_PATH="$FIXTURE_ROOT/srv/secpal/private-storage"
QUADLET_ROOT="$FIXTURE_ROOT/quadlet"
GENERATED_ROOT="$FIXTURE_ROOT/generated"
INSTANCE="d2-native-$$"
CONTAINER_NAME="secpal-$INSTANCE"
SERVICE_NAME="$INSTANCE.service"
SYSTEMD_ENV=(
  "XDG_RUNTIME_DIR=/run/user/$(id -u)"
  "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus"
)
LINKED=0

cleanup() {
  if [ "$LINKED" -eq 1 ]; then
    env "${SYSTEMD_ENV[@]}" systemctl --user stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    env "${SYSTEMD_ENV[@]}" systemctl --user disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    env "${SYSTEMD_ENV[@]}" systemctl --user daemon-reload >/dev/null 2>&1 || true
  fi
  podman rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || true
  if [ -L "$FIXTURE_ROOT" ]; then
    printf 'ERROR: native lifecycle fixture root became a symbolic link.\n' >&2
    return 1
  elif [ -d "$FIXTURE_ROOT" ]; then
    case "$(realpath "$FIXTURE_ROOT")" in
      /tmp/secpal-d2-native.*)
        podman unshare chown -R 0:0 "$FIXTURE_ROOT" >/dev/null 2>&1 || true
        rm -rf -- "$FIXTURE_ROOT"
        ;;
      *) printf 'ERROR: native lifecycle fixture root escaped its boundary.\n' >&2 ;;
    esac
  fi
}
interrupted() {
  trap - EXIT HUP INT TERM
  cleanup
  exit 143
}
trap cleanup EXIT
trap interrupted HUP INT TERM

install -d -m 0750 "$FIXTURE_ROOT/srv/secpal" "$STATE_PATH"
install -d -m 0700 "$QUADLET_ROOT" "$GENERATED_ROOT"
podman unshare chown 10001:10001 "$STATE_PATH"

python3 - "$ROOT_DIR" "$FIXTURE_ROOT" "$INSTANCE" "$QUADLET_ROOT/$INSTANCE.container" <<'PY'
import importlib.util
from pathlib import Path
import sys

root, fixture, instance, output = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location(
    "render_production_quadlets", root / "scripts/render-production-quadlets.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)
contract = module.load_contract(module.DEFAULT_CONTRACT)
output.write_text(
    module.build_native_lifecycle_fixture_unit(contract, fixture, instance.name),
    encoding="utf-8",
)
PY

QUADLET_UNIT_DIRS="$QUADLET_ROOT" "$GENERATOR" \
  "$GENERATED_ROOT" "$GENERATED_ROOT" "$GENERATED_ROOT"
test -f "$GENERATED_ROOT/$SERVICE_NAME"

# The full production set must also remain admissible to the native generator.
PRODUCTION_GENERATED="$FIXTURE_ROOT/production-generated"
install -d -m 0700 "$PRODUCTION_GENERATED"
QUADLET_UNIT_DIRS="$ROOT_DIR/config/production/quadlet" "$GENERATOR" \
  "$PRODUCTION_GENERATED" "$PRODUCTION_GENERATED" "$PRODUCTION_GENERATED"
test "$(find "$PRODUCTION_GENERATED" -maxdepth 1 -type f | wc -l)" -eq 11

if ! podman image exists "$FRONTEND_IMAGE"; then
  if [ "${SECPAL_REQUIRE_NATIVE_LIFECYCLE:-0}" = 1 ]; then
    printf 'ERROR: required production state native lifecycle image is not staged.\n' >&2
    exit 1
  fi
  printf 'SKIP: Production state native lifecycle unavailable: reviewed image is not locally staged.\n'
  exit 0
fi
if [ ! -S "/run/user/$(id -u)/bus" ]; then
  if [ "${SECPAL_REQUIRE_NATIVE_LIFECYCLE:-0}" = 1 ]; then
    printf 'ERROR: required production state native lifecycle systemd user bus is unavailable.\n' >&2
    exit 1
  fi
  printf 'SKIP: Production state native lifecycle unavailable: systemd user bus is unavailable.\n'
  exit 0
fi

env "${SYSTEMD_ENV[@]}" systemctl --user link "$GENERATED_ROOT/$SERVICE_NAME" >/dev/null
LINKED=1
env "${SYSTEMD_ENV[@]}" systemctl --user daemon-reload
env "${SYSTEMD_ENV[@]}" systemctl --user start "$SERVICE_NAME"

before="$(podman unshare stat -c '%i:%u:%g:%a:%s' "$STATE_PATH/proof")"
test "$(podman unshare stat -c '%u:%g' "$STATE_PATH/proof")" = 10001:10001
test "$(podman unshare cat "$STATE_PATH/proof")" = persistence
env "${SYSTEMD_ENV[@]}" systemctl --user stop "$SERVICE_NAME"
env "${SYSTEMD_ENV[@]}" systemctl --user start "$SERVICE_NAME"
test "$(podman unshare cat "$STATE_PATH/proof")" = persistence

env "${SYSTEMD_ENV[@]}" systemctl --user stop "$SERVICE_NAME"
podman rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || true
env "${SYSTEMD_ENV[@]}" systemctl --user start "$SERVICE_NAME"
after="$(podman unshare stat -c '%i:%u:%g:%a:%s' "$STATE_PATH/proof")"
test "$before" = "$after"
test "$(podman unshare cat "$STATE_PATH/proof")" = persistence

printf 'Production state native systemd-user/Quadlet lifecycle passed.\n'
