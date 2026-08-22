#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
FRONTEND_IMAGE='ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
GENERATOR=/usr/lib/systemd/user-generators/podman-user-generator

native_unavailable() {
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
STATE_PATH="$FIXTURE_ROOT/state"
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
  if [ -d "$FIXTURE_ROOT" ]; then
    podman unshare chown -R 0:0 "$FIXTURE_ROOT" >/dev/null 2>&1 || true
    case "$(realpath "$FIXTURE_ROOT")" in
      /tmp/secpal-d2-native.*) rm -rf -- "$FIXTURE_ROOT" ;;
      *) printf 'ERROR: native lifecycle fixture root escaped its boundary.\n' >&2 ;;
    esac
  fi
}
trap cleanup EXIT HUP INT TERM

install -d -m 0750 "$STATE_PATH"
install -d -m 0700 "$QUADLET_ROOT" "$GENERATED_ROOT"
podman unshare chown 101:101 "$STATE_PATH"

cat >"$QUADLET_ROOT/$INSTANCE.container" <<EOF
[Unit]
Description=SecPal D.2 disposable native persistence proof

[Container]
ContainerName=$CONTAINER_NAME
Image=$FRONTEND_IMAGE
Pull=never
User=101
Group=101
ReadOnly=true
DropCapability=all
NoNewPrivileges=true
Network=none
Mount=type=bind,source=$STATE_PATH,target=/state,rw=true
Entrypoint=["/bin/sh"]
Exec=-c "if [ ! -f /state/proof ]; then printf persistence > /state/proof; fi; exec sleep 300"

[Service]
Restart=no
TimeoutStartSec=60
EOF

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
  printf 'Production state native lifecycle skipped: reviewed image is not locally staged.\n'
  exit 0
fi
if [ ! -S "/run/user/$(id -u)/bus" ]; then
  printf 'Production state native lifecycle skipped: systemd user bus is unavailable.\n'
  exit 0
fi

env "${SYSTEMD_ENV[@]}" systemctl --user link "$GENERATED_ROOT/$SERVICE_NAME" >/dev/null
LINKED=1
env "${SYSTEMD_ENV[@]}" systemctl --user daemon-reload
env "${SYSTEMD_ENV[@]}" systemctl --user start "$SERVICE_NAME"

before="$(podman unshare stat -c '%i:%u:%g:%a:%s' "$STATE_PATH/proof")"
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
