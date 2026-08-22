#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
FRONTEND_IMAGE='ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
GENERATOR=/usr/lib/systemd/user-generators/podman-user-generator
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
