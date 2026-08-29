#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

SECRET_DIR="${SECPAL_SECRET_DIR:-/run/secpal-secrets}"
POSTGRES_DATA_DIR="${SECPAL_POSTGRES_DATA_DIR:-}"
PRIVATE_STORAGE_DIR="${SECPAL_PRIVATE_STORAGE_DIR:-/app/storage/app/private}"
API_UID="${SECPAL_API_UID:-10001}"
API_GID="${SECPAL_API_GID:-10001}"
POSTGRES_UID="${SECPAL_POSTGRES_UID:-999}"
VALKEY_UID="${SECPAL_VALKEY_UID:-10002}"
TEMP_DIR=""
INITIALIZATION_ACTIVE=0
secret_names=(app-key postgres-password valkey-password tenant-kek)

fail() {
  printf 'ERROR: unable to initialize the local ephemeral secret contract.\n' >&2
  exit 1
}

require_metadata() {
  local path="$1"
  local expected_owner="$2"
  local expected_group="$3"
  local expected_mode="$4"

  if [ -L "$path" ] || [ ! -f "$path" ] ||
    [ "$(stat -c '%u' "$path")" != "$expected_owner" ] ||
    [ "$(stat -c '%g' "$path")" != "$expected_group" ] ||
    [ "$(stat -c '%a' "$path")" != "$expected_mode" ]; then
    fail
  fi
}

cleanup() {
  local name

  if [ "$INITIALIZATION_ACTIVE" -eq 1 ]; then
    for name in "${secret_names[@]}"; do
      if [ -f "$SECRET_DIR/$name" ] || [ -L "$SECRET_DIR/$name" ]; then
        rm -f -- "$SECRET_DIR/$name" || true
      fi
    done
  fi
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf -- "$TEMP_DIR" || true
  fi
}

handle_signal() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

if [ "$(id -u)" -ne 0 ]; then
  fail
fi

case "$SECRET_DIR" in
  /*) ;;
  *) fail ;;
esac

case "$PRIVATE_STORAGE_DIR" in
  /*) ;;
  *) fail ;;
esac

case "$POSTGRES_DATA_DIR" in
  /*) ;;
  *) fail ;;
esac

if [ -L "$PRIVATE_STORAGE_DIR" ] ||
  { [ -e "$PRIVATE_STORAGE_DIR" ] && [ ! -d "$PRIVATE_STORAGE_DIR" ]; }; then
  fail
fi

install -d -m 0711 "$SECRET_DIR"
install -d -m 0700 -o "$POSTGRES_UID" -g "$POSTGRES_UID" "$POSTGRES_DATA_DIR"
install -d -m 0750 -o "$API_UID" -g "$API_GID" "$PRIVATE_STORAGE_DIR"

if [ -L "$PRIVATE_STORAGE_DIR" ] || [ ! -d "$PRIVATE_STORAGE_DIR" ] ||
  [ "$(stat -c '%u' "$PRIVATE_STORAGE_DIR")" != "$API_UID" ] ||
  [ "$(stat -c '%g' "$PRIVATE_STORAGE_DIR")" != "$API_GID" ] ||
  [ "$(stat -c '%a' "$PRIVATE_STORAGE_DIR")" != 750 ]; then
  fail
fi

present=0
for name in "${secret_names[@]}"; do
  if [ -e "$SECRET_DIR/$name" ] || [ -L "$SECRET_DIR/$name" ]; then
    present=$((present + 1))
  fi
done

if [ "$present" -ne 0 ] && [ "$present" -ne "${#secret_names[@]}" ]; then
  for name in "${secret_names[@]}"; do
    if [ -f "$SECRET_DIR/$name" ] || [ -L "$SECRET_DIR/$name" ]; then
      rm -f -- "$SECRET_DIR/$name"
    elif [ -e "$SECRET_DIR/$name" ]; then
      fail
    fi
  done
  present=0
fi

if [ "$present" -eq "${#secret_names[@]}" ]; then
  require_metadata "$SECRET_DIR/app-key" "$API_UID" "$API_GID" 400
  require_metadata "$SECRET_DIR/postgres-password" "$POSTGRES_UID" "$API_GID" 440
  require_metadata "$SECRET_DIR/valkey-password" "$VALKEY_UID" "$API_GID" 440
  require_metadata "$SECRET_DIR/tenant-kek" "$API_UID" "$API_GID" 400

  if [ "$(stat -c '%s' "$SECRET_DIR/app-key")" -ne 52 ] ||
    [ "$(stat -c '%s' "$SECRET_DIR/postgres-password")" -ne 65 ] ||
    [ "$(stat -c '%s' "$SECRET_DIR/valkey-password")" -ne 65 ] ||
    [ "$(stat -c '%s' "$SECRET_DIR/tenant-kek")" -ne 32 ]; then
    fail
  fi
  exit 0
fi

INITIALIZATION_ACTIVE=1
TEMP_DIR="$(mktemp -d "$SECRET_DIR/.init.XXXXXX")"
chmod 0700 "$TEMP_DIR"

php -r 'fwrite(STDOUT, "base64:".base64_encode(random_bytes(32)).PHP_EOL);' >"$TEMP_DIR/app-key"
php -r 'fwrite(STDOUT, bin2hex(random_bytes(32)).PHP_EOL);' >"$TEMP_DIR/postgres-password"
php -r 'fwrite(STDOUT, bin2hex(random_bytes(32)).PHP_EOL);' >"$TEMP_DIR/valkey-password"
php -r 'fwrite(STDOUT, random_bytes(32));' >"$TEMP_DIR/tenant-kek"

chown "$API_UID:$API_GID" "$TEMP_DIR/app-key" "$TEMP_DIR/tenant-kek"
chmod 0400 "$TEMP_DIR/app-key" "$TEMP_DIR/tenant-kek"
chown "$POSTGRES_UID:$API_GID" "$TEMP_DIR/postgres-password"
chmod 0440 "$TEMP_DIR/postgres-password"
chown "$VALKEY_UID:$API_GID" "$TEMP_DIR/valkey-password"
chmod 0440 "$TEMP_DIR/valkey-password"

for name in "${secret_names[@]}"; do
  mv -- "$TEMP_DIR/$name" "$SECRET_DIR/$name"
done

rmdir "$TEMP_DIR"
TEMP_DIR=""
INITIALIZATION_ACTIVE=0

printf 'Local ephemeral runtime secrets initialized without revealing values.\n'
