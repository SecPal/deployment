#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

SECRET_DIR="${SECPAL_SECRET_DIR:-/run/secpal-secrets}"

fail() {
  printf 'ERROR: local runtime secret contract is not satisfied.\n' >&2
  exit 1
}

case "$SECRET_DIR" in
  /*) ;;
  *) fail ;;
esac

require_secret_file() {
  local path="$1"
  local mode

  if [ -L "$path" ] || [ ! -f "$path" ] || [ ! -r "$path" ]; then
    fail
  fi

  mode="$(stat -c '%a' "$path")"
  case "$mode" in
    400 | 440) ;;
    *) fail ;;
  esac
}

read_text_secret() {
  local path="$1"
  local value

  require_secret_file "$path"
  value="$(<"$path")"
  if [ -z "$value" ] || [ "$(wc -l <"$path")" -ne 1 ]; then
    fail
  fi
  printf '%s' "$value"
}

app_key="$(read_text_secret "$SECRET_DIR/app-key")"
database_password="$(read_text_secret "$SECRET_DIR/postgres-password")"
valkey_password="$(read_text_secret "$SECRET_DIR/valkey-password")"
require_secret_file "$SECRET_DIR/tenant-kek"

if ! [[ "$app_key" =~ ^base64:[A-Za-z0-9+/]{43}=$ ]] ||
  ! [[ "$database_password" =~ ^[a-f0-9]{64}$ ]] ||
  ! [[ "$valkey_password" =~ ^[a-f0-9]{64}$ ]] ||
  [ "$(stat -c '%s' "$SECRET_DIR/tenant-kek")" -ne 32 ]; then
  fail
fi

export APP_KEY="$app_key"
export DB_PASSWORD="$database_password"
export KEK_PATH="$SECRET_DIR/tenant-kek"
export REDIS_PASSWORD="$valkey_password"

unset app_key database_password valkey_password

if [ "$#" -eq 0 ]; then
  printf 'ERROR: no container role command was provided.\n' >&2
  exit 1
fi

install -d -m 0750 \
  /app/bootstrap/cache \
  /app/storage/app/private \
  /app/storage/app/public \
  /app/storage/framework/cache/data \
  /app/storage/framework/sessions \
  /app/storage/framework/views \
  /app/storage/logs \
  /config/caddy \
  /config/psysh \
  /data/caddy

exec "$@"
