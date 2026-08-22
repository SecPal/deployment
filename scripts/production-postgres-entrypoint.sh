#!/bin/sh
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -eu

data=/var/lib/postgresql/data
password_file=/run/secpal-secret/password
socket_directory=/tmp/secpal-postgres-init

fail() {
  printf 'ERROR: production PostgreSQL state or secret contract is invalid.\n' >&2
  exit 78
}

validate_cluster() {
  [ -f "$data/PG_VERSION" ] || fail
  [ "$(cat "$data/PG_VERSION")" = 16 ] || fail
  pg_controldata "$data" >/dev/null 2>&1 || fail
}

started=0
cleanup() {
  if [ "$started" -eq 1 ]; then
    pg_ctl -D "$data" -m fast -w stop >/dev/null 2>&1 || true
  fi
}

interrupted() {
  trap - EXIT HUP INT TERM
  cleanup
  exit 143
}

start_temporary_server() {
  install -d -m 0700 "$socket_directory"
  pg_ctl -D "$data" -o "-c listen_addresses='' -c unix_socket_directories='$socket_directory'" \
    -w start >/dev/null
  started=1
}

stop_temporary_server() {
  pg_ctl -D "$data" -m fast -w stop >/dev/null
  started=0
}

validate_database() {
  psql --host="$socket_directory" --username=secpal --dbname=secpal \
    --no-psqlrc --tuples-only --command='SELECT 1' >/dev/null 2>&1 || fail
}

case "${1:-}" in
  initialize)
    if [ -f "$data/PG_VERSION" ]; then
      validate_cluster
      trap cleanup EXIT
      trap interrupted HUP INT TERM
      start_temporary_server
      validate_database
      stop_temporary_server
      trap - EXIT HUP INT TERM
      exit 0
    fi
    if find "$data" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
      fail
    fi
    if [ -L "$password_file" ] || [ ! -f "$password_file" ] || [ ! -r "$password_file" ] ||
      [ "$(stat -c '%a:%h' "$password_file")" != "400:1" ]; then
      fail
    fi
    trap cleanup EXIT
    trap interrupted HUP INT TERM
    initdb -D "$data" --username=secpal --pwfile="$password_file" \
      --auth-local=trust --auth-host=scram-sha-256 >/dev/null
    start_temporary_server
    createdb --host="$socket_directory" --username=secpal secpal
    validate_database
    stop_temporary_server
    trap - EXIT HUP INT TERM
    validate_cluster
    ;;
  run)
    validate_cluster
    exec postgres -D "$data"
    ;;
  *)
    fail
    ;;
esac
