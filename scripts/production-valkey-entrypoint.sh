#!/bin/sh
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -eu

password_file=/run/secpal-secret/password
configuration=/tmp/secpal-valkey.conf

if [ -L "$password_file" ] || [ ! -f "$password_file" ] || [ ! -r "$password_file" ] ||
  [ "$(stat -c '%a:%h' "$password_file")" != "400:1" ]; then
  printf 'ERROR: production Valkey secret contract is invalid.\n' >&2
  exit 78
fi

password="$(cat "$password_file")"
case "$password" in
  *[!A-Za-z0-9._~!#%+/:=?^@-]* | '')
    printf 'ERROR: production Valkey secret contract is invalid.\n' >&2
    exit 78
    ;;
esac
if [ "${#password}" -lt 24 ] || [ "${#password}" -gt 128 ]; then
  printf 'ERROR: production Valkey secret contract is invalid.\n' >&2
  exit 78
fi

umask 077
{
  printf 'requirepass %s\n' "$password"
  printf 'dir /data\n'
  printf 'appendonly yes\n'
  printf 'appendfsync everysec\n'
  printf 'save ""\n'
} >"$configuration"
unset password

exec valkey-server "$configuration"
