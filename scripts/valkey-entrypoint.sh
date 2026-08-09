#!/bin/sh
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -eu

password_file=/run/secpal-secrets/valkey-password
configuration=/tmp/valkey.conf

if [ -L "$password_file" ] || [ ! -f "$password_file" ] || [ ! -r "$password_file" ]; then
  printf 'ERROR: local Valkey secret contract is not satisfied.\n' >&2
  exit 1
fi

umask 077
printf 'requirepass %s\n' "$(cat "$password_file")" >"$configuration"
exec valkey-server "$configuration" --save "" --appendonly no
