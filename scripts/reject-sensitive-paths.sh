#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

failures=0
while IFS= read -r -d '' path; do
  path="${path#./}"
  case "$path" in
    .env | */.env | .env.* | */.env.* | \
      *.key | *.pem | *.crt | *.p12 | *.pfx | *.jks | *.keystore | \
      *.age | *.gpg | *.asc | *.tfstate | *.tfstate.* | \
      secrets/* | */secrets/* | private/* | */private/* | \
      credentials/* | */credentials/*)
      printf 'ERROR: forbidden sensitive path present: %s\n' "$path" >&2
      failures=$((failures + 1))
      ;;
  esac
done

if [ "$failures" -ne 0 ]; then
  exit 1
fi
