#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" != 2 || ! "$1" =~ ^[1-9][0-9]{0,19}$ || ! "$2" =~ ^[1-9][0-9]{0,2}$ ]]; then
  exit 64
fi
exec /usr/bin/python3 -I \
  /opt/secpal-control/scripts/ci-cloud/qualify-product-backends.py "$1" "$2"
