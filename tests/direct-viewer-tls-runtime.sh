#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
SECPAL_FIXTURE_OUTER_NETNS="$(stat -Lc '%i' /proc/self/ns/net)"
export SECPAL_FIXTURE_OUTER_NETNS
unshare --user --map-auto --map-root-user --net bash -c 'set -euo pipefail; ip link set lo up; exec python3 tests/direct-viewer-tls-runtime.py'
