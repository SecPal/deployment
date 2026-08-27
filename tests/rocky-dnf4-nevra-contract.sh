#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

# shellcheck source=/dev/null
. /etc/os-release
test "$ID" = rocky
test "$VERSION_ID" = 10.2
test "$(uname -m)" = x86_64
test "$(dnf4 --version | head -n 1)" = 4.20.0

nevra="$(
  dnf4 --quiet \
    '--disablerepo=*' \
    '--enablerepo=baseos,appstream,extras' \
    repoquery \
    --available \
    --arch "$(uname -m)" \
    --latest-limit 1 \
    --nevra \
    bash
)"
[[ "$nevra" =~ ^bash-[^-]+-[^-]+\.el10[^.]*\.x86_64$ ]]

old_status=0
old_error="$(mktemp)"
trap 'rm -f -- "$old_error"' EXIT
dnf4 --quiet \
  '--disablerepo=*' \
  '--enablerepo=baseos,appstream,extras' \
  repoquery \
  --qf '%{repoid}' \
  --nevra \
  "$nevra" \
  >/dev/null 2>"$old_error" || old_status=$?
test "$old_status" -ne 0
grep -Fq 'not allowed with argument --qf/--queryformat' "$old_error"

repositories="$(
  dnf4 --quiet \
    '--disablerepo=*' \
    '--enablerepo=baseos,appstream,extras' \
    repoquery-nevra \
    --qf '%{repoid}' \
    "$nevra"
)"
test -n "$repositories"
while IFS= read -r repository; do
  case "$repository" in
    baseos | appstream | extras) ;;
    *) exit 1 ;;
  esac
done <<<"$repositories"

wrong="$(
  dnf4 --quiet \
    '--disablerepo=*' \
    '--enablerepo=baseos,appstream,extras' \
    repoquery-nevra \
    --qf '%{repoid}' \
    "definitely-not-$nevra"
)"
test -z "$wrong"

printf 'Rocky %s DNF4 exact NEVRA: %s -> %s\n' \
  "$VERSION_ID" "$nevra" "$repositories"
