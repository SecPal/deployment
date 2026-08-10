#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

install -d -o root -g root -m 0755 /etc/containers/systemd/users/20000
install -d -o secpal-ci -g secpal-ci -m 0700 /srv/secpal-ci

if ! grep -Fqx 'secpal-ci:200000:65536' /etc/subuid; then
  if grep -q '^secpal-ci:' /etc/subuid; then
    printf 'ERROR: secpal-ci has an unexpected subordinate UID range.\n' >&2
    exit 1
  fi
  usermod --add-subuids 200000-265535 secpal-ci
fi
if ! grep -Fqx 'secpal-ci:200000:65536' /etc/subgid; then
  if grep -q '^secpal-ci:' /etc/subgid; then
    printf 'ERROR: secpal-ci has an unexpected subordinate GID range.\n' >&2
    exit 1
  fi
  usermod --add-subgids 200000-265535 secpal-ci
fi

systemctl --global disable \
  podman.socket podman.service podman-auto-update.timer || true
systemctl disable --now podman.socket podman.service || true
loginctl enable-linger secpal-ci
systemctl enable --now apparmor.service

apparmor_status_path=/run/secpal-ci-evidence/apparmor-status
evidence_dir="${apparmor_status_path%/*}"
install -d -o root -g root -m 0755 "$evidence_dir"
snapshot_tmp="$(mktemp "$evidence_dir/.apparmor-status.XXXXXX")"
trap 'rm -f -- "$snapshot_tmp"' EXIT
loaded_profiles="$(aa-status --profiled)"
enforcing_profiles="$(aa-status --enforced)"
if [[ ! "$loaded_profiles" =~ ^[0-9]+$ ||
  ! "$enforcing_profiles" =~ ^[0-9]+$ ||
  "$enforcing_profiles" -gt "$loaded_profiles" ]]; then
  printf 'ERROR: unable to capture bounded AppArmor policy counts.\n' >&2
  exit 1
fi
printf 'loaded_profiles=%s\nenforcing_profiles=%s\n' \
  "$loaded_profiles" "$enforcing_profiles" >"$snapshot_tmp"
install -o root -g root -m 0644 \
  "$snapshot_tmp" "$apparmor_status_path"
rm -f -- "$snapshot_tmp"
trap - EXIT

sshd -t
systemctl restart ssh.service
