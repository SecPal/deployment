#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly fixture='docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1'
readonly evidence_root=/var/lib/secpal-rocky/evidence

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'usage: run-rocky-target-qualification.sh FULL_TARGET_SHA\n' >&2
  exit 64
fi
readonly target_sha="$1"
[[ -f /var/lib/secpal-rocky/prepared ]]
[[ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]
[[ -z "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]
if curl --noproxy '*' --fail --silent --max-time 2 \
  -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
  >/dev/null 2>&1; then
  printf 'ERROR: target execution can reach a metadata credential.\n' >&2
  exit 1
fi

work_root="$(mktemp -d /var/tmp/secpal-rocky-target-XXXXXX)"
chmod 0700 "$work_root"
cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT HUP INT TERM

git -C "$work_root" init --quiet
git -C "$work_root" remote add origin https://github.com/SecPal/deployment.git
git -C "$work_root" fetch --quiet --depth=1 origin "$target_sha"
git -C "$work_root" checkout --quiet --detach FETCH_HEAD
[[ "$(git -C "$work_root" rev-parse HEAD)" == "$target_sha" ]]
[[ -x "$work_root/scripts/qualify-production-host.sh" ]]

stdout="$evidence_root/qualification.stdout"
set +e
timeout --signal=TERM --kill-after=30s 45m \
  "$work_root/scripts/qualify-production-host.sh" \
  --image "$fixture" --service-account secpal-runtime >"$stdout" 2>&1
status=$?
set -e
[[ "$(stat -c %s "$stdout")" -le 65536 ]]

python3 - "$target_sha" "$status" "$stdout" "$evidence_root/qualification.json" <<'PY'
import hashlib
import json
import pwd
import re
import sys
from pathlib import Path

target_sha, raw_status, stdout_path, output_path = sys.argv[1:]
payload = Path(stdout_path).read_bytes()
text = payload.decode("utf-8")
facts = dict(re.findall(r"^(process_a|process_b|storage_a|seccomp_mode)=(.+)$", text, re.MULTILINE))
runtime_account = pwd.getpwnam("secpal-runtime")
cleanup_checks = [
    [
        "runuser", "--user", "secpal-runtime", "--", "env",
        f"HOME={runtime_account.pw_dir}",
        f"XDG_RUNTIME_DIR=/run/user/{runtime_account.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime_account.pw_uid}/bus",
        "podman", "ps", "-a", "--format", "{{.Names}}",
    ],
    ["find", "/etc/containers/systemd/users", "-name", "secpal-host-qualification-*.container", "-print"],
    ["find", "/var/tmp", "-maxdepth", "1", "-name", "secpal-host-qualification-*", "-print"],
]
import subprocess
cleanup_results = [
    subprocess.run(command, check=False, capture_output=True, text=True)
    for command in cleanup_checks
]
cleanup_complete = all(
    result.returncode == 0 and not result.stdout.strip()
    for result in cleanup_results
)
passed = int(raw_status) == 0 and "PASS: Rocky Linux 10.2 native" in text and cleanup_complete
document = {
    "schema_version": 1,
    "target_sha": target_sha,
    "exit_status": int(raw_status),
    "stdout_sha256": hashlib.sha256(payload).hexdigest(),
    "stdout_bytes": len(payload),
    "process_contexts": [facts.get("process_a", ""), facts.get("process_b", "")],
    "storage_context": facts.get("storage_a", ""),
    "mcs_distinct": passed,
    "positive_access": passed,
    "cross_mcs_denied": passed,
    "avc_observed": passed,
    "seccomp_enforced": passed and facts.get("seccomp_mode") == "2",
    "cleanup_complete": cleanup_complete,
    "classification": "PASS" if passed else "FAIL",
}
Path(output_path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 0600 "$evidence_root/qualification.json" "$stdout"
/opt/secpal-control/scripts/ci-cloud/rocky-control.py validate-evidence qualification \
  "$evidence_root/qualification.json"
chown secpal-cloud:secpal-cloud "$evidence_root/qualification.json" "$stdout"
chmod 0400 "$evidence_root/qualification.json" "$stdout"
