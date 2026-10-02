# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Shared fixed official GitHub CLI staging used by SecPal image admission."""

import hashlib
import os
from pathlib import Path
import tarfile

EXPECTED_GH_VERSION = '2.97.0'
CLOUD_GH_RELEASES = {
    "x86_64": (
        "amd64",
        "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112",
    ),
    "aarch64": (
        "arm64",
        "73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5",
    ),
}


def stage_gh_cli(fixture_root: Path, release: tuple[str, str], command, environment: dict) -> str:
    release_arch, expected_sha256 = release
    if release_arch not in ('amd64', 'arm64'):
        raise ValueError('cloud GitHub CLI architecture is unsupported')
    archive_name = f"gh_{EXPECTED_GH_VERSION}_linux_{release_arch}.tar.gz"
    archive = fixture_root / archive_name
    executable = fixture_root / "tools" / "gh"
    executable.parent.mkdir(mode=0o700)
    command(
        [
            "curl",
            "--disable",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--max-time",
            "180",
            "--max-filesize",
            "67108864",
            "--output",
            os.fspath(archive),
            (
                "https://github.com/cli/cli/releases/download/"
                f"v{EXPECTED_GH_VERSION}/{archive_name}"
            ),
        ],
        environment=environment,
    )
    try:
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError("cloud GitHub CLI archive digest differs")
        member_name = (
            f"gh_{EXPECTED_GH_VERSION}_linux_{release_arch}/bin/gh"
        )
        with tarfile.open(archive, mode="r:gz") as bundle:
            member = bundle.getmember(member_name)
            if not member.isfile() or not 0 < member.size <= 64 * 1024 * 1024:
                raise ValueError("cloud GitHub CLI archive member is invalid")
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("cloud GitHub CLI archive member is missing")
            content = source.read(64 * 1024 * 1024 + 1)
            if len(content) != member.size:
                raise ValueError("cloud GitHub CLI archive member is truncated")
        executable.write_bytes(content)
        executable.chmod(0o700)
    except (KeyError, OSError, tarfile.TarError) as error:
        raise ValueError("cloud GitHub CLI staging failed") from error
    finally:
        archive.unlink(missing_ok=True)
    return os.fspath(executable)
