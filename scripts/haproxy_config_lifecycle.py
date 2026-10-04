#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Atomic reviewed candidate publication; no active partial-write pathname.

The privileged wrapper owns path/identity admission and serialization. Binary
validation precedes any replacement. HAProxy's master-worker reload retains old
workers on failure; rollback restores accepted disk bytes for the next start.
"""

import os
from pathlib import Path
import stat
import tempfile

from haproxy_base_contract import MAX_CONFIG_BYTES


def sync_directory(directory: Path):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage(directory: Path, data: bytes, prepare):
    descriptor, name = tempfile.mkstemp(prefix='.secpal-candidate-', dir=directory)
    candidate = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(candidate, 0o444)
        prepare(candidate)
        return candidate
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise


def publish(serving: Path, data: bytes, validate, reload, prepare=lambda _: None, recover=lambda: None):
    """Reject invalid bytes before replacement; preserve LKG on reload failure.

    No configurable shell command or runtime API. Callbacks are reviewed code,
    never operator inputs. The installed wrapper holds a root-owned flock across
    this entire operation and requires regular immutable root-owned paths.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CONFIG_BYTES:
        raise ValueError('admit-candidate-size')
    previous = None
    if serving.exists() or serving.is_symlink():
        info = serving.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_CONFIG_BYTES:
            raise ValueError('admit-serving-file')
        previous = serving.read_bytes()
    candidate = stage(serving.parent, data, prepare)
    rollback = None
    try:
        validate(candidate)
        if previous == data:
            return
        if previous is not None:
            rollback = stage(serving.parent, previous, prepare)
        os.replace(candidate, serving)
        sync_directory(serving.parent)
        try:
            reload()
        except BaseException:
            if rollback is not None:
                os.replace(rollback, serving)
            else:
                serving.unlink(missing_ok=True)
            sync_directory(serving.parent)
            recover()
            raise
    finally:
        candidate.unlink(missing_ok=True)
        if rollback is not None:
            rollback.unlink(missing_ok=True)
