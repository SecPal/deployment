#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Select the first aligned non-overlapping subordinate-ID range."""

from __future__ import annotations

import re
import sys
import grp
import pwd
from pathlib import Path


LINE = re.compile(r"^[^:]{1,64}:([0-9]{1,10}):([0-9]{1,10})$")
WIDTH = 65536


def ranges(path: Path) -> list[range]:
    result: list[range] = []
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed subordinate-ID entry in {path}")
        start, count = map(int, match.groups())
        if count < 1 or start + count > 2**32:
            raise ValueError(f"out-of-range subordinate-ID entry in {path}")
        result.append(range(start, start + count))
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: allocate-rocky-subids.py SUBUID SUBGID", file=sys.stderr)
        return 64
    occupied = ranges(Path(sys.argv[1])) + ranges(Path(sys.argv[2]))
    effective_ids = {entry.pw_uid for entry in pwd.getpwall()}
    effective_ids.update(entry.pw_gid for entry in pwd.getpwall())
    effective_ids.update(entry.gr_gid for entry in grp.getgrall())
    for start in range(1_048_576, 4_294_901_761, WIDTH):
        candidate = range(start, start + WIDTH)
        if (
            all(candidate.stop <= item.start or candidate.start >= item.stop for item in occupied)
            and all(identifier not in candidate for identifier in effective_ids)
        ):
            print(start)
            return 0
    print("no non-overlapping subordinate-ID range remains", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
