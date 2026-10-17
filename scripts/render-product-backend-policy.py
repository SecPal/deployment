#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Render #101's host policy without installing or starting anything."""

import argparse
from pathlib import Path

from product_backend_contract import haproxy_backends, host_policy


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--haproxy-uid", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    files = host_policy(args.haproxy_uid)
    files["haproxy-backends.cfg"] = haproxy_backends()
    header = (
        "# SPDX-FileCopyrightText: 2026 SecPal Contributors\n"
        "# SPDX-License" "-Identifier: CC0-1.0\n\n"
    )
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in files.items():
        prefix = header.replace("#", ";") if name.endswith(".cil") else header
        with (args.output / name).open("x", encoding="utf-8") as handle:
            handle.write(prefix + content)


if __name__ == "__main__":
    main()
