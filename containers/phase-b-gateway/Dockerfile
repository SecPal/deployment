# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: CC0-1.0

ARG CADDY_IMAGE=caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d
FROM ${CADDY_IMAGE}

USER root
RUN setcap -r /usr/bin/caddy
USER 10003:10003
