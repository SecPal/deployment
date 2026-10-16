# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Cleanup-only provider configuration for authenticated historical run state.
# No resource or data declarations remain. Retain until outstanding resources
# and recovery responsibilities are independently discharged.
# Any state-driven destroy requires separately scoped operator authorization.

terraform {
  required_version = "= 1.12.5"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "= 2.106.0"
    }
  }
}

provider "digitalocean" {}
