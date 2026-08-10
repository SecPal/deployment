# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

terraform {
  required_version = "= 1.12.5"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "= 2.99.1"
    }
  }
}

provider "digitalocean" {}
