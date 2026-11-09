# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Retained-state recovery only. Resource creation is retired.
terraform {
  required_version = "= 1.12.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.9.0"
    }
  }
}

provider "google" {
  project                         = "secpal-dev"
  region                          = "europe-west3"
  zone                            = "europe-west3-a"
  add_terraform_attribution_label = false
}
