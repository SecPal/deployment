# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

variable "project_id" {
  type = string
  validation {
    condition     = var.project_id == "secpal-dev"
    error_message = "project_id must be the reviewed SecPal conformance project."
  }
}

variable "bootstrap_service_account" {
  type = string
  validation {
    condition = (
      var.bootstrap_service_account == "secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com"
    )
    error_message = "bootstrap_service_account must be the reviewed role-free identity."
  }
}

variable "trusted_control_sha" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.trusted_control_sha))
    error_message = "trusted_control_sha must be a lowercase full commit SHA."
  }
}

variable "target_sha" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.target_sha))
    error_message = "target_sha must be a lowercase full commit SHA."
  }
}

variable "profile" {
  type = string
  validation {
    condition     = var.profile == "gcp-rocky-10-2-arm64"
    error_message = "profile is outside the closed Rocky allowlist."
  }
}

variable "zone" {
  type = string
  validation {
    condition     = var.zone == "europe-west3-a"
    error_message = "zone must be europe-west3-a."
  }
}

variable "machine_type" {
  type = string
  validation {
    condition     = var.machine_type == "c4a-standard-4"
    error_message = "machine_type must be c4a-standard-4."
  }
}

variable "disk_type" {
  type = string
  validation {
    condition     = var.disk_type == "hyperdisk-balanced"
    error_message = "disk_type must be hyperdisk-balanced."
  }
}

variable "disk_size_gib" {
  type = number
  validation {
    condition     = var.disk_size_gib == 120
    error_message = "disk_size_gib must be exactly 120."
  }
}

variable "exact_image_self_link" {
  type = string
  validation {
    condition = can(regex(
      "^https://www\\.googleapis\\.com/compute/v1/projects/rocky-linux-cloud/global/images/rocky-linux-10-[a-z0-9-]{1,50}$",
      var.exact_image_self_link,
    ))
    error_message = "exact_image_self_link must be one immutable official Rocky ARM64 image."
  }
}

variable "run_id" {
  type = string
  validation {
    condition     = can(regex("^[1-9][0-9]{0,19}$", var.run_id))
    error_message = "run_id must be a positive GitHub Actions run ID."
  }
}

variable "run_attempt" {
  type = string
  validation {
    condition     = can(regex("^[1-9][0-9]{0,2}$", var.run_attempt))
    error_message = "run_attempt must be a bounded positive value."
  }
}

variable "runner_ipv4" {
  type = string
  validation {
    condition     = can(cidrnetmask("${var.runner_ipv4}/32"))
    error_message = "runner_ipv4 must be one IPv4 address."
  }
}

variable "ssh_public_key" {
  type = string
  validation {
    condition = (
      length(trimspace(var.ssh_public_key)) <= 128 &&
      can(regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,2} secpal-rocky-${var.run_id}-${var.run_attempt}$", trimspace(var.ssh_public_key)))
    )
    error_message = "ssh_public_key must be the bounded run-specific Ed25519 public key."
  }
}

variable "created_at" {
  type = string
  validation {
    condition     = can(regex("^[1-9][0-9]{9}$", var.created_at))
    error_message = "created_at must be a ten-digit Unix timestamp."
  }
}

variable "expires_at" {
  type = string
  validation {
    condition = (
      can(regex("^[1-9][0-9]{9}$", var.expires_at)) &&
      tonumber(var.expires_at) > tonumber(var.created_at) &&
      tonumber(var.expires_at) - tonumber(var.created_at) <= 10800
    )
    error_message = "expires_at must bind a positive TTL of no more than three hours."
  }
}
