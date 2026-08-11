# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

variable "project_id" {
  description = "Dedicated Google Cloud project for non-production conformance fixtures."
  type        = string

  validation {
    condition     = var.project_id == "secpal-dev"
    error_message = "project_id must be the reviewed SecPal conformance project."
  }
}

variable "run_id" {
  description = "GitHub Actions run ID."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]{0,19}$", var.run_id))
    error_message = "run_id must be a positive decimal GitHub Actions run ID."
  }
}

variable "run_attempt" {
  description = "GitHub Actions run attempt."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]{0,2}$", var.run_attempt))
    error_message = "run_attempt must be a positive decimal value no larger than three digits."
  }
}

variable "target_sha" {
  description = "Exact deployment commit under test."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.target_sha))
    error_message = "target_sha must be a lowercase full 40-character Git commit SHA."
  }
}

variable "zone" {
  description = "Closed C4A test zone."
  type        = string

  validation {
    condition     = var.zone == "europe-west3-a"
    error_message = "zone must be europe-west3-a."
  }
}

variable "runner_ipv4" {
  description = "Validated public IPv4 address of the GitHub-hosted runner."
  type        = string

  validation {
    condition     = can(cidrnetmask("${var.runner_ipv4}/32"))
    error_message = "runner_ipv4 must be an IPv4 address."
  }
}

variable "ssh_public_key" {
  description = "Per-run Ed25519 public key; the private key never enters OpenTofu."
  type        = string

  validation {
    condition     = can(regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,2} secpal-ci-${var.run_id}-${var.run_attempt}$", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be the run-bound Ed25519 public key."
  }
}

variable "created_at" {
  description = "Creation time as Unix epoch seconds."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]{9}$", var.created_at))
    error_message = "created_at must be a ten-digit Unix timestamp."
  }
}

variable "expires_at" {
  description = "Expiration time as Unix epoch seconds."
  type        = string

  validation {
    condition = (
      can(regex("^[1-9][0-9]{9}$", var.expires_at)) &&
      can(tonumber(var.created_at)) &&
      can(tonumber(var.expires_at)) &&
      tonumber(var.expires_at) > tonumber(var.created_at) &&
      tonumber(var.expires_at) - tonumber(var.created_at) <= 10800
    )
    error_message = "expires_at must be after creation and no more than three hours later."
  }
}
