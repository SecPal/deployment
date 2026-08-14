# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

output "image_id" {
  description = "Exact provider image self-link resolved from the closed Debian 13 arm64 family."
  value       = data.google_compute_image.debian_13.self_link
}

output "instance_id" {
  description = "Exact provider instance ID for run evidence."
  value       = google_compute_instance.conformance.instance_id
}

output "disk_id" {
  description = "Exact provider boot-disk ID for run evidence."
  value       = google_compute_disk.conformance.disk_id
}

output "zone" {
  description = "Effective Google Compute Engine zone."
  value       = google_compute_instance.conformance.zone
}

output "machine_type" {
  description = "Effective fixed Axion machine type."
  value       = google_compute_instance.conformance.machine_type
}
