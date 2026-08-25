# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

output "exact_image_self_link" {
  value       = var.exact_image_self_link
  description = "Immutable image identity admitted before OpenTofu execution."
}

output "instance_id" {
  value       = google_compute_instance.qualification.instance_id
  description = "Exact retained instance identity."
}

output "instance_name" {
  value       = google_compute_instance.qualification.name
  description = "Exact run-owned instance name."
}

output "zone" {
  value       = google_compute_instance.qualification.zone
  description = "Closed retained instance zone."
}

output "initial_ipv4_address" {
  value       = google_compute_instance.qualification.network_interface[0].access_config[0].nat_ip
  description = "Initial address used only by trusted preparation orchestration."
}

output "machine_type" {
  value       = google_compute_instance.qualification.machine_type
  description = "Effective fixed C4A machine type."
}
