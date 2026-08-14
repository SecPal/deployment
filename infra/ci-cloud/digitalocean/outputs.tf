# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

output "ipv4_address" {
  description = "Public address admitted only through the per-run SSH firewall."
  value       = digitalocean_droplet.conformance.ipv4_address
}

output "image_id" {
  description = "Exact provider image ID resolved from the closed Debian 13 slug."
  value       = data.digitalocean_image.debian_13.id
}

output "droplet_id" {
  description = "Exact provider resource ID for run evidence."
  value       = digitalocean_droplet.conformance.id
}

output "region" {
  description = "Effective DigitalOcean region."
  value       = digitalocean_droplet.conformance.region
}

output "size" {
  description = "Effective DigitalOcean size slug."
  value       = digitalocean_droplet.conformance.size
}
